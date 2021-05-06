# Copyright (c) 2020 iXsystems, Inc.
# All rights reserved.
# This file is a part of TrueNAS
# and may not be copied and/or distributed
# without the express permission of iXsystems.

import asyncio
import base64
import errno
from lockfile import LockFile
import logging
try:
    import netif
except ImportError:
    netif = None
import os
import pickle
import queue
import re
import shutil
import socket
import subprocess
try:
    import sysctl
except ImportError:
    sysctl = None
import tempfile
import textwrap
import time
import enum

from functools import partial

from middlewared.schema import accepts, Bool, Dict, Int, List, NOT_PROVIDED, Str
from middlewared.service import (
    job, no_auth_required, pass_app, private, throttle, CallError, ConfigService, ValidationErrors,
)
import middlewared.sqlalchemy as sa
from middlewared.plugins.auth import AuthService, SessionManagerCredentials
from middlewared.plugins.config import FREENAS_DATABASE
from middlewared.plugins.datastore.connection import DatastoreService
from middlewared.utils.contextlib import asyncnullcontext

BUFSIZE = 256
ENCRYPTION_CACHE_LOCK = asyncio.Lock()
FAILOVER_NEEDOP = '/tmp/.failover_needop'
TRUENAS_VERS = re.compile(r'\d*\.?\d+')

logger = logging.getLogger('failover')


class HA_HARDWARE(enum.Enum):

    """
    The echostream E16 JBOD and the echostream Z-series chassis
    are the same piece of hardware. One of the only ways to differentiate
    them is to look at the enclosure elements in detail. The Z-series
    chassis identifies element 0x26 as `ZSERIES_ENCLOSURE` listed below.
    The E16 JBOD does not. The E16 identifies element 0x25 as NM_3115RL4WB66_8R5K5.

    We use this fact to ensure we are looking at the internal enclosure, and
    not a shelf. If we used a shelf to determine which node was A or B, you could
    cause the nodes to switch identities by switching the cables for the shelf.
    """

    ZSERIES_ENCLOSURE = re.compile(r'SD_9GV12P1J_12R6K4', re.M)
    ZSERIES_NODE = re.compile(r'3U20D-Encl-([AB])', re.M)
    XSERIES_ENCLOSURE = re.compile(r'Enclosure Name: CELESTIC (P3215-O|P3217-B)', re.M)
    XSERIES_NODEA = re.compile(r'ESCE A_(5[0-9A-F]{15})', re.M)
    XSERIES_NODEB = re.compile(r'ESCE B_(5[0-9A-F]{15})', re.M)
    MSERIES_ENCLOSURE = re.compile(r'Enclosure Name: (ECStream|iX) 4024S([ps])', re.M)


class TruenasNodeSessionManagerCredentials(SessionManagerCredentials):
    pass


class UnableToDetermineOSVersion(Exception):

    """
    Raised in JournalSync thread when we're unable
    to detect the remote node's OS version.
    (i.e. if remote node goes down (upgrade/reboot, etc)
    """
    pass



class OSVersionMismatch(Exception):

    """
    Raised in JournalSync thread when the remote nodes OS version
    does not match the local nodes OS version.
    """
    pass


def throttle_condition(middleware, app, *args, **kwargs):
    # app is None means internal middleware call
    if app is None or (app and app.authenticated):
        return True, 'AUTHENTICATED'
    return False, None


class FailoverModel(sa.Model):
    __tablename__ = 'system_failover'

    id = sa.Column(sa.Integer(), primary_key=True)
    disabled = sa.Column(sa.Boolean(), default=False)
    master_node = sa.Column(sa.String(1))
    timeout = sa.Column(sa.Integer(), default=0)


class FailoverService(ConfigService):

    HA_MODE = None
    LAST_STATUS = None
    LAST_DISABLEDREASONS = None

    class Config:
        datastore = 'system.failover'
        datastore_extend = 'failover.failover_extend'

    @private
    async def failover_extend(self, data):
        data['master'] = await self.middleware.call('failover.node') == data.pop('master_node')
        return data

    @accepts(Dict(
        'failover_update',
        Bool('disabled'),
        Int('timeout'),
        Bool('master', null=True),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update failover state.

        `disabled` When true indicates that HA will be disabled.
        `master`  Marks the particular node in the chassis as the master node.
                    The standby node will have the opposite value.

        `timeout` is the time to WAIT until a failover occurs when a network
            event occurs on an interface that is marked critical for failover AND
            HA is enabled and working appropriately.

            The default time to wait is 2 seconds.
            **NOTE**
                This setting does NOT effect the `disabled` or `master` parameters.
        """
        master = data.pop('master', NOT_PROVIDED)

        old = await self.middleware.call('datastore.config', 'system.failover')

        new = old.copy()
        new.update(data)

        if master is not NOT_PROVIDED:
            # The node making the call is the one we want to make MASTER by default
            new['master_node'] = await self.middleware.call('failover.node')
        else:
            new['master_node'] = await self._master_node(master)

        verrors = ValidationErrors()
        if new['disabled'] is False:
            if not await self.middleware.call('interface.query', [('failover_critical', '=', True)]):
                verrors.add(
                    'failover_update.disabled',
                    'You need at least one critical interface to enable failover.',
                )
        verrors.check()

        await self.middleware.call('datastore.update', 'system.failover', new['id'], new)

        await self.middleware.call('service.restart', 'failover')

        if new['disabled']:
            if new['master_node'] == await self.middleware.call('failover.node'):
                await self.middleware.call('failover.force_master')
            else:
                await self.middleware.call('failover.call_remote', 'failover.force_master')

        return await self.config()

    async def _master_node(self, master):
        node = await self.middleware.call('failover.node')
        if node == 'A':
            if master:
                return 'A'
            else:
                return 'B'
        elif node == 'B':
            if master:
                return 'B'
            else:
                return 'A'
        else:
            raise CallError('Unable to change node state in MANUAL mode')

    @accepts()
    def licensed(self):
        """
        Checks whether this instance is licensed as a HA unit.
        """
        info = self.middleware.call_sync('system.info')
        if not info['license'] or not info['license']['system_serial_ha']:
            return False
        return True

    @private
    async def ha_mode(self):

        # update the class attribute so that all instances
        # of this class see the correct value
        if FailoverService.HA_MODE is None:
            FailoverService.HA_MODE = await self.middleware.call(
                'failover.enclosure.detect'
            )

        return FailoverService.HA_MODE

    @accepts()
    async def hardware(self):
        """
        Returns the hardware type for an HA system.
          ECHOSTREAM
          ECHOWARP
          PUMA
          SBB
          ULTIMATE
          BHYVE
          MANUAL
        """

        hardware = await self.middleware.call('failover.ha_mode')

        return hardware[0]

    @accepts()
    async def node(self):
        """
        Returns the slot position in the chassis that
        the controller is located.
          A - First node
          B - Seconde Node
          MANUAL - slot position in chassis could not be determined
        """

        node = await self.middleware.call('failover.ha_mode')

        return node[1]

    @private
    @accepts()
    async def internal_interfaces(self):
        """
        This is a p2p ethernet connection on HA systems.
        """

        return await self.middleware.call(
            'failover.internal_interface.detect'
        )

    @private
    async def get_carp_states(self, interfaces=None):
        """
        This method has to be left in for backwards compatibility
        when upgrading from 11.3 to 12+
        """
        return await self.middleware.call(
            'failover.vip.get_states', interfaces
        )

    @private
    async def check_carp_states(self, local, remote):
        """
        This method has to be left in for backwards compatibility
        when upgrading from 11.3 to 12+
        """
        return await self.middleware.call(
            'failover.vip.check_states', local, remote
        )

    @no_auth_required
    @throttle(seconds=2, condition=throttle_condition)
    @accepts()
    @pass_app(rest=True)
    async def status(self, app):
        """
        Get the current HA status.

        Returns:
            MASTER
            BACKUP
            ELECTING
            IMPORTING
            ERROR
            SINGLE
        """

        status = await self._status(app)
        if status != self.LAST_STATUS:
            self.LAST_STATUS = status
            self.middleware.send_event('failover.status', 'CHANGED', fields={'status': status})

        return status

    async def _status(self, app):

        try:
            status = await self.middleware.call('cache.get', 'failover_status')
        except KeyError:
            status = await self.middleware.call('failover.status.get_local', app)
            if status:
                await self.middleware.call('cache.put', 'failover_status', status, 300)

        if status:
            return status

        try:
            remote_imported = await self.middleware.call(
                'failover.call_remote', 'pool.query',
                [[['status', '!=', 'OFFLINE']]]
            )

            # Other node has the pool
            if remote_imported:
                return 'BACKUP'
            # Other node has no pool
            else:
                return 'ERROR'
        except Exception as e:
            # Anything other than ClientException is unexpected and should be logged
            if not isinstance(e, CallError):
                self.logger.warning('Failed checking failover status', exc_info=True)
            return 'UNKNOWN'

    @private
    async def status_refresh(self):
        await self.middleware.call('cache.pop', 'failover_status')
        # Kick a new status so it may be ready on next user call
        await self.middleware.call('failover.status')
        await self.middleware.call('failover.disabled_reasons')

    @accepts()
    def in_progress(self):
        """
        Returns True if there is an ongoing failover event.
        """

        return LockFile('/tmp/.failover_event').is_locked()

    @no_auth_required
    @throttle(seconds=2, condition=throttle_condition)
    @accepts()
    @pass_app()
    async def get_ips(self, app):
        """
        Get a list of IPs which can be accessed for management via UI.
        """
        addresses = (await self.middleware.call('system.general.config'))['ui_address']
        if '0.0.0.0' in addresses:
            ips = []
            for interface in await self.middleware.call('interface.query', [
                ('failover_vhid', '!=', None)
            ]):
                ips += [i['address'] for i in interface.get('failover_virtual_aliases', [])]
            return ips
        return addresses

    @accepts()
    async def force_master(self):
        """
        Force this controller to become MASTER.
        """

        # Skip if we are already MASTER
        if await self.middleware.call('failover.status') == 'MASTER':
            return False

        if not await self.middleware.call('failover.fenced.start', {'force': True}):
            return False

        for i in await self.middleware.call('interface.query', [('failover_critical', '!=', None)]):
            if i['failover_vhid']:
                await self.middleware.call('failover.event', i['name'], i['failover_vhid'], 'forcetakeover')
                break

        return False

    @accepts(Dict(
        'options',
        Bool('reboot', default=False),
    ))
    def sync_to_peer(self, options):
        """
        Sync database and files to the other controller.

        `reboot` as true will reboot the other controller after syncing.
        """
        self.logger.debug('Sending database to standby controller')
        self.middleware.call_sync('failover.send_database')
        self.logger.debug('Syncing cached keys')
        self.middleware.call_sync('failover.sync_keys_to_remote_node')
        self.logger.debug('Sending license and pwenc files')
        self.send_small_file('/data/license')
        self.send_small_file('/data/pwenc_secret')
        self.send_small_file('/root/.ssh/authorized_keys')

        for path in ('/data/geli',):
            if not os.path.exists(path) or not os.path.isdir(path):
                continue
            for f in os.listdir(path):
                fullpath = os.path.join(path, f)
                if not os.path.isfile(fullpath):
                    continue
                self.send_small_file(fullpath)

        self.middleware.call_sync('failover.call_remote', 'service.restart', ['failover'])

        if options['reboot']:
            self.middleware.call_sync('failover.call_remote', 'system.reboot', [{'delay': 2}])

    @accepts()
    def sync_from_peer(self):
        """
        Sync database and files from the other controller.
        """
        self.middleware.call_sync('failover.call_remote', 'failover.sync_to_peer')

    @private
    async def send_database(self):
        await self.middleware.run_in_executor(DatastoreService.thread_pool, self._send_database)

    def _send_database(self):
        # We are in the `DatastoreService` thread so until the end of this method an item that we put into `sql_queue`
        # will be the last one and no one else is able to write neither to the database nor to the journal.

        # Journal thread will see that this is special value and will clear journal.
        sql_queue.put(None)

        self.send_small_file(FREENAS_DATABASE, FREENAS_DATABASE + '.sync')
        self.middleware.call_sync('failover.call_remote', 'failover.receive_database')

    @private
    def receive_database(self):
        os.rename(FREENAS_DATABASE + '.sync', FREENAS_DATABASE)
        self.middleware.call_sync('datastore.setup')

    @private
    def send_small_file(self, path, dest=None):
        if dest is None:
            dest = path
        if not os.path.exists(path):
            return
        mode = os.stat(path).st_mode
        with open(path, 'rb') as f:
            first = True
            while True:
                read = f.read(1024 * 1024 * 10)
                if not read:
                    break
                self.middleware.call_sync('failover.call_remote', 'filesystem.file_receive', [
                    dest, base64.b64encode(read).decode(), {'mode': mode, 'append': not first}
                ])
                first = False

    @no_auth_required
    @throttle(seconds=2, condition=throttle_condition)
    @accepts()
    @pass_app()
    def disabled_reasons(self, app):
        """
        Returns a list of reasons why failover is not enabled/functional.

        NO_VOLUME - There are no pools configured.
        NO_VIP - There are no interfaces configured with Virtual IP.
        NO_SYSTEM_READY - Other storage controller has not finished booting.
        NO_PONG - Other storage controller is not communicable.
        NO_FAILOVER - Failover is administratively disabled.
        NO_LICENSE - Other storage controller has no license.
        DISAGREE_CARP - Nodes CARP states do not agree.
        MISMATCH_DISKS - The storage controllers do not have the same quantity of disks.
        NO_CRITICAL_INTERFACES - No network interfaces are marked critical for failover.
        """
        reasons = set(self._disabled_reasons(app))
        if reasons != self.LAST_DISABLEDREASONS:
            self.LAST_DISABLEDREASONS = reasons
            self.middleware.send_event('failover.disabled_reasons', 'CHANGED', fields={'disabled_reasons': list(reasons)})
        return list(reasons)

    def _disabled_reasons(self, app):
        reasons = []
        if not self.middleware.call_sync('pool.query'):
            reasons.append('NO_VOLUME')
        if not any(filter(
            lambda x: x.get('failover_virtual_aliases'), self.middleware.call_sync('interface.query'))
        ):
            reasons.append('NO_VIP')
        try:
            assert self.middleware.call_sync('failover.remote_connected') is True

            # if the remote node panic's (this happens on failover event if we cant export the
            # zpool in 4 seconds on freeBSD systems (linux reboots silently by design)
            # then the p2p interface stays "UP" and the websocket remains open.
            # At this point, we have to wait for the TCP timeout (60 seconds default).
            # This means the assert line up above will return `True`.
            # However, any `call_remote` method will hang because the websocket is still
            # open but hasn't closed due to the default TCP timeout window. This can be painful
            # on failover events because it delays the process of restarting services in a timely
            # manner. To work around this, we place a `timeout` of 5 seconds on the system.ready
            # call. This essentially bypasses the TCP timeout window.
            if not self.middleware.call_sync('failover.call_remote', 'system.ready', [], {'timeout': 5}):
                reasons.append('NO_SYSTEM_READY')

            if not self.middleware.call_sync('failover.call_remote', 'failover.licensed'):
                reasons.append('NO_LICENSE')

            local = self.middleware.call_sync('failover.vip.get_states')
            try:
                remote = self.middleware.call_sync('failover.call_remote', 'failover.vip.get_states')
            except Exception as e:
                if e.errno == CallError.ENOMETHOD:
                    # We're talking to an 11.3 system, so use the old API
                    remote = self.middleware.call_sync('failover.call_remote', 'failover.get_carp_states')
                else:
                    raise

            if self.middleware.call_sync('failover.vip.check_states', local, remote):
                reasons.append('DISAGREE_CARP')

            mismatch_disks = self.middleware.call_sync('failover.mismatch_disks')
            if mismatch_disks['missing_local'] or mismatch_disks['missing_remote']:
                reasons.append('MISMATCH_DISKS')

            if not self.middleware.call_sync('datastore.query', 'network.interfaces', [['int_critical', '=', True]]):
                reasons.append('NO_CRITICAL_INTERFACES')
        except Exception:
            reasons.append('NO_PONG')
        if self.middleware.call_sync('failover.config')['disabled']:
            reasons.append('NO_FAILOVER')
        return reasons

    @private
    async def mismatch_disks(self):
        """
        On HA systems, da#'s can be different
        between controllers. This isn't common
        but does occurr. An example being when
        a customer powers off passive storage controller
        for maintenance and also powers off an expansion shelf.
        The active controller will reassign da#'s appropriately
        depending on which shelf was powered off. When passive
        storage controller comes back online, the da#'s will be
        different than what's on the active controller because the
        kernel reassigned those da#'s. This function now grabs
        the serial numbers of each disk and calculates the difference
        between the controllers. Instead of returning da#'s to alerts,
        this returns serial numbers.
        This accounts for 2 scenarios:
         1. the quantity of disks are different between
            controllers
         2. the quantity of disks are the same between
            controllers but serials do not match
        """
        local_boot_disks = await self.middleware.call('boot.get_disks')
        remote_boot_disks = await self.middleware.call('failover.call_remote', 'boot.get_disks')
        local_disks = set(
            v['ident']
            for k, v in (await self.middleware.call('device.get_info', 'DISK')).items()
            if k not in local_boot_disks
        )
        remote_disks = set(
            v['ident']
            for k, v in (await self.middleware.call('failover.call_remote', 'device.get_info', ['DISK'])).items()
            if k not in remote_boot_disks
        )
        return {
            'missing_local': sorted(remote_disks - local_disks),
            'missing_remote': sorted(local_disks - remote_disks),
        }

    @accepts(Dict(
        'options',
        List(
            'pools', items=[
                Dict(
                    'pool_keys',
                    Str('name', required=True),
                    Str('passphrase', required=True)
                )
            ], default=[]
        ),
        List(
            'datasets', items=[
                Dict(
                    'dataset_keys',
                    Str('name', required=True),
                    Str('passphrase', required=True),
                )
            ], default=[]
        ),
    ))
    async def unlock(self, options):
        """
        Unlock pools in HA, syncing passphrase between controllers and forcing this controller
        to be MASTER importing the pools.
        """
        if options['pools'] or options['datasets']:
            await self.middleware.call(
                'failover.update_encryption_keys', {
                    'pools': options['pools'],
                    'datasets': options['datasets'],
                },
            )

        return await self.middleware.call('failover.force_master')

    @private
    @job(lock=lambda args: f'failover_dataset_unlock_{args[0]}')
    async def unlock_zfs_datasets(self, job, pool_name):
        # We are going to unlock all zfs datasets we have keys in cache/database for the pool in question
        zfs_keys = (await self.encryption_keys())['zfs']
        unlock_job = await self.middleware.call(
            'pool.dataset.unlock', pool_name, {
                'recursive': True,
                'datasets': [{'name': name, 'passphrase': passphrase} for name, passphrase in zfs_keys.items()]
            }
        )
        return await job.wrap(unlock_job)

    @private
    @accepts()
    async def encryption_keys(self):
        return await self.middleware.call(
            'cache.get_or_put', 'failover_encryption_keys', 0, lambda: {'geli': {}, 'zfs': {}}
        )

    @private
    @accepts(
        Dict(
            'update_encryption_keys',
            Bool('sync_keys', default=True),
            List(
                'pools', items=[
                    Dict(
                        'pool_geli_keys',
                        Str('name', required=True),
                        Str('passphrase', required=True),
                    )
                ], default=[]
            ),
            List(
                'datasets', items=[
                    Dict(
                        'dataset_keys',
                        Str('name', required=True),
                        Str('passphrase', required=True),
                    )
                ], default=[]
            ),
        )
    )
    async def update_encryption_keys(self, options):
        if not options['pools'] and not options['datasets']:
            raise CallError('Please specify pools/datasets to update')

        async with ENCRYPTION_CACHE_LOCK:
            keys = await self.encryption_keys()
            for pool in options['pools']:
                keys['geli'][pool['name']] = pool['passphrase']
            for dataset in options['datasets']:
                keys['zfs'][dataset['name']] = dataset['passphrase']
            await self.middleware.call('cache.put', 'failover_encryption_keys', keys)
            if options['sync_keys']:
                await self.sync_keys_to_remote_node(lock=False)

    @private
    @accepts(
        Dict(
            'remove_encryption_keys',
            Bool('sync_keys', default=True),
            List('pools', items=[Str('pool')], default=[]),
            List('datasets', items=[Str('dataset')], default=[]),
        )
    )
    async def remove_encryption_keys(self, options):
        if not options['pools'] and not options['datasets']:
            raise CallError('Please specify pools/datasets to remove')

        async with ENCRYPTION_CACHE_LOCK:
            keys = await self.encryption_keys()
            for pool in options['pools']:
                keys['geli'].pop(pool, None)
            for dataset in options['datasets']:
                keys['zfs'] = {
                    k: v for k, v in keys['zfs'].items() if k != dataset and not k.startswith(f'{dataset}/')
                }
            await self.middleware.call('cache.put', 'failover_encryption_keys', keys)
            if options['sync_keys']:
                await self.sync_keys_to_remote_node(lock=False)

    @private
    @job()
    def attach_all_geli_providers(self, job):
        pools = self.middleware.call_sync('pool.query', [('encrypt', '>', 0)])
        if not pools:
            return

        failed_drive = 0
        failed_volumes = []
        geli_keys = self.middleware.call_sync('failover.encryption_keys')['geli']
        for pool in pools:
            with tempfile.NamedTemporaryFile(mode='w+') as tmp:
                tmp.file.write(geli_keys.get(pool['name'], ''))
                tmp.file.flush()
                keyfile = pool['encryptkey_path']
                procs = []
                for encrypted_disk in self.middleware.call_sync(
                    'datastore.query',
                    'storage.encrypteddisk',
                    [('encrypted_volume', '=', pool['id'])]
                ):
                    if encrypted_disk['encrypted_disk']:
                        # gptid might change on the active head, so we need to rescan
                        # See #16070
                        try:
                            open(
                                f'/dev/{encrypted_disk["encrypted_disk"]["disk_name"]}', 'w'
                            ).close()
                        except Exception:
                            self.logger.warning(
                                'Failed to open dev %s to rescan.',
                                encrypted_disk['encrypted_disk']['disk_name'],
                            )
                    provider = encrypted_disk['encrypted_provider']
                    if not os.path.exists(f'/dev/{provider}.eli'):
                        proc = subprocess.Popen(
                            'geli attach {} -k {} {}'.format(
                                f'-j {tmp.name}' if pool['encrypt'] == 2 else '-p',
                                keyfile,
                                provider,
                            ),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            shell=True,
                        )
                        procs.append(proc)
                for proc in procs:
                    msg = proc.communicate()[1]
                    if proc.returncode != 0:
                        job.set_progress(None, f'Unable to attach GELI provider: {msg}')
                        self.logger.warn('Unable to attach GELI provider: %s', msg)
                        failed_drive += 1

                try:
                    self.middleware.call_sync('zfs.pool.import_pool', pool['guid'], {
                        'altroot': '/mnt',
                    })
                except Exception as e:
                    failed_volumes.append(pool['name'])
                    self.logger.error('Failed to import %s pool: %s', pool['name'], str(e))

        if failed_drive > 0:
            job.set_progress(None, f'{failed_drive} drive(s) can not be attached.')
            self.logger.error('%d drive(s) can not be attached.', failed_drive)

        try:
            if not failed_volumes:
                try:
                    os.unlink(FAILOVER_NEEDOP)
                except FileNotFoundError:
                    pass
                self.middleware.call_sync('failover.sync_keys_to_remote_node')
            else:
                with open(FAILOVER_NEEDOP, 'w') as f:
                    f.write('\n'.join(failed_volumes))
        except Exception:
            pass

    @private
    @job()
    def encryption_detachall(self, job):
        # Let us be very careful before we rip down the GELI providers
        for pool in self.middleware.call_sync('pool.query', [('encrypt', '>', 0)]):
            if pool['status'] == 'OFFLINE':
                for encrypted_disk in self.middleware.call_sync(
                    'datastore.query',
                    'storage.encrypteddisk',
                    [('encrypted_volume', '=', pool['id'])]
                ):
                    provider = encrypted_disk['encrypted_provider']
                    cp = subprocess.run(
                        ['geli', 'detach', provider],
                        capture_output=True, text=True, check=False,
                    )
                    if cp.returncode != 0:
                        job.set_progress(
                            None,
                            f'Unable to detach GELI provider {provider}: {cp.stderr}',
                        )
                return True
            else:
                job.set_progress(
                    None,
                    'Not detaching GELI providers because an encrypted zpool with name '
                    f'{pool["name"]!r} is still mounted!',
                )
                return False

    @private
    async def is_single_master_node(self):
        return await self.middleware.call('failover.status') in ('MASTER', 'SINGLE')

    @accepts(
        Str('action', enum=['ENABLE', 'DISABLE']),
        Dict(
            'options',
            Bool('active'),
        ),
    )
    async def control(self, action, options=None):
        if not options:
            # The node making the call is the one we want to make MASTER by default
            node = await self._master_node((await self.middleware.call('failover.node')))
        else:
            node = await self._master_node(options.get('active'))

        failover = await self.middleware.call('datastore.config', 'system.failover')
        if action == 'ENABLE':
            if failover['disabled'] is False:
                # Already enabled
                return False
            update = {
                'disabled': False,
                'master_node': node,
            }
        elif action == 'DISABLE':
            if failover['disabled'] is True:
                # Already disabled
                return False
            update = {
                'disabled': True,
                'master_node': node,
            }

        await self.middleware.call('datastore.update', 'system.failover', failover['id'], update)
        await self.middleware.call('service.restart', 'failover')

    @private
    def upgrade_version(self):
        return 1

    @accepts(Dict(
        'failover_upgrade',
        Str('train', empty=False),
    ))
    @job(lock='failover_upgrade', pipes=['input'], check_pipes=False)
    def upgrade(self, job, options):
        """
        Upgrades both controllers.

        Files will be downloaded to the Active Controller and then transferred to the Standby
        Controller.

        Upgrade process will start concurrently on both nodes.

        Once both upgrades are applied, the Standby Controller will reboot. This job will wait for
        that job to complete before finalizing.
        """

        if self.middleware.call_sync('failover.status') != 'MASTER':
            raise CallError('Upgrade can only run on Active Controller.')

        try:
            job.check_pipe('input')
        except ValueError:
            updatefile = False
        else:
            updatefile = True

        train = options.get('train')
        if train:
            self.middleware.call_sync('update.set_train', train)

        local_path = self.middleware.call_sync('update.get_update_location')

        if updatefile:
            updatefile_name = 'updatefile.tar'
            job.set_progress(None, 'Uploading update file')
            updatefile_localpath = os.path.join(local_path, updatefile_name)
            os.makedirs(local_path, exist_ok=True)
            with open(updatefile_localpath, 'wb') as f:
                shutil.copyfileobj(job.pipes.input.r, f, 1048576)

        try:
            if not self.middleware.call_sync('failover.call_remote', 'system.ready'):
                raise CallError('Standby Controller is not ready.')

            legacy_upgrade = False
            try:
                self.middleware.call_sync('failover.call_remote', 'failover.upgrade_version')
            except CallError as e:
                if e.errno == CallError.ENOMETHOD:
                    legacy_upgrade = True
                else:
                    raise

            if not updatefile and not legacy_upgrade:
                def download_callback(j):
                    job.set_progress(
                        None, j['progress']['description'] or 'Downloading upgrade files'
                    )

                djob = self.middleware.call_sync('update.download', job_on_progress_cb=download_callback)
                djob.wait_sync()
                if djob.error:
                    raise CallError(f'Error downloading update: {djob.error}')
                if not djob.result:
                    raise CallError('No updates available.')

            self.middleware.call_sync('keyvalue.set', 'HA_UPGRADE', True)

            if legacy_upgrade:
                namespace = 'notifier'
            else:
                namespace = 'update'
            self.middleware.call_sync('failover.call_remote', f'{namespace}.destroy_upload_location')
            remote_path = self.middleware.call_sync(
                'failover.call_remote', f'{namespace}.create_upload_location'
            ) or '/var/tmp/firmware'

            # Only send files to standby:
            # 1. Its a manual upgrade which means it needs to go through master first
            # 2. Its not a legacy upgrade, which means files are downloaded on master first
            #
            # For legacy upgrade it will be downloaded directly from standby.
            if updatefile or not legacy_upgrade:
                job.set_progress(None, 'Sending files to Standby Controller')
                token = self.middleware.call_sync('failover.call_remote', 'auth.generate_token')

                for f in os.listdir(local_path):
                    self.middleware.call_sync('failover.sendfile', token, os.path.join(local_path, f), os.path.join(remote_path, f))

            local_version = self.middleware.call_sync('system.version')
            remote_version = self.middleware.call_sync('failover.call_remote', 'system.version')

            update_remote_descr = update_local_descr = 'Starting upgrade'

            def callback(j, controller):
                nonlocal update_local_descr, update_remote_descr
                if j['state'] != 'RUNNING':
                    return
                if controller == 'LOCAL':
                    update_local_descr = f'{int(j["progress"]["percent"])}%: {j["progress"]["description"]}'
                else:
                    update_remote_descr = f'{int(j["progress"]["percent"])}%: {j["progress"]["description"]}'
                job.set_progress(
                    None, (
                        f'Active Controller: {update_local_descr}\n' if not legacy_upgrade else ''
                    ) + f'Standby Controller: {update_remote_descr}'
                )

            if updatefile:
                update_method = 'update.manual'
                update_remote_args = [os.path.join(remote_path, updatefile_name)]
                update_local_args = [updatefile_localpath]
            else:
                update_method = 'update.update'
                update_remote_args = []
                update_local_args = []

            # If they are the same we assume this is a clean upgrade so we start by
            # upgrading the standby controller.
            if legacy_upgrade or local_version == remote_version:
                rjob = self.middleware.call_sync(
                    'failover.call_remote', update_method, update_remote_args, {
                        'job_return': True,
                        'callback': partial(callback, controller='REMOTE')
                    }
                )
            else:
                rjob = None

            if not legacy_upgrade:
                ljob = self.middleware.call_sync(
                    update_method, *update_local_args,
                    job_on_progress_cb=partial(callback, controller='LOCAL')
                )
                ljob.wait_sync()
                if ljob.error:
                    raise CallError(ljob.error)

                remote_boot_id = self.middleware.call_sync(
                    'failover.call_remote', 'system.boot_id'
                )

            if rjob:
                rjob.result()

            self.middleware.call_sync('failover.call_remote', 'system.reboot', [
                {'delay': 5}
            ], {'job': True})

        except Exception:
            raise

        if not legacy_upgrade:
            # Update will activate the new boot environment.
            # We want to reactivate the current boot environment so on reboot for failover
            # the user has a chance to verify the new version is working as expected before
            # move on and have both controllers on new version.
            local_bootenv = self.middleware.call_sync('bootenv.query', [('active', 'rin', 'N')])
            if not local_bootenv:
                raise CallError('Could not find current boot environment.')
            self.middleware.call_sync('bootenv.activate', local_bootenv[0]['id'])

        job.set_progress(None, 'Waiting on the Standby Controller to reboot.')

        # Wait enough that standby controller has stopped receiving new connections and is
        # rebooting.
        try:
            retry_time = time.monotonic()
            shutdown_timeout = sysctl.filter('kern.init_shutdown_timeout')[0].value
            while time.monotonic() - retry_time < shutdown_timeout:
                self.middleware.call_sync('failover.call_remote', 'core.ping', [], {'timeout': 5})
                time.sleep(5)
        except CallError:
            pass
        else:
            raise CallError('Standby Controller failed to reboot.', errno.ETIMEDOUT)

        if not self.upgrade_waitstandby():
            raise CallError('Timed out waiting Standby Controller after upgrade.')

        if not legacy_upgrade and remote_boot_id == self.middleware.call_sync(
            'failover.call_remote', 'system.boot_id'
        ):
            raise CallError('Standby Controller failed to reboot.')

        return True

    @private
    def upgrade_waitstandby(self, seconds=900):
        """
        We will wait up to 15 minutes by default for the Standby Controller to reboot.
        This values come from observation from support of how long a M-series can take.
        """
        retry_time = time.monotonic()
        while time.monotonic() - retry_time < seconds:
            try:
                if not self.middleware.call_sync('failover.call_remote', 'system.ready'):
                    time.sleep(5)
                    continue
                return True
            except CallError as e:
                if e.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                    time.sleep(5)
                    continue
                raise
        return False

    @accepts()
    def upgrade_pending(self):
        """
        Verify if HA upgrade is pending.

        `upgrade_finish` needs to be called to finish
        the HA upgrade process if this method returns true.
        """

        if self.middleware.call_sync('failover.status') != 'MASTER':
            raise CallError('Upgrade can only be run from the Active Controller.')

        if self.middleware.call_sync('keyvalue.get', 'HA_UPGRADE', False) is not True:
            return False

        try:
            assert self.middleware.call_sync('failover.call_remote', 'core.ping') == 'pong'
        except Exception:
            return False

        local_version = self.middleware.call_sync('system.version')
        remote_version = self.middleware.call_sync('failover.call_remote', 'system.version')

        if local_version == remote_version:
            self.middleware.call_sync('keyvalue.set', 'HA_UPGRADE', False)
            return False

        local_bootenv = self.middleware.call_sync(
            'bootenv.query', [('active', 'rin', 'N')])

        remote_bootenv = self.middleware.call_sync(
            'failover.call_remote', 'bootenv.query', [[('active', '=', 'NR')]])

        if not local_bootenv or not remote_bootenv:
            raise CallError('Unable to determine installed version of software')

        loc_findall = TRUENAS_VERS.findall(local_bootenv[0]['id'])
        rem_findall = TRUENAS_VERS.findall(remote_bootenv[0]['id'])

        loc_vers = tuple(float(i) for i in loc_findall)
        rem_vers = tuple(float(i) for i in rem_findall)

        if loc_vers > rem_vers:
            return True

        return False

    @accepts()
    @job(lock='failover_upgrade_finish')
    def upgrade_finish(self, job):
        """
        Perform the last stage of an HA upgrade.

        This will activate the new boot environment on the
        Standby Controller and reboot it.
        """

        if self.middleware.call_sync('failover.status') != 'MASTER':
            raise CallError('Upgrade can only run on Active Controller.')

        job.set_progress(None, 'Ensuring the Standby Controller is booted')
        if not self.upgrade_waitstandby():
            raise CallError('Timed out waiting for the Standby Controller to boot.')

        job.set_progress(None, 'Activating new boot environment')
        local_bootenv = self.middleware.call_sync('bootenv.query', [('active', 'rin', 'N')])
        if not local_bootenv:
            raise CallError('Could not find current boot environment.')
        self.middleware.call_sync('failover.call_remote', 'bootenv.activate', [local_bootenv[0]['id']])

        job.set_progress(None, 'Rebooting Standby Controller')
        self.middleware.call_sync('failover.call_remote', 'system.reboot', [{'delay': 10}])
        self.middleware.call_sync('keyvalue.set', 'HA_UPGRADE', False)
        return True

    @private
    async def sync_keys_from_remote_node(self):
        """
        Sync GELI and/or ZFS encryption keys from the active node.

        TODO:
            Once TruenAS >= 11.3 < 12 has been EOL'd, we should remove this method
            (should call `failover.call_remote` `failover.sync_keys_to_remote_node`)
        """

        if not await self.middleware.call('failover.licensed'):
            return

        # only sync keys if we're the BACKUP node
        if (await self.middleware.call('failover.status')) != 'BACKUP':
            return

        # make sure we can contact the MASTER node
        try:
            assert (await self.middleware.call('failover.call_remote', 'core.ping')) == 'pong'
        except Exception:
            self.middleware.logger.error(
                'Failed to contact active controller when syncing encryption keys', exc_info=True
            )
            return

        try:
            await self.middleware.call('failover.call_remote', 'failover.sync_keys_to_remote_node')
        except Exception as e:
            if e.errno == CallError.ENOMETHOD:
                # we're talking to an older system (this happens on upgrades from 11 to 12+)
                enc_pools = await self.middleware.call('pool.query', [('encrypt', '>', 0)])
                if enc_pools:
                    passphrase = await self.middleware.call('failover.call_remote', 'failover.encryption_getkey')
                    await self.middleware.call(
                        'failover.update_encryption_keys', {
                            'pools': [
                                {'name': p['name'], 'passphrase': passphrase or ''}
                                for p in enc_pools
                            ],
                            'sync_keys': False,
                        }
                    )
            else:
                self.middleware.logger.error(
                    'Failed to sync keys from active controller when syncing encryption keys', exc_info=True
                )

    @private
    async def sync_keys_to_remote_node(self, lock=True):
        """
        Sync GELI and/or ZFS encryption keys to the standby node.
        """

        if not await self.middleware.call('failover.licensed'):
            return

        # only sync keys if we're the MASTER node
        if (await self.middleware.call('failover.status')) != 'MASTER':
            return

        # make sure we can contact the BACKUP node
        try:
            assert (await self.middleware.call('failover.call_remote', 'core.ping')) == 'pong'
        except Exception:
            self.middleware.logger.error(
                'Failed to contact standby controller when syncing encryption keys', exc_info=True
            )
            return

        async with ENCRYPTION_CACHE_LOCK if lock else asyncnullcontext():
            try:
                keys = await self.encryption_keys()
                await self.middleware.call(
                    'failover.call_remote', 'cache.put', ['failover_encryption_keys', keys]
                )
            except Exception as e:
                await self.middleware.call('alert.oneshot_create', 'FailoverKeysSyncFailed', None)
                self.middleware.logger.error('Failed to sync keys with standby controller: %s', str(e), exc_info=True)
            else:
                await self.middleware.call('alert.oneshot_delete', 'FailoverKeysSyncFailed', None)
            try:
                kmip_keys = await self.middleware.call('kmip.kmip_memory_keys')
                await self.middleware.call(
                    'failover.call_remote', 'kmip.update_memory_keys', [kmip_keys]
                )
            except Exception as e:
                if e.errno == CallError.ENOMETHOD:
                    # the remote node is an older system that doesn't have
                    # kmip.update_memory_keys method
                    pass
                else:
                    await self.middleware.call(
                        'alert.oneshot_create', 'FailoverKMIPKeysSyncFailed', {'error': str(e)}
                    )
                    self.middleware.logger.error(
                        'Failed to sync KMIP keys with standby controller: %s', str(e), exc_info=True
                    )
            else:
                await self.middleware.call('alert.oneshot_delete', 'FailoverKMIPKeysSyncFailed', None)


async def ha_permission(middleware, app):
    # Skip if session was already authenticated
    if app.authenticated is True:
        return

    # We only care for remote connections (IPv4), in the interlink
    sock = app.request.transport.get_extra_info('socket')
    if sock.family != socket.AF_INET:
        return

    remote_addr, remote_port = app.request.transport.get_extra_info('peername')

    if remote_port <= 1024 and remote_addr in (
        '169.254.10.1',
        '169.254.10.2',
        '169.254.10.20',
        '169.254.10.80',
    ):
        AuthService.session_manager.login(app, TruenasNodeSessionManagerCredentials())


async def hook_pool_change_passphrase(middleware, passphrase_data):
    """
    Hook to set pool passphrase when its changed.
    """
    if not await middleware.call('failover.licensed'):
        return
    if passphrase_data['action'] == 'UPDATE':
        await middleware.call(
            'failover.update_encryption_keys', {
                'pools': [{
                    'name': passphrase_data['pool'], 'passphrase': passphrase_data['passphrase']
                }]
            }
        )
    else:
        await middleware.call('failover.remove_encryption_keys', {'pools': [passphrase_data['pool']]})


sql_queue = queue.Queue()


class Journal:
    path = '/data/ha-journal'

    def __init__(self):
        self.journal = []
        if os.path.exists(self.path):
            try:
                with open(self.path, 'rb') as f:
                    self.journal = pickle.load(f)
            except EOFError:
                # file is empty
                pass
            except Exception:
                logger.warning('Failed to read journal', exc_info=True)

        self.persisted_journal = self.journal.copy()

    def __bool__(self):
        return bool(self.journal)

    def __iter__(self):
        for query, params in self.journal:
            yield query, params

    def __len__(self):
        return len(self.journal)

    def peek(self):
        return self.journal[0]

    def shift(self):
        self.journal = self.journal[1:]

    def append(self, item):
        self.journal.append(item)

    def clear(self):
        self.journal = []

    def write(self):
        if self.persisted_journal != self.journal:
            self._write()
            self.persisted_journal = self.journal.copy()

    def _write(self):
        tmp_file = f'{self.path}.tmp'

        with open(tmp_file, 'wb') as f:
            pickle.dump(self.journal, f)

        os.rename(tmp_file, self.path)


class JournalSync:
    def __init__(self, middleware, sql_queue, journal):
        self.middleware = middleware
        self.sql_queue = sql_queue
        self.journal = journal

        self.failover_status = None
        self._update_failover_status()

        self.last_query_failed = False  # this only affects logging

    def process(self):
        if self.failover_status != 'MASTER':
            if self.journal:
                logger.warning('Node status %s but has %d queries in journal', self.failover_status, len(self.journal))

            self.journal.clear()

        if self.journal:
            os_ver_match = self._os_versions_match()
            if os_ver_match is None:
                raise UnableToDetermineOSVersion()
            elif not os_ver_match:
                raise OSVersionMismatch()

        had_journal_items = bool(self.journal)
        flush_succeeded = self._flush_journal()

        if had_journal_items:
            # We've spent some flushing journal, failover status might have changed
            self._update_failover_status()

        self._consume_queue_nonblocking()
        self.journal.write()

        # Avoid busy loop
        if flush_succeeded:
            # The other node is synchronized, we can wait until new query arrives
            timeout = None
        else:
            # Retry in N seconds,
            timeout = 5

        try:
            item = sql_queue.get(True, timeout)
        except queue.Empty:
            pass
        else:
            # We've spent some time waiting, failover status might have changed
            self._update_failover_status()

            self._handle_sql_queue_item(item)

            # Consume other pending queries
            self._consume_queue_nonblocking()

        self.journal.write()

    def _flush_journal(self):
        while self.journal:
            query, params = self.journal.peek()

            try:
                self.middleware.call_sync('failover.call_remote', 'datastore.sql', [query, params])
            except Exception as e:
                if isinstance(e, CallError) and e.errno in [errno.ECONNREFUSED, errno.ECONNRESET]:
                    logger.trace('Skipping journal sync, node down')
                else:
                    if not self.last_query_failed:
                        logger.exception('Failed to run query %s: %r', query, e)
                        self.last_query_failed = True

                    self.middleware.call_sync('alert.oneshot_create', 'FailoverSyncFailed', None)

                return False
            else:
                self.last_query_failed = False

                self.middleware.call_sync('alert.oneshot_delete', 'FailoverSyncFailed', None)

                self.journal.shift()

        return True

    def _consume_queue_nonblocking(self):
        while True:
            try:
                self._handle_sql_queue_item(self.sql_queue.get_nowait())
            except queue.Empty:
                break

    def _handle_sql_queue_item(self, item):
        if item is None:
            # This is sent by `failover.send_database`
            self.journal.clear()
        else:
            if self.failover_status == 'SINGLE':
                pass
            elif self.failover_status == 'MASTER':
                self.journal.append(item)
            else:
                query, params = item
                logger.warning('Node status %s but executed SQL query: %s', self.failover_status, query)

    def _update_failover_status(self):
        self.failover_status = self.middleware.call_sync('failover.status')

    def _os_versions_match(self):

        try:
            rem = self.middleware.call_sync('failover.get_remote_os_version')
            loc = self.middleware.call_sync('system.version')
        except Exception:
            return False

        if rem is None:
            # happens when other node goes offline
            # (reboot/upgrade etc, etc) the log message
            # is a little misleading in this scenario
            # so make it a little better
            return
        else:
            return loc == rem


def hook_datastore_execute_write(middleware, sql, params):
    sql_queue.put((sql, params))


async def journal_ha(middleware):
    """
    This is a green thread responsible for trying to sync the journal
    file to the other node.
    Every SQL query that could not be synced is stored in the journal.
    """
    await middleware.run_in_thread(journal_sync, middleware)


def journal_sync(middleware):

    alert = True
    while True:
        try:
            journal = Journal()
            journal_sync = JournalSync(middleware, sql_queue, journal)
            while True:
                journal_sync.process()
                alert = True
        except UnableToDetermineOSVersion:
            if alert:
                logger.warning(
                    'Unable to determine remote node OS version. Not syncing journal'
                )
                alert = False
        except OSVersionMismatch:
            if alert:
                logger.warning(
                    'OS version does not match remote node. Not syncing journal'
                )
                alert = False
        except Exception:
            logger.warning('Failed to sync journal', exc_info=True)

        time.sleep(5)


def sync_internal_ips(middleware, iface, carp1_skew, carp2_skew, internal_ip):
    try:
        iface = netif.get_interface(iface)
    except KeyError:
        middleware.logger.error('Internal interface %s not found, skipping setup.', iface)
        return

    carp1_addr = '169.254.10.20'
    carp2_addr = '169.254.10.80'

    found_i = found_1 = found_2 = False
    for address in iface.addresses:
        if address.af != netif.AddressFamily.INET:
            continue
        if str(address.address) == internal_ip:
            found_i = True
        elif str(address.address) == carp1_addr:
            found_1 = True
        elif str(address.address) == carp2_addr:
            found_2 = True
        else:
            iface.remove_address(address)

    # VHID needs to be configured before aliases
    found = 0
    for carp_config in iface.carp_config:
        if carp_config.vhid == 10 and carp_config.advskew == carp1_skew:
            found += 1
        elif carp_config.vhid == 20 and carp_config.advskew == carp2_skew:
            found += 1
        else:
            found -= 1
    if found != 2:
        iface.carp_config = [
            netif.CarpConfig(10, advskew=carp1_skew),
            netif.CarpConfig(20, advskew=carp2_skew),
        ]

    if not found_i:
        iface.add_address(middleware.call_sync('interface.alias_to_addr', {
            'address': internal_ip,
            'netmask': '24',
        }))

    if not found_1:
        iface.add_address(middleware.call_sync('interface.alias_to_addr', {
            'address': carp1_addr,
            'netmask': '32',
            'vhid': 10,
        }))

    if not found_2:
        iface.add_address(middleware.call_sync('interface.alias_to_addr', {
            'address': carp2_addr,
            'netmask': '32',
            'vhid': 20,
        }))


async def interface_pre_sync_hook(middleware):
    hardware = await middleware.call('failover.hardware')
    if hardware == 'MANUAL':
        middleware.logger.debug('No HA hardware detected, skipping interfaces setup.')
        return
    node = await middleware.call('failover.node')
    if node == 'A':
        carp1_skew = 20
        carp2_skew = 80
        internal_ip = '169.254.10.1'
    elif node == 'B':
        carp1_skew = 80
        carp2_skew = 20
        internal_ip = '169.254.10.2'
    else:
        middleware.logger.debug('Could not determine HA node, skipping interfaces setup.')
        return

    iface = await middleware.call('failover.internal_interfaces')
    if not iface:
        middleware.logger.debug(f'No internal interfaces found for {hardware}.')
        return
    iface = iface[0]

    await middleware.run_in_thread(
        sync_internal_ips, middleware, iface, carp1_skew, carp2_skew, internal_ip
    )


async def hook_restart_devd(middleware, *args, **kwargs):
    """
    We need to restart devd when SSH or UI settings are updated because of pf.conf.block rules
    might change.
    """
    if not await middleware.call('failover.licensed'):
        return
    await middleware.call('service.restart', 'failover')


async def hook_license_update(middleware, *args, **kwargs):
    FailoverService.HA_MODE = None

    if not await middleware.call('failover.licensed'):
        return

    etc_generate = ['rc']
    if await middleware.call('system.feature_enabled', 'FIBRECHANNEL'):
        await middleware.call('etc.generate', 'loader')
        etc_generate += ['loader']

    # setup the local heartbeat interface
    heartbeat = True
    try:
        await middleware.call('failover.ensure_remote_client')
    except Exception:
        middleware.logger.warning('Failed to ensure remote client on active')
        heartbeat = False

    if heartbeat:
        # setup the remote controller
        try:
            await middleware.call('failover.send_small_file', '/data/license')
        except Exception:
            middleware.logger.warning('Failed to sync db to standby')

        try:
            await middleware.call('failover.call_remote', 'failover.ensure_remote_client')
        except Exception:
            middleware.logger.warning('Failed to ensure remote client on standby')

        try:
            for etc in etc_generate:
                await middleware.call('failover.call_remote', 'etc.generate', [etc])
        except Exception:
            middleware.logger.warning('etc.generate failed on standby')

    await middleware.call('service.restart', 'failover')
    await middleware.call('failover.status_refresh')


async def hook_post_rollback_setup_ha(middleware, *args, **kwargs):
    """
    This hook needs to be run after a NIC rollback operation and before
    an `interfaces.sync` operation on a TrueNAS HA system
    """
    if not await middleware.call('failover.licensed'):
        return

    try:
        await middleware.call('failover.call_remote', 'core.ping')
    except Exception:
        middleware.logger.debug('[HA] Failed to contact standby controller', exc_info=True)
        return

    await middleware.call('failover.send_database')

    middleware.logger.debug('[HA] Successfully sent database to standby controller')


async def hook_setup_ha(middleware, *args, **kwargs):

    if not await middleware.call('failover.licensed'):
        return

    if not await middleware.call('interface.query', [('failover_vhid', '!=', None)]):
        return

    if not await middleware.call('pool.query'):
        return

    # If we have reached this stage make sure status is up to date
    await middleware.call('failover.status_refresh')

    try:
        ha_configured = await middleware.call(
            'failover.call_remote', 'failover.status'
        ) != 'SINGLE'
    except Exception:
        ha_configured = False

    if ha_configured:
        # If HA is already configured and failover has been disabled,
        # and we have gotten to this point, then this means a few things could be happening.
        #    1. a new interface is being added
        #    2. an alias is being added to an already configured interface
        #    3. an interface is being modified (changing vhid/ip etc)
        #    4. an interface is being deleted

        # In the event #2 happens listed above, there is a race condition that
        # must be accounted for. When an alias is added to an already configured interface,
        # a CARP event will be triggered and the interface will go from MASTER to INIT->BACKUP->MASTER which
        # generates a devd event that is processed by the failover.event plugin.
        # It takes a few seconds for the kernel to transition the CARP interface from BACKUP->MASTER.
        # However, we refresh the failover.status while this interface is transitioning.
        # This means that failover.status returns 'ERROR'.
        # To work around this we check 2 things:
        #    1. if failover.status == 'MASTER' then we continue
        #    or
        #    2. the node in the chassis is marked as the master_node in the webUI
        #      (because failover has been disabled in the webUI)
        cur_status = await middleware.call('failover.status')
        config = await middleware.call('failover.config')
        if cur_status == 'MASTER' or (config['master'] and config['disabled']):

            # In the event HA is configured and the end-user deletes
            # an interface, we need to sync the database over to the
            # standby node before we call `interface.sync`
            middleware.logger.debug('[HA] Sending database to standby node')
            await middleware.call('failover.send_database')

            middleware.logger.debug('[HA] Configuring network on standby node')
            await middleware.call('failover.call_remote', 'interface.sync')

        return

    # when HA is initially setup, we don't synchronize service states to the
    # standby controller. Minimally, however, it's nice to synchronize ssh
    # (if appropriate, of course)
    filters = [('srv_service', '=', 'ssh')]
    ssh_enabled = remote_ssh_started = False
    if ssh := await middleware.call('datastore.query', 'services.services', filters):
        if ssh[0]['srv_enable']:
            ssh_enabled = True
        if await middleware.call('failover.call_remote', 'service.started', ['ssh']):
            remote_ssh_started = True

    middleware.logger.debug('[HA] Setting up')

    middleware.logger.debug('[HA] Synchronizing database and files')
    await middleware.call('failover.sync_to_peer')

    middleware.logger.debug('[HA] Configuring network on standby node')
    await middleware.call('failover.call_remote', 'interface.sync')

    if ssh_enabled and not remote_ssh_started:
        middleware.logger.debug('[HA] Starting SSH on standby node')
        await middleware.call('failover.call_remote', 'service.start', ['ssh'])

    middleware.logger.debug('[HA] Restarting failover service on this node')
    await middleware.call('service.restart', 'failover')

    middleware.logger.debug('[HA] Restarting failover service on remote node')
    await middleware.call('failover.call_remote', 'service.restart', ['failover'])

    middleware.logger.debug('[HA] Resfreshing failover status')
    await middleware.call('failover.status_refresh')

    middleware.logger.info('[HA] Setup complete')

    middleware.send_event('failover.setup', 'ADDED', fields={})


async def hook_sync_geli(middleware, pool=None):
    """
    When a new volume is created we need to sync geli file.
    """
    if not pool.get('encryptkey_path'):
        return

    if not await middleware.call('failover.licensed'):
        return

    try:
        if await middleware.call(
            'failover.call_remote', 'failover.status'
        ) != 'BACKUP':
            return
    except Exception:
        return

    # TODO: failover_sync_peer is overkill as it will sync a bunch of other things
    await middleware.call('failover.sync_to_peer')


async def hook_pool_export(middleware, pool=None, *args, **kwargs):
    await middleware.call('enclosure.sync_zpool', pool)
    await middleware.call('failover.remove_encryption_keys', {'pools': [pool]})


async def hook_pool_post_import(middleware, pool):
    if pool and pool['encrypt'] == 2 and pool['passphrase']:
        await middleware.call(
            'failover.update_encryption_keys', {
                'pools': [{'name': pool['name'], 'passphrase': pool['passphrase']}]
            }
        )


async def hook_pool_lock(middleware, pool=None):
    await middleware.call('failover.remove_encryption_keys', {'pools': [pool]})


async def hook_pool_unlock(middleware, pool=None, passphrase=None):
    if passphrase:
        await middleware.call(
            'failover.update_encryption_keys', {'pools': [{'name': pool['name'], 'passphrase': passphrase}]}
        )


async def hook_pool_dataset_unlock(middleware, datasets):
    datasets = [
        {'name': ds['name'], 'passphrase': ds['encryption_key']}
        for ds in datasets if ds['key_format'].upper() == 'PASSPHRASE'
    ]
    if datasets:
        await middleware.call('failover.update_encryption_keys', {'datasets': datasets})


async def hook_pool_dataset_post_create(middleware, dataset_data):
    if dataset_data['encrypted']:
        if str(dataset_data['key_format']).upper() == 'PASSPHRASE':
            await middleware.call(
                'failover.update_encryption_keys', {
                    'datasets': [{'name': dataset_data['name'], 'passphrase': dataset_data['encryption_key']}]
                }
            )
        else:
            kmip = await middleware.call('kmip.config')
            if kmip['enabled'] and kmip['manage_zfs_keys']:
                await middleware.call('failover.sync_keys_to_remote_node')


async def hook_pool_dataset_post_delete_lock(middleware, dataset):
    await middleware.call('failover.remove_encryption_keys', {'datasets': [dataset]})


async def hook_pool_dataset_change_key(middleware, dataset_data):
    if dataset_data['key_format'] == 'PASSPHRASE' or dataset_data['old_key_format'] == 'PASSPHRASE':
        if dataset_data['key_format'] == 'PASSPHRASE':
            await middleware.call(
                'failover.update_encryption_keys', {
                    'datasets': [{'name': dataset_data['name'], 'passphrase': dataset_data['encryption_key']}]
                }
            )
        else:
            await middleware.call('failover.remove_encryption_keys', {'datasets': [dataset_data['name']]})
    else:
        kmip = await middleware.call('kmip.config')
        if kmip['enabled'] and kmip['manage_zfs_keys']:
            await middleware.call('failover.sync_keys_to_remote_node')


async def hook_pool_dataset_inherit_parent_encryption_root(middleware, dataset):
    await middleware.call('failover.remove_encryption_keys', {'datasets': [dataset]})


async def hook_kmip_sync(middleware, *args, **kwargs):
    await middleware.call('failover.sync_keys_to_remote_node')


async def hook_pool_rekey(middleware, pool=None):
    if not pool or not pool['encryptkey_path']:
        return
    try:
        await middleware.call('failover.send_small_file', pool['encryptkey_path'])
    except Exception as e:
        middleware.logger.warn('Failed to send encryptkey to standby node: %s', e)


async def service_remote(middleware, service, verb, options):
    """
    Most of service actions need to be replicated to the standby node so we don't lose
    too much time during failover regenerating things (e.g. users database)

    This is the middleware side of what legacy UI did on service changes.
    """
    if not options['ha_propagate']:
        return
    # Skip if service is blacklisted or we are not MASTER
    if service in (
        'system',
        'webshell',
        'smartd',
        'system_datasets',
        'nfs',
    ) or await middleware.call('failover.status') != 'MASTER':
        return
    # Nginx should never be stopped on standby node
    if service == 'nginx' and verb == 'stop':
        return
    try:
        await middleware.call('failover.call_remote', 'core.bulk', [
            f'service.{verb}', [[service, options]]
        ])
    except Exception as e:
        if not (isinstance(e, CallError) and e.errno in (errno.ECONNREFUSED, errno.ECONNRESET)):
            middleware.logger.warn(f'Failed to run {verb}({service})', exc_info=True)


async def ready_system_sync_keys(middleware):

    await middleware.call('failover.sync_keys_from_remote_node')


async def _event_system_ready(middleware, event_type, args):
    """
    Method called when system is ready to issue an event in case
    HA upgrade is pending.
    """
    if await middleware.call('failover.status') in ('MASTER', 'SINGLE'):
        return

    if await middleware.call('keyvalue.get', 'HA_UPGRADE', False):
        middleware.send_event('failover.upgrade_pending', 'ADDED', id='BACKUP', fields={'pending': True})


def remote_status_event(middleware, *args, **kwargs):
    middleware.call_sync('failover.status_refresh')


async def setup(middleware):
    middleware.event_register('failover.setup', 'Sent when failover is being setup.')
    middleware.event_register('failover.status', 'Sent when failover status changes.')
    middleware.event_register(
        'failover.disabled_reasons',
        'Sent when the reasons for failover being disabled have changed.'
    )
    middleware.event_register('failover.upgrade_pending', textwrap.dedent('''\
        Sent when system is ready and HA upgrade is pending.

        It is expected the client will react by issuing `upgrade_finish` call
        at user will.'''))
    middleware.event_subscribe('system', _event_system_ready)
    middleware.register_hook('core.on_connect', ha_permission, sync=True)
    middleware.register_hook('datastore.post_execute_write', hook_datastore_execute_write, inline=True)
    middleware.register_hook('pool.post_change_passphrase', hook_pool_change_passphrase, sync=False)
    middleware.register_hook('interface.pre_sync', interface_pre_sync_hook, sync=True)
    middleware.register_hook('interface.post_sync', hook_setup_ha, sync=True)
    middleware.register_hook('interface.post_rollback', hook_post_rollback_setup_ha, sync=True)
    middleware.register_hook('pool.post_create_or_update', hook_setup_ha, sync=True)
    middleware.register_hook('pool.post_create_or_update', hook_sync_geli, sync=True)
    middleware.register_hook('pool.post_export', hook_pool_export, sync=True)
    middleware.register_hook('pool.post_import', hook_setup_ha, sync=True)
    middleware.register_hook('pool.post_import', hook_pool_post_import, sync=True)
    middleware.register_hook('pool.post_lock', hook_pool_lock, sync=True)
    middleware.register_hook('pool.post_unlock', hook_pool_unlock, sync=True)
    middleware.register_hook('dataset.post_create', hook_pool_dataset_post_create, sync=True)
    middleware.register_hook('dataset.post_delete', hook_pool_dataset_post_delete_lock, sync=True)
    middleware.register_hook('dataset.post_lock', hook_pool_dataset_post_delete_lock, sync=True)
    middleware.register_hook('dataset.post_unlock', hook_pool_dataset_unlock, sync=True)
    middleware.register_hook('dataset.change_key', hook_pool_dataset_change_key, sync=True)
    middleware.register_hook(
        'dataset.inherit_parent_encryption_root', hook_pool_dataset_inherit_parent_encryption_root, sync=True
    )
    middleware.register_hook('kmip.sed_keys_sync', hook_kmip_sync, sync=True)
    middleware.register_hook('kmip.zfs_keys_sync', hook_kmip_sync, sync=True)
    middleware.register_hook('pool.rekey_done', hook_pool_rekey, sync=True)
    middleware.register_hook('ssh.post_update', hook_restart_devd, sync=False)
    middleware.register_hook('system.general.post_update', hook_restart_devd, sync=False)
    middleware.register_hook('system.post_license_update', hook_license_update, sync=False)
    middleware.register_hook('service.pre_action', service_remote, sync=False)

    # Register callbacks to properly refresh HA status and send events on changes
    await middleware.call('failover.remote_subscribe', 'system', remote_status_event)
    await middleware.call('failover.remote_subscribe', 'failover.carp_event', remote_status_event)
    await middleware.call('failover.remote_on_connect', remote_status_event)
    await middleware.call('failover.remote_on_disconnect', remote_status_event)

    asyncio.ensure_future(journal_ha(middleware))

    if await middleware.call('system.ready'):
        asyncio.ensure_future(ready_system_sync_keys(middleware))
