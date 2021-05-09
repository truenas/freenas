try:
    from bsd import kld
except ImportError:
    kld = None

from middlewared.plugins.ipmi_.utils import parse_ipmitool_output
from middlewared.schema import Bool, Dict, Int, IPAddr, Str, accepts
from middlewared.service import CallError, CRUDService, filterable, ValidationErrors
from middlewared.utils import filter_list, run
from middlewared.validators import Netmask

import errno
import os
import subprocess

channels = []


class IPMIService(CRUDService):

    class Config:
        cli_namespace = 'network.ipmi'

    @accepts()
    async def is_loaded(self):
        """
        Returns a boolean true value indicating if ipmi device is loaded.
        """
        return os.path.exists('/dev/ipmi0')

    @accepts()
    async def channels(self):
        """
        Return a list with the IPMI channels available.
        """
        return channels

    @filterable
    async def query(self, filters, options):
        """
        Query all IPMI Channels with `query-filters` and `query-options`.
        """
        result = []
        for channel in await self.channels():
            try:
                cp = await run('ipmitool', 'lan', 'print', str(channel))
            except subprocess.CalledProcessError as e:
                raise CallError(f'Failed to get details from channel {channel}: {e}')

            output = cp.stdout.decode()
            data = {'channel': channel, 'id': channel}
            for line in output.split('\n'):
                if ':' not in line:
                    continue

                name, value = line.split(':', 1)
                if not name:
                    continue

                name = name.strip()
                value = value.strip()

                if name == 'IP Address':
                    data['ipaddress'] = value
                elif name == 'Subnet Mask':
                    data['netmask'] = value
                elif name == 'Default Gateway IP':
                    data['gateway'] = value
                elif name == '802.1q VLAN ID':
                    if value == 'Disabled':
                        data['vlan'] = None
                    else:
                        data['vlan'] = value
                elif name == 'IP Address Source':
                    data['dhcp'] = False if value == 'Static Address' else True
            result.append(data)
        return filter_list(result, filters, options)

    @accepts(Int('channel'), Dict(
        'ipmi',
        IPAddr('ipaddress', v6=False),
        Str('netmask', validators=[Netmask(ipv6=False, prefix_length=False)]),
        IPAddr('gateway', v6=False),
        Str('password', private=True),
        Bool('dhcp'),
        Int('vlan', null=True),
    ))
    async def do_update(self, id, data):
        """
        Update `id` IPMI Configuration.

        `ipaddress` is a valid ip which will be used to connect to the IPMI interface.

        `netmask` is the subnet mask associated with `ipaddress`.

        `dhcp` is a boolean value which if unset means that `ipaddress`, `netmask` and `gateway` must be set.
        """

        if not await self.is_loaded():
            raise CallError('The ipmi device could not be found')

        verrors = ValidationErrors()

        if data.get('password') and len(data.get('password')) > 20:
            verrors.add(
                'ipmi_update.password',
                'A maximum of 20 characters are allowed'
            )

        if not data.get('dhcp'):
            for k in ['ipaddress', 'netmask', 'gateway']:
                if not data.get(k):
                    verrors.add(
                        f'ipmi_update.{k}',
                        'This field is required when dhcp is not given'
                    )

        if verrors:
            raise verrors

        args = ['ipmitool', 'lan', 'set', str(id)]
        rv = 0
        if data.get('dhcp'):
            rv |= (await run(*args, 'ipsrc', 'dhcp', check=False)).returncode
        else:
            rv |= (await run(*args, 'ipsrc', 'static', check=False)).returncode
            rv |= (await run(*args, 'ipaddr', data['ipaddress'], check=False)).returncode
            rv |= (await run(*args, 'netmask', data['netmask'], check=False)).returncode
            rv |= (await run(*args, 'defgw', 'ipaddr', data['gateway'], check=False)).returncode
        rv |= (await run(
            *args, 'vlan', 'id', str(data['vlan']) if data.get('vlan') else 'off'
        )).returncode

        rv |= (await run(*args, 'access', 'on', check=False)).returncode
        rv |= (await run(*args, 'auth', 'USER', 'MD2,MD5', check=False)).returncode
        rv |= (await run(*args, 'auth', 'OPERATOR', 'MD2,MD5', check=False)).returncode
        rv |= (await run(*args, 'auth', 'ADMIN', 'MD2,MD5', check=False)).returncode
        rv |= (await run(*args, 'auth', 'CALLBACK', 'MD2,MD5', check=False)).returncode
        # Setting arp have some issues in some hardwares
        # Do not fail if setting these couple settings do not work
        # See #15578
        await run(*args, 'arp', 'respond', 'on', check=False)
        await run(*args, 'arp', 'generate', 'on', check=False)
        if data.get('password'):
            rv |= (await run(
                'ipmitool', 'user', 'set', 'password', '2', data.get('password'),
            )).returncode
        rv |= (await run('ipmitool', 'user', 'enable', '2')).returncode
        # XXX: according to dwhite, this needs to be executed off the box via
        # the lanplus interface.
        # rv |= (await run('ipmitool', 'sol', 'set', 'enabled', 'true', '1')).returncode
        # )
        return rv

    @accepts(Dict(
        'options',
        Int('seconds'),
        Bool('force'),
    ))
    async def identify(self, options):
        """
        Turn on IPMI chassis identify light.

        To turn off specify 0 as `seconds`.
        """
        options = options or {}
        if options.get('force') and options.get('seconds'):
            raise CallError('You have to use either "seconds" or "force" option, not both')

        if options.get('force'):
            cmd = 'force'
        else:
            cmd = str(options.get('seconds'))
        await run('ipmitool', 'chassis', 'identify', cmd)

    @filterable
    async def query_sel(self):
        """
        Query IPMI System Event Log
        """
        return [
            record._asdict()
            for record in parse_ipmitool_output(await run('ipmitool', '-c', 'sel', 'elist'))
        ]

    @accepts()
    async def clear_sel(self):
        """
        Clear IPMI System Event Log
        """
        await run('ipmitool', 'sel', 'clear')


async def setup(middleware):

    try:
        if kld:
            kld.kldload('/boot/kernel/ipmi.ko')
    except OSError as e:
        # Only skip if not already loaded
        if e.errno != errno.EEXIST:
            middleware.logger.warn(f'Cannot load IPMI module: {e}')
            return

    # Scan available channels
    for i in range(1, 17):
        try:
            await run('ipmitool', 'lan', 'print', str(i))
        except subprocess.CalledProcessError:
            continue
        channels.append(i)
