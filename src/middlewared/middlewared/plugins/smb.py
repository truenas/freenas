from middlewared.common.attachment import LockableFSAttachmentDelegate
from middlewared.common.listen import SystemServiceListenMultipleDelegate
from middlewared.schema import Bool, Dict, IPAddr, List, Str, Int, Patch
from middlewared.service import accepts, job, private, SharingService, SystemServiceService, ValidationErrors, filterable
from middlewared.service_exception import CallError
import middlewared.sqlalchemy as sa
from middlewared.utils import osc, Popen, run

import asyncio
import codecs
import enum
import errno
import os
import re
import subprocess
import uuid
from bidict import bidict

try:
    from samba.samba3 import param
    from samba.samba3 import passdb
except ImportError:
    param = None


LOGLEVEL_MAP = bidict({
    '0': 'NONE',
    '1': 'MINIMUM',
    '2': 'NORMAL',
    '3': 'FULL',
    '10': 'DEBUG',
})
RE_NETBIOSNAME = re.compile(r"^[a-zA-Z0-9\.\-_!@#\$%^&\(\)'\{\}~]{1,15}$")

LP_CTX = param.get_context()


class SMBHAMODE(enum.IntEnum):
    """
    'standalone' - Not an HA system.
    'legacy' - Two samba instances simultaneously running on active and standby controllers with no shared state.
    'unified' - Single set of state files migrating between controllers. Single netbios name.
    """
    STANDALONE = 0
    LEGACY = 1
    UNIFIED = 2
    CLUSTERED = 3


class SMBCmd(enum.Enum):
    NET = 'net'
    PDBEDIT = 'pdbedit'
    SHARESEC = 'sharesec'
    SMBCACLS = 'smbcacls'
    SMBCONTROL = 'smbcontrol'
    SMBPASSWD = 'smbpasswd'
    STATUS = 'smbstatus'
    WBINFO = 'wbinfo'


class SMBBuiltin(enum.Enum):
    ADMINISTRATORS = ('builtin_administrators', 'S-1-5-32-544')
    GUESTS = ('builtin_guests', 'S-1-5-32-546')
    USERS = ('builtin_users', 'S-1-5-32-545')

    def unix_groups():
        return [x.value[0] for x in SMBBuiltin]

    def sids():
        return [x.value[1] for x in SMBBuiltin]


class SMBPath(enum.Enum):
    GLOBALCONF = ('/usr/local/etc/smb4.conf', '/etc/smb4.conf', 0o755, False)
    SHARECONF = ('/usr/local/etc/smb4_share.conf', '/etc/smb4_share.conf', 0o755, False)
    STATEDIR = ('/var/db/system/samba4', '/var/db/system/samba4', 0o755, True)
    PRIVATEDIR = ('/var/db/system/samba4/private', '/var/db/system/samba4/private', 0o700, True)
    LEGACYSTATE = ('/root/samba', '/root/samba', 0o755, True)
    LEGACYPRIVATE = ('/root/samba/private', '/root/samba/private', 0o700, True)
    MSG_SOCK = ('/var/db/system/samba4/private/msg.sock', '/var/db/system/samba4/private/msg.sock', 0o700, False)
    RUNDIR = ('/var/run/samba4', '/var/run/samba', 0o755, True)
    LOCKDIR = ('/var/lock', '/var/run/samba-lock', 0o755, True)
    LOGDIR = ('/var/log/samba4', '/var/log/samba4', 0o755, True)
    IPCSHARE = ('/var/tmp', '/tmp', 0o1777, True)

    def platform(self):
        return self.value[1] if osc.IS_LINUX else self.value[0]

    def mode(self):
        return self.value[2]

    def is_dir(self):
        return self.value[3]


class SMBSharePreset(enum.Enum):
    NO_PRESET = {"verbose_name": "No presets", "params": {
        'auxsmbconf': '',
    }}
    DEFAULT_SHARE = {"verbose_name": "Default share parameters", "params": {
        'path_suffix': '',
        'home': False,
        'ro': False,
        'browsable': True,
        'timemachine': False,
        'recyclebin': False,
        'abe': False,
        'hostsallow': [],
        'hostsdeny': [],
        'aapl_name_mangling': False,
        'acl': True,
        'durablehandle': True,
        'shadowcopy': True,
        'streams': True,
        'fsrvp': False,
        'auxsmbconf': '',
    }}
    ENHANCED_TIMEMACHINE = {"verbose_name": "Multi-user time machine", "params": {
        'path_suffix': '%U',
        'timemachine': True,
        'auxsmbconf': '\n'.join([
            'ixnas:zfs_auto_homedir=true' if osc.IS_FREEBSD else 'zfs_core:zfs_auto_create=true',
            'ixnas:default_user_quota=1T' if osc.IS_FREEBSD else 'zfs_core:base_user_quota=1T',
        ])
    }}
    MULTI_PROTOCOL_AFP = {"verbose_name": "Multi-protocol (AFP/SMB) shares", "params": {
        'acl': True,
        'aapl_name_mangling': True,
        'streams': True,
        'durablehandle': False,
        'auxsmbconf': '\n'.join([
            'fruit:locking = netatalk',
            'fruit:metadata = netatalk',
            'fruit:resource = file',
            'streams_xattr:prefix = user.',
            'streams_xattr:store_stream_type = no',
            'oplocks = no',
            'level2 oplocks = no',
            'strict locking = auto',
        ])
    }}
    MULTI_PROTOCOL_NFS = {"verbose_name": "Multi-protocol (NFSv3/SMB) shares", "params": {
        'acl': False,
        'streams': False,
        'durablehandle': False,
        'auxsmbconf': '\n'.join([
            'oplocks = no',
            'level2 oplocks = no',
            'strict locking = yes',
        ])
    }}
    PRIVATE_DATASETS = {"verbose_name": "Private SMB Datasets and Shares", "params": {
        'path_suffix': '%U',
        'auxsmbconf': '\n'.join([
            'ixnas:zfs_auto_homedir=true' if osc.IS_FREEBSD else 'zfs_core:zfs_auto_create=true'
        ])
    }}
    WORM_DROPBOX = {"verbose_name": "SMB WORM. Files become readonly via SMB after 5 minutes", "params": {
        'path_suffix': '',
        'auxsmbconf': '\n'.join([
            'worm:grace_period = 300',
        ])
    }}


class SMBModel(sa.Model):
    __tablename__ = 'services_cifs'

    id = sa.Column(sa.Integer(), primary_key=True)
    cifs_srv_netbiosname = sa.Column(sa.String(120))
    cifs_srv_netbiosname_b = sa.Column(sa.String(120), nullable=True)
    cifs_srv_netbiosalias = sa.Column(sa.String(120), nullable=True)
    cifs_srv_workgroup = sa.Column(sa.String(120))
    cifs_srv_description = sa.Column(sa.String(120))
    cifs_srv_unixcharset = sa.Column(sa.String(120), default="UTF-8")
    cifs_srv_loglevel = sa.Column(sa.String(120), default="0")
    cifs_srv_syslog = sa.Column(sa.Boolean(), default=False)
    cifs_srv_aapl_extensions = sa.Column(sa.Boolean(), default=False)
    cifs_srv_localmaster = sa.Column(sa.Boolean(), default=False)
    cifs_srv_guest = sa.Column(sa.String(120), default="nobody")
    cifs_srv_filemask = sa.Column(sa.String(120))
    cifs_srv_dirmask = sa.Column(sa.String(120))
    cifs_srv_smb_options = sa.Column(sa.Text())
    cifs_srv_bindip = sa.Column(sa.MultiSelectField())
    cifs_SID = sa.Column(sa.String(120), nullable=True)
    cifs_srv_ntlmv1_auth = sa.Column(sa.Boolean(), default=False)
    cifs_srv_enable_smb1 = sa.Column(sa.Boolean(), default=False)
    cifs_srv_admin_group = sa.Column(sa.String(120), nullable=True, default="")
    cifs_srv_next_rid = sa.Column(sa.Integer(), nullable=False)
    cifs_srv_secrets = sa.Column(sa.EncryptedText(), nullable=True)


class WBCErr(enum.Enum):
    SUCCESS = ('Winbind operation successfully completed.', None)
    NOT_IMPLEMENTED = ('Function is not implemented.', errno.ENOSYS)
    UNKNOWN_FAILURE = ('Generic failure.', errno.EFAULT)
    ERR_NO_MEMORY = ('Memory allocation error.', errno.ENOMEM)
    WINBIND_NOT_AVAILABLE = ('Winbind daemon is not available.', errno.EFAULT)
    DOMAIN_NOT_FOUND = ('Domain is not trusted or cannot be found.', errno.EFAULT)
    INVALID_RESPONSE = ('Winbind returned an invalid response.', errno.EINVAL)
    AUTH_ERROR = ('Authentication failed.', errno.EPERM)
    PWD_CHANGE_FAILED = ('Password change failed.', errno.EFAULT)

    def err(self):
        return f'WBC_ERR_{self.name}'


class SMBService(SystemServiceService):

    class Config:
        service = 'cifs'
        service_verb = 'restart'
        datastore = 'services.cifs'
        datastore_extend = 'smb.smb_extend'
        datastore_prefix = 'cifs_srv_'
        cli_namespace = 'service.smb'

    @private
    async def smb_extend(self, smb):
        """Extend smb for netbios."""

        ha_mode = SMBHAMODE[(await self.get_smb_ha_mode())]

        if ha_mode == SMBHAMODE.STANDALONE:
            smb['netbiosname_local'] = smb['netbiosname']

        elif ha_mode == SMBHAMODE.LEGACY:
            failover_node = await self.middleware.call('failover.node')
            smb['netbiosname_local'] = smb['netbiosname'] if failover_node == 'A' else smb['netbiosname_b']

        elif ha_mode == SMBHAMODE.UNIFIED:
            ngc = await self.middleware.call('network.configuration.config')
            smb['netbiosname_local'] = ngc['hostname_virtual']

        smb['netbiosalias'] = (smb['netbiosalias'] or '').split()

        smb['loglevel'] = LOGLEVEL_MAP.get(smb['loglevel'])

        smb.pop('secrets')

        return smb

    async def __validate_netbios_name(self, name):
        return RE_NETBIOSNAME.match(name)

    async def unixcharset_choices(self):
        return await self.generate_choices(
            ['UTF-8', 'ISO-8859-1', 'ISO-8859-15', 'GB2312', 'EUC-JP', 'ASCII']
        )

    @private
    async def generate_choices(self, initial):
        def key_cp(encoding):
            cp = re.compile(r"(?P<name>CP|GB|ISO-8859-|UTF-)(?P<num>\d+)").match(encoding)
            if cp:
                return tuple((cp.group('name'), int(cp.group('num'), 10)))
            else:
                return tuple((encoding, float('inf')))

        charset = await self.common_charset_choices()
        return {
            v: v for v in [
                c for c in sorted(charset, key=key_cp) if c not in initial
            ] + initial
        }

    @accepts()
    async def bindip_choices(self):
        """
        List of valid choices for IP addresses to which to bind the SMB service.
        Addresses assigned by DHCP are excluded from the results.
        """
        choices = {}
        for i in await self.middleware.call('interface.ip_in_use'):
            choices[i['address']] = i['address']
        return choices

    @accepts()
    async def domain_choices(self):
        """
        List of domains visible to winbindd. Returns empty list if winbindd is
        stopped.
        """
        domains = []
        wb = await run([SMBCmd.WBINFO.value, '-m'], check=False)
        if wb.returncode == 0:
            domains = wb.stdout.decode().splitlines()

        return domains

    @private
    async def common_charset_choices(self):

        def check_codec(encoding):
            try:
                return encoding.upper() if codecs.lookup(encoding) else False
            except LookupError:
                return False

        proc = await Popen(
            ['/usr/bin/iconv', '-l'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = (await proc.communicate())[0].decode()

        encodings = set()
        for line in output.splitlines():
            enc = [e for e in line.split() if check_codec(e)]

            if enc:
                cp = enc[0]
                for e in enc:
                    if e in ('UTF-8', 'ASCII', 'GB2312', 'HZ-GB-2312', 'CP1361'):
                        cp = e
                        break

                encodings.add(cp)

        return encodings

    @private
    async def store_ldap_admin_password(self):
        """
        This is required if the LDAP directory service is enabled. The ldap admin dn and
        password are stored in private/secrets.tdb file.
        """
        ldap = await self.middleware.call('datastore.config', 'directoryservice.ldap')
        if not ldap['ldap_enable']:
            return True

        set_pass = await run([SMBCmd.SMBPASSWD.value, '-w', ldap['ldap_bindpw']], check=False)
        if set_pass.returncode != 0:
            self.logger.debug(f"Failed to set set ldap bindpw in secrets.tdb: {set_pass.stdout.decode()}")
            return False

        return True

    @private
    async def getparm(self, parm, section):
        """
        Get a parameter from the smb4.conf file. This is more reliable than
        'testparm --parameter-name'. testparm will fail in a variety of
        conditions without returning the parameter's value.
        """
        ret = None
        try:
            ret = await self.middleware.call('sharing.smb.reg_getparm', section, parm)
        except Exception as e:
            if not section.upper() == 'GLOBAL':
                raise CallError(f'Attempt to query smb4.conf parameter [{parm}] failed with error: {e}')

        if ret:
            return ret

        try:
            LP_CTX.load(SMBPath.GLOBALCONF.platform())
        except Exception as e:
            self.logger.warning("Failed to reload smb.conf: %s", e)

        return LP_CTX.get(parm)

    @private
    def set_passdb_backend(self, backend_type):
        if backend_type not in ['tdbsam', 'ldapsam']:
            raise CallError(f'Unsupported passdb backend type: [{backend_type}]', errno.EINVAL)
        try:
            LP_CTX.load(SMBPath.GLOBALCONF.platform())
        except Exception as e:
            self.logger.warning("Failed to reload smb.conf: %s", e)

        return LP_CTX.set('passdb backend', backend_type)

    @private
    async def get_next_rid(self):
        next_rid = (await self.config())['next_rid']
        if next_rid == 0:
            try:
                private_dir = await self.middleware.call("smb.getparm", "private directory", "GLOBAL")
                next_rid = passdb.PDB(f"tdbsam:{private_dir}/passdb.tdb").new_rid()
            except Exception:
                self.logger.warning("Failed to initialize RID counter from passdb. "
                                    "Using default value for initialization.", exc_info=True)
                next_rid = 5000

        await self.middleware.call('datastore.update', 'services.cifs', 1,
                                   {'next_rid': next_rid + 1},
                                   {'prefix': 'cifs_srv_'})
        return next_rid

    @private
    async def setup_directories(self):
        await self.reset_smb_ha_mode()
        await self.middleware.call('etc.generate', 'smb')

        for p in SMBPath:
            if p == SMBPath.STATEDIR:
                path = await self.middleware.call("smb.getparm", "state directory", "global")
            elif p == SMBPath.PRIVATEDIR:
                path = await self.middleware.call("smb.getparm", "privatedir", "global")
            else:
                path = p.platform()

            try:
                if not await self.middleware.call('filesystem.acl_is_trivial', path):
                    self.logger.warning("Inappropriate ACL detected on path [%s] stripping ACL", path)
                    stripacl = await run(['setfacl', '-b', path], check=False)
                    if stripacl.returncode != 0:
                        self.logger.warning("Failed to strip ACL from path %s: %s", path,
                                            stripacl.stderr.decode())
            except CallError:
                # Currently only time CallError is raise here is on ENOENT, which may be expected
                pass

            if not os.path.exists(path):
                if p.is_dir():
                    os.mkdir(path, p.mode())
            else:
                os.chmod(path, p.mode())

    @private
    async def import_conf_to_registry(self):
        drop = await run([SMBCmd.NET.value, 'conf', 'drop'], check=False)
        if drop.returncode != 0:
            self.logger.warning('failed to drop existing share config: %s',
                                drop.stderr.decode())
        load = await run([SMBCmd.NET.value, 'conf', 'import',
                          SMBPath.SHARECONF.platform()], check=False)
        if load.returncode != 0:
            self.logger.warning('failed to load share config: %s',
                                load.stderr.decode())

    @private
    async def ctdb_wait(self):
        while True:
            healthy = await self.middleware.call('ctdb.general.healthy')
            if healthy:
                return

            await asyncio.sleep(1)

    @private
    @job(lock="smb_configure")
    async def configure(self, job, create_paths=True):
        """
        Many samba-related tools will fail if they are unable to initialize
        a messaging context, which will happen if the samba-related directories
        do not exist or have incorrect permissions.
        """
        data = await self.config()
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        job.set_progress(0, 'Setting up SMB directories.')
        if create_paths:
            await self.setup_directories()

        job.set_progress(10, 'Generating stub SMB config.')
        await self.middleware.call('etc.generate', 'smb')

        """
        smb4.conf registry setup. The smb config is split between five
        different middleware plugins (smb, idmap, ad, ldap, sharing.smb).
        This initializes them in the above order so that configuration errors
        do not occur.
        """
        if ha_mode == SMBHAMODE.CLUSTERED:
            """
            Cluster should be healthy before we start synchonizing configuration.
            """
            job.set_progress(25, 'Waiting for ctdb to become healthy.')
            await self.ctdb_wait()
            job.set_progress(30, 'Generating SMB, idmap, and directory service config.')
            await self.middleware.call('smb.initialize_globals')
            ad_enabled = (await self.middleware.call('smb.getparm', 'security', 'global')) == 'ADS'
            """
            Clustered LDAP client is currently not implemented.
            """
            # ldap_enabled = (await self.middleware.call('directoryservices.get_conf', 'directoryservice.ldap'))['enable']
            ldap_enabled = False
            await self.middleware.call('idmap.ctdb_setup')
        else:
            job.set_progress(25, 'generating SMB, idmap, and directory service config.')
            await self.middleware.call('smb.initialize_globals')
            ad_enabled = (await self.middleware.call('activedirectory.config'))['enable']
            ldap_enabled = (await self.middleware.call('ldap.config'))['enable']
            await self.middleware.call('idmap.synchronize')

        if ad_enabled:
            await self.middleware.call('activedirectory.synchronize')
            await self.middleware.call('idmap.synchronize')
        elif ldap_enabled:
            await self.middleware.call('ldap.synchronize')
            await self.middleware.call('idmap.synchronize')

        job.set_progress(30, 'Setting up server SID.')
        await self.middleware.call('smb.set_sid', data['cifs_SID'])

        """
        If the ldap passdb backend is being used, then the remote LDAP server
        will provide the SMB users and groups. We skip these steps to avoid having
        samba potentially try to write our local users and groups to the remote
        LDAP server.

        Local users and groups are skipped on clustered servers for now.
        """
        passdb_backend = await self.middleware.call('smb.getparm', 'passdb backend', 'global')
        if ha_mode != SMBHAMODE.CLUSTERED and passdb_backend == "tdbsam":
            job.set_progress(40, 'Synchronizing passdb and groupmap.')
            await self.middleware.call('etc.generate', 'user')
            pdb_job = await self.middleware.call("smb.synchronize_passdb")
            grp_job = await self.middleware.call("smb.synchronize_group_mappings")
            await pdb_job.wait()
            await grp_job.wait()
            await self.middleware.call("admonitor.start")

        """
        The following steps ensure that we cleanly import our SMB shares
        into the registry.
        This step is not required when underlying database is clustered (cluster node should
        just recover with info from other nodes on reboot).
        """
        job.set_progress(60, 'generating SMB share configuration.')
        await self.middleware.call('sharing.smb.sync_registry')

        """
        It is possible that system dataset was migrated or an upgrade
        wiped our secrets.tdb file. Re-import directory service secrets
        if they are missing from the current running configuration.
        """
        job.set_progress(65, 'Initializing directory services')
        await self.middleware.call("directoryservices.initialize")

        job.set_progress(70, 'Checking SMB server status.')
        if await self.middleware.call("service.started", "cifs"):
            job.set_progress(80, 'Restarting SMB service.')
            await self.middleware.call("service.restart", "cifs")
        job.set_progress(100, 'Finished configuring SMB.')

    @private
    async def get_smb_ha_mode(self):
        if await self.middleware.call('cache.has_key', 'SMB_HA_MODE'):
            return await self.middleware.call('cache.get', 'SMB_HA_MODE')

        gl_enabled = (await self.middleware.call('service.query', [('service', '=', 'glusterd')], {'get': True}))['enable']

        if gl_enabled:
            hamode = SMBHAMODE['CLUSTERED'].name
        elif await self.middleware.call('system.is_enterprise') and await self.middleware.call('failover.licensed'):
            system_dataset = await self.middleware.call('systemdataset.config')
            if system_dataset['pool'] != await self.middleware.call('boot.pool_name'):
                hamode = SMBHAMODE['UNIFIED'].name
            else:
                hamode = SMBHAMODE['LEGACY'].name

        else:
            hamode = SMBHAMODE['STANDALONE'].name

        await self.middleware.call('cache.put', 'SMB_HA_MODE', hamode)
        return hamode

    @private
    async def cluster_check(self):
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            return

        ctdb_healthy = await self.middleware.call('ctdb.general.healthy')
        if not ctdb_healthy:
            raise CallError("SMB-related changes are not permitted while cluster unhealthy.")

    @private
    async def reset_smb_ha_mode(self):
        await self.middleware.call('cache.pop', 'SMB_HA_MODE')
        return await self.get_smb_ha_mode()

    @private
    async def apply_aapl_changes(self):
        shares = await self.middleware.call('sharing.smb.query')
        for share in shares:
            diff = await self.middleware.call(
                'sharing.smb.diff_middleware_and_registry', share['name'], share
            )

            if diff is None:
                self.logger.warning("Share [%s] does not exist in registry.",
                                    share['name'])
                continue

            share_name = share['name'] if not share['home'] else 'homes'
            await self.middleware.call('sharing.smb.apply_conf_diff',
                                       'REGISTRY', share_name, diff)

    @private
    async def validate_smb(self, new, verrors):
        try:
            await self.middleware.call('sharing.smb.validate_aux_params',
                                       new['smb_options'],
                                       'smb_update.smb_options')
        except ValidationErrors as errs:
            verrors.add_child('smb_update.smb_options', errs)

        if new.get('unixcharset') and new['unixcharset'] not in await self.unixcharset_choices():
            verrors.add(
                'smb_update.unixcharset',
                'Please provide a valid value for unixcharset'
            )

        for i in ('workgroup', 'netbiosname', 'netbiosname_b', 'netbiosalias'):
            """
            There are two cases where NetBIOS names must be rejected:
            1. They contain invalid characters for NetBIOS protocol
            2. The name is identical to the NetBIOS workgroup.
            """
            if not new.get(i):
                """
                Skip validation on NULL or empty string. If parameter is required for
                the particular server configuration, then a separate validation error
                will be added in a later validation step.
                """
                continue

            if i == 'netbiosalias':
                for idx, item in enumerate(new[i]):
                    if not await self.__validate_netbios_name(item):
                        verrors.add(f'smb_update.{i}.{idx}', f'Invalid NetBIOS name: {item}')
                    if item.casefold() == new['workgroup'].casefold():
                        verrors.add(
                            f'smb_update.{i}.{idx}',
                            f'NetBIOS alias [{item}] conflicts with workgroup name.'
                        )
            else:
                if not await self.__validate_netbios_name(new[i]):
                    verrors.add(f'smb_update.{i}', f'Invalid NetBIOS name: {new[i]}')

                if i != 'workgroup' and new[i].casefold() == new['workgroup'].casefold():
                    verrors.add(
                        f'smb_update.{i}',
                        f'NetBIOS name [{new[i]}] conflicts with workgroup name.'
                    )

        if new['guest'] == 'root':
            verrors.add('smb_update.guest', '"root" is not a permitted guest account')

        if new.get('bindip'):
            bindip_choices = list((await self.bindip_choices()).keys())
            for idx, item in enumerate(new['bindip']):
                if item not in bindip_choices:
                    verrors.add(f'smb_update.bindip.{idx}', f'IP address [{item}] is not a configured address for this server')

        if not new.get('workgroup'):
            verrors.add('smb_update.workgroup', 'workgroup field is required.')

        if not new.get('netbiosname'):
            verrors.add('smb_update.netbiosname', 'NetBIOS name is required.')

        ha_mode = SMBHAMODE[(await self.get_smb_ha_mode())]
        if ha_mode == SMBHAMODE.LEGACY:
            if not new.get('netbiosname_b'):
                verrors.add('smb_update.netbiosname_b',
                            'NetBIOS name for B controller is required while '
                            'system dataset is located on boot pool.')
            if len(new['netbiosalias']) == 0:
                verrors.add('smb_update.netbiosalias',
                            'At least one netbios alias is required for active '
                            'controller while system dataset is located on '
                            'boot pool.')

        elif ha_mode == SMBHAMODE.UNIFIED:
            if not new.get('netbiosname_local'):
                verrors.add('smb_update.netbiosname',
                            'Virtual Hostname is required for SMB configuration '
                            'on high-availability servers.')

            elif not await self.__validate_netbios_name(new['netbiosname_local']):
                verrors.add('smb_update.netbiosname',
                            'Virtual hostname does not conform to NetBIOS naming standards.')

        for i in ('filemask', 'dirmask'):
            if not new[i]:
                continue
            try:
                if int(new[i], 8) & ~0o11777:
                    raise ValueError('Not an octet')
            except (ValueError, TypeError):
                verrors.add(f'smb_update.{i}', 'Not a valid mask')

    @private
    async def config(self):
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            return await super().config()

        return await self.middleware.call('smb.reg_config')

    @accepts(Dict(
        'smb_update',
        Str('netbiosname', max_length=15),
        Str('netbiosname_b', max_length=15),
        List('netbiosalias', items=[Str('netbios_alias', max_length=15)]),
        Str('workgroup'),
        Str('description'),
        Bool('enable_smb1'),
        Str('unixcharset'),
        Str('loglevel', enum=['NONE', 'MINIMUM', 'NORMAL', 'FULL', 'DEBUG']),
        Bool('syslog'),
        Bool('aapl_extensions'),
        Bool('localmaster'),
        Str('guest'),
        Str('admin_group', required=False, default=None, null=True),
        Str('filemask'),
        Str('dirmask'),
        Bool('ntlmv1_auth'),
        List('bindip', items=[IPAddr('ip')]),
        Str('smb_options', max_length=None),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update SMB Service Configuration.

        `netbiosname` defaults to the original hostname of the system.

        `netbiosalias` a list of netbios aliases. If Server is joined to an AD domain, additional Kerberos
        Service Principal Names will be generated for these aliases.

        `workgroup` specifies the NetBIOS workgroup to which the TrueNAS server belongs. This will be automatically
        set to the correct value during the process of joining an AD domain. `workgroup` and `netbiosname` should have different values.

        `enable_smb1` allows legacy SMB clients to connect to the server when enabled.

        `aapl_extensions` enables support for SMB2 protocol extensions for MacOS clients. This is not a requirement for MacOS support,
        but is currently a requirement for time machine support.

        `localmaster` when set, determines if the system participates in a browser election.

        `guest` attribute is specified to select the account to be used for guest access. It defaults to "nobody".

        The group specified as the SMB `admin_group` will be automatically added as a foreign group member of S-1-5-32-544 (builtin\admins).
        This will afford the group all privileges granted to a local admin. Any SMB group may be selected (including AD groups).

        `ntlmv1_auth` enables a legacy and insecure authentication method, which may be required for legacy or poorly-implemented
        SMB clients.

        `smb_options` smb.conf parameters that are not covered by the above supported configuration options may be added as
        an smb_option. Not all options are tested or supported, and behavior of smb_options may change between releases. Stability of
        smb.conf options is not guaranteed.
        """
        old = await self.config()

        new = old.copy()
        new.update(data)
        await self.middleware.call("smb.cluster_check")

        verrors = ValidationErrors()
        ad_enabled = (await self.middleware.call('activedirectory.get_state') != "DISABLED")
        if ad_enabled:
            for i in ('workgroup', 'netbiosname', 'netbiosname_b', 'netbiosalias'):
                if old[i] != new[i]:
                    verrors.add(f'smb_update.{i}',
                                'This parameter may not be changed after joining Active Directory (AD). '
                                'If it must be changed, the proper procedure is to leave the AD domain '
                                'and then alter the parameter before re-joining the domain.')

        await self.validate_smb(new, verrors)
        verrors.check()

        if new['admin_group'] and new['admin_group'] != old['admin_group']:
            await self.middleware.call('smb.add_admin_group', new['admin_group'])

        # TODO: consider using bidict
        for k, v in LOGLEVEL_MAP.items():
            if new['loglevel'] == v:
                new['loglevel'] = k
                break

        new['netbiosalias'] = ' '.join(new['netbiosalias'])

        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            await self.middleware.call('smb.reg_update', new)
            await self.compress(new)
            await self._update_service(old, new)
        else:
            await self.middleware.call('smb.reg_update', new)
            await self._service_change(self._config.service, 'restart')

        await self.reset_smb_ha_mode()

        """
        Toggling aapl_extensions will require changes to all shares
        on server (enabling vfs_fruit and possibly changing catia params).
        """
        if old['aapl_extensions'] != new['aapl_extensions']:
            await self.apply_aapl_changes()

        return await self.config()

    @private
    async def compress(self, data):
        data.pop('netbiosname_local', None)
        data.pop('next_rid')
        return data


class SharingSMBModel(sa.Model):
    __tablename__ = 'sharing_cifs_share'

    id = sa.Column(sa.Integer(), primary_key=True)
    cifs_purpose = sa.Column(sa.String(120))
    cifs_path = sa.Column(sa.String(255), nullable=True)
    cifs_path_suffix = sa.Column(sa.String(255), nullable=False)
    cifs_home = sa.Column(sa.Boolean(), default=False)
    cifs_name = sa.Column(sa.String(120))
    cifs_comment = sa.Column(sa.String(120))
    cifs_ro = sa.Column(sa.Boolean(), default=False)
    cifs_browsable = sa.Column(sa.Boolean(), default=True)
    cifs_recyclebin = sa.Column(sa.Boolean(), default=False)
    cifs_guestok = sa.Column(sa.Boolean(), default=False)
    cifs_hostsallow = sa.Column(sa.Text())
    cifs_hostsdeny = sa.Column(sa.Text())
    cifs_auxsmbconf = sa.Column(sa.Text())
    cifs_aapl_name_mangling = sa.Column(sa.Boolean())
    cifs_abe = sa.Column(sa.Boolean())
    cifs_acl = sa.Column(sa.Boolean())
    cifs_durablehandle = sa.Column(sa.Boolean())
    cifs_streams = sa.Column(sa.Boolean())
    cifs_timemachine = sa.Column(sa.Boolean(), default=False)
    cifs_vuid = sa.Column(sa.String(36))
    cifs_shadowcopy = sa.Column(sa.Boolean())
    cifs_fsrvp = sa.Column(sa.Boolean())
    cifs_enabled = sa.Column(sa.Boolean(), default=True)
    cifs_share_acl = sa.Column(sa.Text())
    cifs_cluster_volname = sa.Column(sa.String(255), nullable=False)


class SharingSMBService(SharingService):

    share_task_type = 'SMB'

    class Config:
        namespace = 'sharing.smb'
        datastore = 'sharing.cifs_share'
        datastore_prefix = 'cifs_'
        datastore_extend = 'sharing.smb.extend'
        cli_namespace = 'sharing.smb'

    @private
    async def sharing_task_determine_locked(self, data, locked_datasets):
        return await self.middleware.call(
            'pool.dataset.path_in_locked_datasets', data[self.path_field], locked_datasets
        ) if data[self.path_field] else False

    @private
    async def strip_comments(self, data):
        parsed_config = ""
        for entry in data['auxsmbconf'].splitlines():
            if entry == "" or entry.startswith(('#', ';')):
                continue
            parsed_config += entry if len(parsed_config) == 0 else f'\n{entry}'

        data['auxsmbconf'] = parsed_config

    @accepts(Dict(
        'sharingsmb_create',
        Str('purpose', enum=[x.name for x in SMBSharePreset], default=SMBSharePreset.DEFAULT_SHARE.name),
        Str('path', required=True),
        Str('path_suffix', default=''),
        Bool('home', default=False),
        Str('name', max_length=80),
        Str('comment', default=''),
        Bool('ro', default=False),
        Bool('browsable', default=True),
        Bool('timemachine', default=False),
        Bool('recyclebin', default=False),
        Bool('guestok', default=False),
        Bool('abe', default=False),
        List('hostsallow'),
        List('hostsdeny'),
        Bool('aapl_name_mangling', default=False),
        Bool('acl', default=True),
        Bool('durablehandle', default=True),
        Bool('shadowcopy', default=True),
        Bool('streams', default=True),
        Bool('fsrvp', default=False),
        Str('auxsmbconf', max_length=None, default=''),
        Bool('enabled', default=True),
        Str('cluster_volname', default=''),
        register=True
    ))
    async def do_create(self, data):
        """
        Create a SMB Share.

        `purpose` applies common configuration presets depending on intended purpose.

        `timemachine` when set, enables Time Machine backups for this share.

        `ro` when enabled, prohibits write access to the share.

        `guestok` when enabled, allows access to this share without a password.

        `hostsallow` is a list of hostnames / IP addresses which have access to this share.

        `hostsdeny` is a list of hostnames / IP addresses which are not allowed access to this share. If a handful
        of hostnames are to be only allowed access, `hostsdeny` can be passed "ALL" which means that it will deny
        access to ALL hostnames except for the ones which have been listed in `hostsallow`.

        `acl` enables support for storing the SMB Security Descriptor as a Filesystem ACL.

        `streams` enables support for storing alternate datastreams as filesystem extended attributes.

        `fsrvp` enables support for the filesystem remote VSS protocol. This allows clients to create
        ZFS snapshots through RPC.

        `shadowcopy` enables support for the volume shadow copy service.

        `auxsmbconf` is a string of additional smb4.conf parameters not covered by the system's API.
        """
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        await self.middleware.call("smb.cluster_check")

        verrors = ValidationErrors()
        path = data['path']

        await self.clean(data, 'sharingsmb_create', verrors)
        await self.validate(data, 'sharingsmb_create', verrors)

        verrors.check()

        if not data['cluster_volname']:
            if path and not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as e:
                    raise CallError(f'Failed to create {path}: {e}')

        await self.apply_presets(data)
        await self.compress(data)
        if ha_mode != SMBHAMODE.CLUSTERED:
            vuid = await self.generate_vuid(data['timemachine'])
            data.update({'vuid': vuid})
            data['id'] = await self.middleware.call(
                'datastore.insert', self._config.datastore, data,
                {'prefix': self._config.datastore_prefix})

        await self.strip_comments(data)
        await self.middleware.call('sharing.smb.reg_addshare', data)
        enable_aapl = await self.check_aapl(data)

        if enable_aapl:
            await self._service_change('cifs', 'restart')
        else:
            await self._service_change('cifs', 'reload')

        if ha_mode == SMBHAMODE.CLUSTERED:
            ret = await self.query([('name', '=', data['name'])],
                                   {'get': True, 'extra': {'ha_mode': ha_mode.name}})
        else:
            ret = await self.get_instance(data['id'])

        return ret

    @accepts(
        Int('id'),
        Patch(
            'sharingsmb_create',
            'sharingsmb_update',
            ('attr', {'update': True})
        )
    )
    async def do_update(self, id, data):
        """
        Update SMB Share of `id`.
        """
        await self.middleware.call("smb.cluster_check")
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]

        verrors = ValidationErrors()
        path = data.get('path')

        old = await self.query([('id', '=', id)], {'get': True, 'extra': {'ha_mode': ha_mode.name}})

        new = old.copy()
        new.update(data)

        oldname = 'homes' if old['home'] else old['name']
        newname = 'homes' if new['home'] else new['name']

        new['vuid'] = await self.generate_vuid(new['timemachine'], new['vuid'])
        await self.clean(new, 'sharingsmb_update', verrors, id=id)
        await self.validate(new, 'sharingsmb_update', verrors, old=old)

        verrors.check()

        if not new['cluster_volname']:
            if path and not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as e:
                    raise CallError(f'Failed to create {path}: {e}')

        if old['purpose'] != new['purpose']:
            await self.apply_presets(new)

        if ha_mode == SMBHAMODE.CLUSTERED:
            diff = await self.middleware.call(
                'sharing.smb.diff_middleware_and_registry', new['name'], new
            )
            share_name = new['name'] if not new['home'] else 'homes'
            await self.middleware.call('sharing.smb.apply_conf_diff',
                                       'REGISTRY', share_name, diff)

            enable_aapl = await self.check_aapl(new)
            if enable_aapl:
                await self._service_change('cifs', 'restart')
            else:
                await self._service_change('cifs', 'reload')

            return await self.query([('name', '=', share_name)],
                                    {'get': True, 'extra': {'ha_mode': ha_mode.name}})

        old_is_locked = (await self.get_instance(id))['locked']
        if old['path'] != new['path']:
            new_is_locked = await self.middleware.call('pool.dataset.path_in_locked_datasets', new['path'])
        else:
            new_is_locked = old_is_locked

        await self.compress(new)
        await self.middleware.call(
            'datastore.update', self._config.datastore, id, new,
            {'prefix': self._config.datastore_prefix})

        await self.strip_comments(new)
        if not new_is_locked:
            """
            Enabling AAPL SMB2 extensions globally affects SMB shares. If this
            happens, the SMB service _must_ be restarted. Skip this step if dataset
            underlying the new path is encrypted.
            """
            enable_aapl = await self.check_aapl(new)
        else:
            enable_aapl = False

        """
        OLD    NEW   = dataset path is encrypted
         ----------
         -      -    = pre-12 behavior. Remove and replace if name changed, else update.
         -      X    = Delete share from running configuration
         X      -    = Add share to running configuration
         X      X    = no-op
        """
        if old_is_locked and new_is_locked:
            """
            Configuration change only impacts a locked SMB share. From standpoint of
            running config, this is a no-op. No need to restart or reload service.
            """
            return await self.get_instance(id)

        elif not old_is_locked and not new_is_locked:
            """
            Default behavior before changes for locked datasets.
            """
            if newname != oldname:
                # This is disruptive change. Share is actually being removed and replaced.
                # Forcibly closes any existing SMB sessions.
                await self.close_share(oldname)
                try:
                    await self.middleware.call('sharing.smb.reg_delshare', oldname)
                except Exception:
                    self.logger.warning('Failed to remove stale share [%s]',
                                        old['name'], exc_info=True)
                await self.middleware.call('sharing.smb.reg_addshare', new)
            else:
                diff = await self.middleware.call(
                    'sharing.smb.diff_middleware_and_registry', new['name'], new
                )
                if diff is None:
                    await self.middleware.call('sharing.smb.reg_addshare', new)
                else:
                    share_name = new['name'] if not new['home'] else 'homes'
                    await self.middleware.call('sharing.smb.apply_conf_diff',
                                               'REGISTRY', share_name, diff)

        elif old_is_locked and not new_is_locked:
            """
            Since the old share was not in our running configuration, we need
            to add it.
            """
            await self.middleware.call('sharing.smb.reg_addshare', new)

        elif not old_is_locked and new_is_locked:
            try:
                await self.middleware.call('sharing.smb.reg_delshare', oldname)
            except Exception:
                self.logger.warning('Failed to remove locked share [%s]',
                                    old['name'], exc_info=True)

        if enable_aapl:
            await self._service_change('cifs', 'restart')
        else:
            await self._service_change('cifs', 'reload')

        return await self.get_instance(id)

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete SMB Share of `id`. This will forcibly disconnect SMB clients
        that are accessing the share.
        """
        await self.middleware.call("smb.cluster_check")
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            share = await self._get_instance(id)
            result = await self.middleware.call('datastore.delete', self._config.datastore, id)
        else:
            share = await self.query([('id', '=', id)], {'get': True})
            result = id

        await self.close_share(share['name'])
        try:
            await self.middleware.call('smb.sharesec._delete', share['name'] if not share['home'] else 'homes')
        except Exception:
            self.logger.debug('Failed to delete share ACL for [%s].', share['name'], exc_info=True)

        try:
            await self.middleware.call('sharing.smb.reg_delshare',
                                       share['name'] if not share['home'] else 'homes')
        except Exception:
            self.logger.warn('Failed to remove registry entry for [%s].', share['name'], exc_info=True)

        if share['timemachine']:
            await self.middleware.call('service.restart', 'mdns')

        return result

    @filterable
    async def query(self, filters, options):
        """
        Query shares with filters. In clustered environments, local datastore query
        is bypassed in favor of clustered registry.
        """
        extra = options.get('extra', {})
        ha_mode_str = extra.get('ha_mode')
        if ha_mode_str is None:
            ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        else:
            ha_mode = SMBHAMODE[ha_mode_str]

        if ha_mode == SMBHAMODE.CLUSTERED:
            result = await self.middleware.call(
                'sharing.smb.registry_query', filters, options
            )
        else:
            return await super().query(filters, options)
        return result

    @private
    async def check_aapl(self, data):
        """
        Returns whether we changed the global aapl support settings.
        """
        aapl_extensions = (await self.middleware.call('smb.config'))['aapl_extensions']

        if not aapl_extensions and data['timemachine']:
            await self.middleware.call('datastore.update', 'services_cifs', 1,
                                       {'cifs_srv_aapl_extensions': True})
            return True

        return False

    @private
    async def close_share(self, share_name):
        c = await run([SMBCmd.SMBCONTROL.value, 'smbd', 'close-share', share_name], check=False)
        if c.returncode != 0:
            if "Can't find pid" in c.stderr.decode():
                # smbd is not running. Don't log error message.
                return

            self.logger.warn('Failed to close smb share [%s]: [%s]',
                             share_name, c.stderr.decode().strip())

    @private
    async def clean(self, data, schema_name, verrors, id=None):
        data['name'] = await self.name_exists(data, schema_name, verrors, id)

    @private
    async def validate_aux_params(self, data, schema_name):
        """
        libsmbconf expects to be provided with key-value pairs.
        """
        verrors = ValidationErrors()
        aux_blacklist = [
            'state directory',
            'private directory',
            'private dir',
            'log level',
            'cache directory',
            'clustering',
            'ctdb socket',
            'socket options',
        ]
        for entry in data.splitlines():
            if entry == '' or entry.startswith(('#', ';')):
                continue

            kv = entry.split('=', 1)
            if len(kv) != 2:
                verrors.add(
                    f'{schema_name}.auxsmbconf',
                    f'Auxiliary parameters must be in the format of "key = value": {entry}'
                )
                continue

            if kv[0].strip() in aux_blacklist:
                """
                This one checks our ever-expanding enumeration of badness.
                Parameters are blacklisted if incorrect values can prevent smbd from starting.
                """
                verrors.add(
                    f'{schema_name}.auxsmbconf',
                    f'{kv[0]} is a blacklisted auxiliary parameter. Changes to this parameter '
                    'are not permitted.'
                )

            if schema_name == 'smb_update.smb_options' and ':' not in kv[0]:
                """
                lib/param doesn't validate params containing a colon.
                this dump_a_parameter() wraps around the respective lp_ctx
                function in samba that checks the known parameter table.
                This should be a lightweight validation of GLOBAL params.
                """
                try:
                    LP_CTX.dump_a_parameter(kv[0].strip())
                except RuntimeError as e:
                    verrors.add(
                        f'{schema_name}.auxsmbconf',
                        str(e)
                    )

        verrors.check()

    @private
    async def cluster_share_validate(self, data, schema_name, verrors):
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            return

        if data['shadowcopy']:
            verrors.add(
                f'{schema_name}.shadowcopy',
                'Shadow Copies are not implemented for clustered shares.'
            )
        if data['fsrvp']:
            verrors.add(
                f'{schema_name}.fsrvp',
                'FSRVP support is not implemented for clustered shares.'
            )
        if not data['cluster_volname']:
            verrors.add(
                f'{schema_name}.cluster_volname',
                'Cluster volume name is required for clustered shares.'
            )

    @private
    async def validate(self, data, schema_name, verrors, old=None):
        """
        Path is a required key in almost all cases. There is a special edge case for LDAP
        [homes] shares. In this case we allow an empty path. Samba interprets this to mean
        that the path should be dynamically set to the user's home directory on the LDAP server.
        Local user auth to SMB shares is prohibited when LDAP is enabled with a samba schema.
        """
        home_result = await self.home_exists(
            data['home'], schema_name, verrors, old)

        if home_result:
            verrors.add(f'{schema_name}.home',
                        'Only one share is allowed to be a home share.')

        bypass = bool(data['cluster_volname'])

        await self.cluster_share_validate(data, schema_name, verrors)

        if data['path']:
            await self.validate_path_field(data, schema_name, verrors, bypass=bypass)
        elif not data['home']:
            verrors.add(f'{schema_name}.path', 'This field is required.')
        else:
            ldap = await self.middleware.call('ldap.config')
            if not ldap['enable'] or not ldap['has_samba_schema']:
                verrors.add(f'{schema_name}.path', 'This field is required.')

        if data['auxsmbconf']:
            try:
                await self.validate_aux_params(data['auxsmbconf'],
                                               f'{schema_name}.auxsmbconf')
            except ValidationErrors as errs:
                verrors.add_child(f'{schema_name}.auxsmbconf', errs)

        if not data['acl'] and not await self.middleware.call('filesystem.acl_is_trivial', data['path']):
            verrors.add(
                f'{schema_name}.acl',
                f'ACL detected on {data["path"]}. ACLs must be stripped prior to creation '
                'of SMB share.'
            )

        if data.get('name') and data['name'].lower() in ['global', 'homes', 'printers']:
            verrors.add(
                f'{schema_name}.name',
                f'{data["name"]} is a reserved section name, please select another one'
            )

        if data.get('path_suffix') and len(data['path_suffix'].split('/')) > 2:
            verrors.add(f'{schema_name}.name',
                        'Path suffix may not contain more than two components.')

    @private
    async def home_exists(self, home, schema_name, verrors, old=None):
        home_filters = [('home', '=', True)]
        home_result = None

        if home:
            if old and old['id'] is not None:
                id = old['id']

                if not old['home']:
                    home_filters.append(('id', '!=', id))
                    # The user already had this set as the home share
                    home_result = await self.middleware.call(
                        'datastore.query', self._config.datastore,
                        home_filters, {'prefix': self._config.datastore_prefix})

        return home_result

    @private
    async def auxsmbconf_dict(self, aux, direction="TO"):
        ret = None
        if direction == 'TO':
            ret = {}
            for entry in aux.splitlines():
                if entry == '':
                    continue

                if entry.startswith(('#', ';')):
                    # Special handling for comments
                    ret[entry] = None
                    continue

                kv = entry.split('=', 1)
                ret[kv[0].strip()] = kv[1].strip()

            return ret

        if direction == 'FROM':
            return '\n'.join([f'{k}={v}' if v is not None else k for k, v in aux.items()])

    @private
    async def name_exists(self, data, schema_name, verrors, id=None):
        name = data['name']
        path = data['path']

        if path and not name:
            name = path.rsplit('/', 1)[-1]

        name_filters = [('name', '=', name)]

        if id is not None:
            name_filters.append(('id', '!=', id))

        name_result = await self.middleware.call(
            'datastore.query', self._config.datastore,
            name_filters,
            {'prefix': self._config.datastore_prefix})

        if name_result:
            verrors.add(f'{schema_name}.name',
                        'A share with this name already exists.')

        return name

    @private
    async def extend(self, data):
        data['hostsallow'] = data['hostsallow'].split()
        data['hostsdeny'] = data['hostsdeny'].split()
        if data['fsrvp']:
            data['shadowcopy'] = True

        if 'share_acl' in data:
            data.pop('share_acl')

        return data

    @private
    async def compress(self, data):
        data['hostsallow'] = ' '.join(data['hostsallow'])
        data['hostsdeny'] = ' '.join(data['hostsdeny'])
        data.pop(self.locked_field, None)

        return data

    @private
    async def generate_vuid(self, timemachine, vuid=""):
        try:
            if timemachine and vuid:
                uuid.UUID(vuid, version=4)
        except ValueError:
            self.logger.debug(f"Time machine VUID string ({vuid}) is invalid. Regenerating.")
            vuid = ""

        if timemachine and not vuid:
            vuid = str(uuid.uuid4())

        return vuid

    @private
    async def apply_presets(self, data):
        """
        Apply settings from presets. Only include auxiliary parameters
        from preset if user-defined aux parameters already exist. In this
        case user-defined takes precedence.
        """
        params = (SMBSharePreset[data["purpose"]].value)["params"].copy()
        aux = params.pop("auxsmbconf")
        data.update(params)
        if data["auxsmbconf"]:
            preset_aux = await self.auxsmbconf_dict(aux, direction="TO")
            data_aux = await self.auxsmbconf_dict(data["auxsmbconf"], direction="TO")
            preset_aux.update(data_aux)
            data["auxsmbconf"] = await self.auxsmbconf_dict(preset_aux, direction="FROM")

        return data

    @accepts()
    async def presets(self):
        """
        Retrieve pre-defined configuration sets for specific use-cases. These parameter
        combinations are often non-obvious, but beneficial in these scenarios.
        """
        return {x.name: x.value for x in SMBSharePreset}

    @private
    @job(lock='sync_smb_registry')
    async def sync_registry(self, job):
        """
        Synchronize registry config with the share configuration in the truenas config
        file. This method simply reconciles lists of shares, removing from and adding to
        the registry as-needed.
        """
        if not os.path.exists(SMBPath.GLOBALCONF.platform()):
            self.logger.warning("smb.conf does not exist. Skipping registry synchronization."
                                "This may indicate that SMB service has not completed initialization.")
            return

        active_shares = await self.query([('locked', '=', False), ('enabled', '=', True)])
        for share in active_shares:
            if share['home']:
                share['name'] = 'homes'

        registry_shares = await self.middleware.call('sharing.smb.reg_listshares')
        cf_active = set([x['name'].casefold() for x in active_shares])
        cf_reg = set([x.casefold() for x in registry_shares])
        to_add = cf_active - cf_reg
        to_del = cf_reg - cf_active

        for share in to_add:
            share_conf = list(filter(lambda x: x['name'].casefold() == share.casefold(), active_shares))
            if not os.path.exists(share_conf[0]['path']):
                self.logger.warning("Path [%s] for share [%s] does not exist. "
                                    "Refusing to add share to SMB configuration.",
                                    share_conf[0]['path'], share_conf[0]['name'])
                continue

            try:
                await self.middleware.call('sharing.smb.reg_addshare', share_conf[0])
            except Exception:
                self.logger.warning("Failed to add SMB share [%s] while synchronizing registry config",
                                    share, exc_info=True)

        for share in to_del:
            await self.middleware.call('sharing.smb.close_share', share)
            try:
                await self.middleware.call('sharing.smb.reg_delshare', share)
            except Exception:
                self.middleware.logger.warning('Failed to remove stale share [%s]',
                                               share, exc_info=True)


async def pool_post_import(middleware, pool):
    """
    Makes sure to reload SMB if a pool is imported and there are shares configured for it.
    """
    if pool is None:
        """
        By the time the post-import hook is called, the smb.configure should have
        already completed and initialized the SMB service.
        """
        asyncio.ensure_future(middleware.call('sharing.smb.sync_registry'))
        return

    path = f'/mnt/{pool["name"]}'
    if await middleware.call('sharing.smb.query', [
        ('OR', [
            ('path', '=', path),
            ('path', '^', f'{path}/'),
        ])
    ]):
        asyncio.ensure_future(middleware.call('sharing.smb.sync_registry'))


class SMBFSAttachmentDelegate(LockableFSAttachmentDelegate):
    name = 'smb'
    title = 'SMB Share'
    service = 'cifs'
    service_class = SharingSMBService

    async def restart_reload_services(self, attachments):
        """
        libsmbconf will handle any required notifications to clients if
        shares are added or deleted.
        mDNS may need to be reloaded if a time machine share is located on
        the share being attached.
        """
        reg_sync = await self.middleware.call('sharing.smb.sync_registry')
        await reg_sync.wait()
        await self.middleware.call('service.reload', 'mdns')

    async def is_child_of_path(self, resource, path):
        return await super().is_child_of_path(resource, path) if resource.get(self.path_field) else False


async def setup(middleware):
    await middleware.call(
        'interface.register_listen_delegate',
        SystemServiceListenMultipleDelegate(middleware, 'smb', 'bindip'),
    )
    await middleware.call('pool.dataset.register_attachment_delegate', SMBFSAttachmentDelegate(middleware))
    middleware.register_hook('pool.post_import', pool_post_import, sync=True)
