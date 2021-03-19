import enum
import errno
import os
import datetime
from middlewared.schema import accepts, Bool, Dict, Int, Patch, Str
from middlewared.service import CallError, CRUDService, job, private, ValidationErrors, filterable
from middlewared.plugins.directoryservices import SSL
import middlewared.sqlalchemy as sa
from middlewared.utils import run, filter_list
from middlewared.validators import Range
from middlewared.plugins.smb import SMBCmd, WBCErr, SMBHAMODE

class DSType(enum.Enum):
    """
    The below DS_TYPES are defined for use as system domains for idmap backends.
    DS_TYPE_NT4 is defined, but has been deprecated. DS_TYPE_DEFAULT_DOMAIN corresponds
    with the idmap settings under services->SMB, and is represented by 'idmap domain = *'
    in the smb4.conf. The only instance where the idmap backend for the default domain will
    not be 'tdb' is when the server is (1) joined to active directory and (2) autorid is enabled.
    """
    DS_TYPE_ACTIVEDIRECTORY = 1
    DS_TYPE_LDAP = 2
    DS_TYPE_NIS = 3
    DS_TYPE_FREEIPA = 4
    DS_TYPE_DEFAULT_DOMAIN = 5


class IDType(enum.Enum):
    USER = "USER"
    GROUP = "GROUP"
    BOTH = "BOTH"


class IdmapBackend(enum.Enum):
    AD = {
        'description': 'The AD backend provides a way for TrueNAS to read id '
                       'mappings from an Active Directory server that uses '
                       'RFC2307/SFU schema extensions. ',
        'parameters': {
            'schema_mode': {"required": False, "default": 'RFC2307'},
            'unix_primary_group': {"required": False, "default": False},
            'unix_nss_info': {"required": False, "default": False},
        },
        'has_secrets': False,
        'services': ['AD'],
    }
    AUTORID = {
        'description': 'Similar to the RID backend, but automatically configures '
                       'the range to be used for each domain, so that there is no '
                       'need to specify a specific range for each domain in the forest '
                       'The only needed configuration is the range of UID/GIDs to use '
                       'for user/group mappings and an optional size for the ranges.',
        'parameters': {
            'rangesize': {"required": False, "default": 100000},
            'readonly': {"required": False, "default": False},
            'ignore_builtin': {"required": False, "default": False},
        },
        'has_secrets': False,
        'services': ['AD'],
    }
    LDAP = {
        'description': 'Stores and retrieves mapping tables in an LDAP directory '
                       'service. Default for LDAP directory service.',
        'parameters': {
            'ldap_base_dn': {"required": True, "default": None},
            'ldap_user_dn': {"required": True, "default": None},
            'ldap_url': {"required": True, "default": None},
            'ldap_user_dn_password': {"required": False, "default": None},
            'ssl': {"required": False, "default": SSL.NOSSL.value},
            'readonly': {"required": False, "default": False},
        },
        'has_secrets': True,
        'services': ['AD', 'LDAP'],
    }
    NSS = {
        'description': 'Provides a simple means of ensuring that the SID for a '
                       'Unix user is reported as the one assigned to the '
                       'corresponding domain user.',
        'parameters': {
            'linked_service': {"required": False, "default": "LOCAL_ACCOUNT"},
        },
        'has_secrets': False,
        'services': ['AD', 'LDAP'],
    }
    RFC2307 = {
        'description': 'Looks up IDs in the Active Directory LDAP server '
                       'or an extenal (non-AD) LDAP server. IDs must be stored '
                       'in RFC2307 ldap schema extensions. Other schema extensions '
                       'such as Services For Unix (SFU20/SFU30) are not supported.',
        'parameters': {
            'ldap_server': {"required": False, "default": "AD"},
            'bind_path_user': {"required": False, "default": None},
            'bind_path_group': {"required": False, "default": None},
            'user_cn': {"required": False, "default": None},
            'cn_realm': {"required": False, "default": None},
            'ldap_domain': {"required": False, "default": None},
            'ldap_url': {"required": False, "default": None},
            'ldap_user_dn': {"required": True, "default": None},
            'ldap_user_dn_password': {"required": False, "default": None},
            'ldap_realm': {"required": False, "default": None},
            'ssl': {"required": False, "default": SSL.NOSSL.value},
        },
        'has_secrets': True,
        'services': ['AD', 'LDAP'],
    }
    RID = {
        'description': 'Default for Active Directory service. requires '
                       'an explicit configuration for each domain, using '
                       'disjoint ranges.',
        'parameters': {
            'sssd_compat': {"required": False, "default": False},
        },
        'has_secrets': False,
        'services': ['AD'],
    }
    TDB = {
        'description': 'Default backend used to store mapping tables for '
                       'BUILTIN and well-known SIDs.',
        'parameters': {
            'readonly': {"required": False, "default": False},
        },
        'services': ['AD'],
    }

    def supported_keys(self):
        return [str(x) for x in self.value['parameters'].keys()]

    def required_keys(self):
        ret = []
        for k, v in self.value['parameters'].items():
            if v['required']:
                ret.append(str(k))
        return ret

    def defaults(self):
        ret = {}
        for k, v in self.value['parameters'].items():
            if v['default'] is not None:
                ret.update({k: v['default']})
        return ret

    def ds_choices():
        directory_services = ['AD', 'LDAP']
        ret = {}
        for ds in directory_services:
            ret[ds] = []

        ds = {'AD': [], 'LDAP': []}
        for x in IdmapBackend:
            for ds in directory_services:
                if ds in x.value['services']:
                    ret[ds].append(x.name)

        return ret

    def stores_secret(self):
        return self.value['has_secrets']


class IdmapDomainModel(sa.Model):
    __tablename__ = 'directoryservice_idmap_domain'

    id = sa.Column(sa.Integer(), primary_key=True)
    idmap_domain_name = sa.Column(sa.String(120))
    idmap_domain_dns_domain_name = sa.Column(sa.String(255), nullable=True)
    idmap_domain_range_low = sa.Column(sa.Integer())
    idmap_domain_range_high = sa.Column(sa.Integer())
    idmap_domain_idmap_backend = sa.Column(sa.String(120), default='rid')
    idmap_domain_options = sa.Column(sa.JSON(type=dict))
    idmap_domain_certificate_id = sa.Column(sa.ForeignKey('system_certificate.id'), index=True, nullable=True)


class IdmapDomainService(CRUDService):

    class Config:
        namespace = 'idmap'
        datastore = 'directoryservice.idmap_domain'
        datastore_prefix = 'idmap_domain_'
        datastore_extend = 'idmap.idmap_extend'
        cli_namespace = 'directory_service.idmap'

    @private
    async def idmap_extend(self, data):
        if data.get('idmap_backend'):
            data['idmap_backend'] = data['idmap_backend'].upper()

        opt_enums = ['ssl', 'linked_service']
        if data.get('options'):
            for i in opt_enums:
                if data['options'].get(i):
                    data['options'][i] = data['options'][i].upper()

        return data

    @private
    async def idmap_compress(self, data):
        opt_enums = ['ssl', 'linked_service']
        if data.get('options'):
            for i in opt_enums:
                if data['options'].get(i):
                    data['options'][i] = data['options'][i].lower()

        data['idmap_backend'] = data['idmap_backend'].lower()

        return data

    @private
    async def get_next_idmap_range(self):
        """
        Increment next high range by 100,000,000 ids. This number has
        to accomodate the highest available rid value for a domain.
        Configured idmap ranges _must_ not overlap.
        """
        domains = await self.query()
        sorted_idmaps = sorted(domains, key=lambda domain: domain['range_high'])
        low_range = sorted_idmaps[-1]['range_high'] + 1
        high_range = sorted_idmaps[-1]['range_high'] + 100000000
        return (low_range, high_range)

    @private
    async def remove_winbind_idmap_tdb(self):
        sysdataset = (await self.middleware.call('systemdataset.config'))['basename']
        ts = str(datetime.datetime.now(datetime.timezone.utc).timestamp())[:10]
        await self.middleware.call('zfs.snapshot.create', {'dataset': f'{sysdataset}/samba4',
                                                           'name': f'wbc-{ts}'})
        try:
            os.remove('/var/db/system/samba4/winbindd_idmap.tdb')

        except FileNotFoundError:
            self.logger.trace("winbindd_idmap.tdb does not exist. Skipping removal.")

        except Exception:
            self.logger.debug("Failed to remove winbindd_idmap.tdb.", exc_info=True)

    @private
    async def domain_info(self, domain):
        ret = {}

        if domain == 'DS_TYPE_ACTIVEDIRECTORY':
            domain = (await self.middleware.call('smb.config'))['workgroup']

        wbinfo = await run(['wbinfo', '-D', domain], check=False)
        if wbinfo.returncode != 0:
            raise CallError(f'Failed to get domain info for {domain}: '
                            f'{wbinfo.stderr.decode().strip()}')

        for entry in wbinfo.stdout.splitlines():
            kv = entry.decode().split(':')
            ret.update({kv[0].strip(): kv[1].strip()})

        return ret

    @private
    async def get_sssd_low_range(self, domain, sssd_config=None, seed=0xdeadbeef):
        """
        This is best effort attempt for SSSD compatibility. It will allocate low
        range for then initial slice in the SSSD environment. The SSSD allocation algorithm
        is non-deterministic. Domain SID string is converted to a 32-bit hashed value
        using murmurhash3 algorithm.

        The modulus of this value with the total number of available slices is used to
        pick the slice. This slice number is then used to calculate the low range for
        RID 0. With the default settings in SSSD this will be deterministic as long as
        the domain has less than 200,000 RIDs.
        """
        sid = (await self.domain_info(domain))['SID']
        sssd_config = {} if not sssd_config else sssd_config
        range_size = sssd_config.get('range_size', 200000)
        range_low = sssd_config.get('range_low', 10001)
        range_max = sssd_config.get('range_max', 2000200000)
        max_slices = int((range_max - range_low) / range_size)

        data = bytearray(sid.encode())
        datalen = len(data)
        hash = seed
        data_bytes = data

        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        r1 = 15
        r2 = 13
        n = 0xe6546b64

        while datalen >= 4:
            k = int.from_bytes(data_bytes[:4], byteorder='little') & 0xFFFFFFFF
            data_bytes = data_bytes[4:]
            datalen = datalen - 4
            k = (k * c1) & 0xFFFFFFFF
            k = (k << r1 | k >> 32 - r1) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            hash ^= k
            hash = (hash << r2 | hash >> 32 - r2) & 0xFFFFFFFF
            hash = (hash * 5 + n) & 0xFFFFFFFF

        if datalen > 0:
            k = 0
            if datalen >= 3:
                k = k | int.from_bytes(data_bytes[2], byteorder='little') << 16
            if datalen >= 2:
                k = k | data_bytes[1] << 8
            if datalen >= 1:
                k = k | data_bytes[0]
                k = (k * c1) & 0xFFFFFFFF
                k = (k << r1 | k >> 32 - r1) & 0xFFFFFFFF
                k = (k * c2) & 0xFFFFFFFF
                hash ^= k

        hash = (hash ^ len(data)) & 0xFFFFFFFF
        hash ^= hash >> 16
        hash = (hash * 0x85ebca6b) & 0xFFFFFFFF
        hash ^= hash >> 13
        hash = (hash * 0xc2b2ae35) & 0xFFFFFFFF
        hash ^= hash >> 16

        return (hash % max_slices) * range_size + range_size

    @accepts()
    @job(lock='clear_idmap_cache')
    async def clear_idmap_cache(self, job):
        """
        Stop samba, remove the winbindd_cache.tdb file, start samba, flush samba's cache.
        This should be performed after finalizing idmap changes.
        """
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == 'CLUSTERED':
            self.logger.warning("clear_idmap_cache is unsafe on clustered smb servers.")
            return

        await self.middleware.call('service.stop', 'cifs')

        try:
            os.remove('/var/db/system/samba4/winbindd_cache.tdb')

        except FileNotFoundError:
            self.logger.debug("Failed to remove winbindd_cache.tdb. File not found.")

        except Exception:
            self.logger.debug("Failed to remove winbindd_cache.tdb.", exc_info=True)

        await self.middleware.call('etc.generate', 'smb')
        await self.middleware.call('service.start', 'cifs')
        gencache_flush = await run(['net', 'cache', 'flush'], check=False)
        if gencache_flush.returncode != 0:
            raise CallError(f'Attempt to flush gencache failed with error: {gencache_flush.stderr.decode().strip()}')

    @private
    async def autodiscover_trusted_domains(self):
        smb = await self.middleware.call('smb.config')

        ad_idmap_backend = (await self.query([('name', '=', 'DS_TYPE_ACTIVEDIRECTORY')], {'get': True}))['idmap_backend']
        if ad_idmap_backend == IdmapBackend.AUTORID.name:
            self.logger.trace('Skipping auto-generation of trusted domains due to AutoRID being enabled.')
            return

        wbinfo = await run(['wbinfo', '-m', '--verbose'], check=False)
        if wbinfo.returncode != 0:
            raise CallError(f'wbinfo -m failed with error: {wbinfo.stderr.decode().strip()}')

        for entry in wbinfo.stdout.decode().splitlines():
            c = entry.split()
            range_low, range_high = await self.get_next_idmap_range()
            if len(c) == 6 and c[0] != smb['workgroup']:
                await self.middleware.call('idmap.create', {
                    'name': c[0],
                    'dns_domain_name': c[1],
                    'range_low': range_low,
                    'range_high': range_high,
                    'idmap_backend': 'RID'
                })

    @accepts()
    async def backend_options(self):
        """
        This returns full information about idmap backend options. Not all
        `options` are valid for every backend.
        """
        return {x.name: x.value for x in IdmapBackend}

    @accepts(
        Str('idmap_backend', enum=[x.name for x in IdmapBackend]),
    )
    async def options_choices(self, backend):
        """
        Returns a list of supported keys for the specified idmap backend.
        """
        return IdmapBackend[backend].supported_keys()

    @accepts()
    async def backend_choices(self):
        """
        Returns array of valid idmap backend choices per directory service.
        """
        return IdmapBackend.ds_choices()

    @private
    async def validate(self, schema_name, data, verrors):
        if data['name'] == DSType.DS_TYPE_LDAP.name:
            if data['idmap_backend'] not in (await self.backend_choices())['LDAP']:
                verrors.add(f'{schema_name}.idmap_backend',
                            f'idmap backend [{data["idmap_backend"]}] is not appropriate '
                            f'for the system domain type {data["name"]}')

        elif data['name'] == DSType.DS_TYPE_DEFAULT_DOMAIN.name:
            if data['idmap_backend'] != 'TDB':
                verrors.add(f'{schema_name}.idmap_backend',
                            'TDB is the only supported idmap backend for DS_TYPE_DEFAULT_DOMAIN.')

        if data['range_high'] < data['range_low']:
            """
            If we don't exit at this point further range() operations will raise an IndexError.
            """
            verrors.add(f'{schema_name}.range_low', 'Idmap high range must be greater than idmap low range')
            return

        if data.get('certificate') and not await self.middleware.call(
            'certificate.query', [['id', '=', data['certificate']]]
        ):
            verrors.add(f'{schema_name}.certificate', 'Please specify a valid certificate.')

        configured_domains = await self.query()
        ldap_enabled = False if await self.middleware.call('ldap.get_state') == 'DISABLED' else True
        ad_enabled = False if await self.middleware.call('activedirectory.get_state') == 'DISABLED' else True
        new_range = range(data['range_low'], data['range_high'])
        idmap_backend = data.get('idmap_backend')
        for i in configured_domains:
            # Do not generate validation error comparing to oneself.
            if i['name'] == data['name']:
                continue

            # Do not generate validation errors for overlapping with a disabled DS.
            if not ldap_enabled and i['name'] == 'DS_TYPE_LDAP':
                continue

            if not ad_enabled and i['name'] == 'DS_TYPE_ACTIVEDIRECTORY':
                continue

            # Idmap settings under Services->SMB are ignored when autorid is enabled.
            if idmap_backend == IdmapBackend.AUTORID.name and i['name'] == 'DS_TYPE_DEFAULT_DOMAIN':
                continue

            # Overlap between ranges defined for 'ad' backend are permitted.
            if idmap_backend == IdmapBackend.AD.name and i['idmap_backend'] == IdmapBackend.AD.name:
                continue

            existing_range = range(i['range_low'], i['range_high'])
            if range(max(existing_range[0], new_range[0]), min(existing_range[-1], new_range[-1]) + 1):
                verrors.add(f'{schema_name}.range_low',
                            'new idmap range conflicts with existing range for domain '
                            f'[{i["name"]}].')

    @private
    async def validate_options(self, schema_name, data, verrors, check=['MISSING', 'EXTRA']):
        supported_keys = set(IdmapBackend[data['idmap_backend']].supported_keys())
        required_keys = set(IdmapBackend[data['idmap_backend']].required_keys())
        provided_keys = set([str(x) for x in data['options'].keys()])

        missing_keys = required_keys - provided_keys
        extra_keys = provided_keys - supported_keys

        if 'MISSING' in check:
            for k in missing_keys:
                verrors.add(f'{schema_name}.options.{k}',
                            f'[{k}] is a required parameter for the [{data["idmap_backend"]}] idmap backend.')

        if 'EXTRA' in check:
            for k in extra_keys:
                verrors.add(f'{schema_name}.options.{k}',
                            f'[{k}] is not a valid parameter for the [{data["idmap_backend"]}] idmap backend.')

    @private
    async def prune_keys(self, data):
        supported_keys = set(IdmapBackend[data['idmap_backend']].supported_keys())
        provided_keys = set([str(x) for x in data['options'].keys()])

        for k in (provided_keys - supported_keys):
            data['options'].pop(k)

    @accepts(
        Dict(
            'idmap_domain_create',
            Str('name', required=True),
            Str('dns_domain_name'),
            Int('range_low', required=True, validators=[Range(min=1000, max=2147483647)]),
            Int('range_high', required=True, validators=[Range(min=1000, max=2147483647)]),
            Str('idmap_backend', enum=[x.name for x in IdmapBackend]),
            Int('certificate', null=True),
            Dict(
                'options',
                Str('schema_mode', enum=['RFC2307', 'SFU', 'SFU20']),
                Bool('unix_primary_group'),
                Bool('unix_nss_info'),
                Int('rangesize', validators=[Range(min=10000, max=1000000000)]),
                Bool('readonly'),
                Bool('ignore_builtin'),
                Str('ldap_base_dn'),
                Str('ldap_user_dn'),
                Str('ldap_user_dn_password', private=True),
                Str('ldap_url'),
                Str('ssl', enum=[x.value for x in SSL]),
                Str('linked_service', enum=['LOCAL_ACCOUNT', 'LDAP', 'NIS']),
                Str('ldap_server'),
                Bool('ldap_realm'),
                Str('bind_path_user'),
                Str('bind_path_group'),
                Bool('user_cn'),
                Str('cn_realm'),
                Str('ldap_domain'),
                Str('ldap_url'),
                Bool('sssd_compat'),
            ),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a new IDMAP domain. These domains must be unique. This table
        will be automatically populated after joining an Active Directory domain
        if "allow trusted domains" is set to True in the AD service configuration.
        There are three default system domains: DS_TYPE_ACTIVEDIRECTORY, DS_TYPE_LDAP, DS_TYPE_DEFAULT_DOMAIN.
        The system domains correspond with the idmap settings under Active Directory, LDAP, and SMB
        respectively.

        `name` the pre-windows 2000 domain name.

        `DNS_domain_name` DNS name of the domain.

        `idmap_backend` provides a plugin interface for Winbind to use varying
        backends to store SID/uid/gid mapping tables. The correct setting
        depends on the environment in which the NAS is deployed.

        `range_low` and `range_high` specify the UID and GID range for which this backend is authoritative.

        `certificate_id` references the certificate ID of the SSL certificate to use for certificate-based
        authentication to a remote LDAP server. This parameter is not supported for all idmap backends as some
        backends will generate SID to ID mappings algorithmically without causing network traffic.

        `options` are additional parameters that are backend-dependent:

        `AD` idmap backend options:
        `unix_primary_group` If True, the primary group membership is fetched from the LDAP attributes (gidNumber).
        If False, the primary group membership is calculated via the "primaryGroupID" LDAP attribute.

        `unix_nss_info` if True winbind will retrieve the login shell and home directory from the LDAP attributes.
        If False or if the AD LDAP entry lacks the SFU attributes the smb4.conf parameters `template shell` and `template homedir` are used.

        `schema_mode` Defines the schema that idmap_ad should use when querying Active Directory regarding user and group information.
        This can be either the RFC2307 schema support included in Windows 2003 R2 or the Service for Unix (SFU) schema.
        For SFU 3.0 or 3.5 please choose "SFU", for SFU 2.0 please choose "SFU20". The behavior of primary group membership is
        controlled by the unix_primary_group option.

        `AUTORID` idmap backend options:
        `readonly` sets the module to read-only mode. No new ranges will be allocated and new mappings
        will not be created in the idmap pool.

        `ignore_builtin` ignores mapping requests for the BUILTIN domain.

        `LDAP` idmap backend options:
        `ldap_base_dn` defines the directory base suffix to use for SID/uid/gid mapping entries.

        `ldap_user_dn` defines the user DN to be used for authentication.

        `ldap_url` specifies the LDAP server to use for SID/uid/gid map entries.

        `ssl` specifies whether to encrypt the LDAP transport for the idmap backend.

        `NSS` idmap backend options:
        `linked_service` specifies the auxiliary directory service ID provider.

        `RFC2307` idmap backend options:
        `domain` specifies the domain for which the idmap backend is being created. Numeric id, short-form
        domain name, or long-form DNS domain name of the domain may be specified. Entry must be entered as
        it appears in `idmap.domain`.

        `range_low` and `range_high` specify the UID and GID range for which this backend is authoritative.

        `ldap_server` defines the type of LDAP server to use. This can either be an LDAP server provided
        by the Active Directory Domain (ad) or a stand-alone LDAP server.

        `bind_path_user` specfies the search base where user objects can be found in the LDAP server.

        `bind_path_group` specifies the search base where group objects can be found in the LDAP server.

        `user_cn` query cn attribute instead of uid attribute for the user name in LDAP.

        `realm` append @realm to cn for groups (and users if user_cn is set) in LDAP queries.

        `ldmap_domain` when using the LDAP server in the Active Directory server, this allows one to
        specify the domain where to access the Active Directory server. This allows using trust relationships
        while keeping all RFC 2307 records in one place. This parameter is optional, the default is to access
        the AD server in the current domain to query LDAP records.

        `ldap_url` when using a stand-alone LDAP server, this parameter specifies the LDAP URL for accessing the LDAP server.

        `ldap_user_dn` defines the user DN to be used for authentication.

        `ldap_user_dn_password` is the password to be used for LDAP authentication.

        `realm` defines the realm to use in the user and group names. This is only required when using cn_realm together with
         a stand-alone ldap server.

        `RID` backend options:
        `sssd_compat` generate idmap low range based on same algorithm that SSSD uses by default.
        """
        await self.middleware.call("smb.cluster_check")
        verrors = ValidationErrors()
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]

        old = await self.query()
        if data['name'] in [x['name'] for x in old]:
            verrors.add('idmap_domain_create.name', 'Domain names must be unique.')

        if data['options'].get('sssd_compat'):
            if await self.middleware.call('activedirectory.get_state') != 'HEALTHY':
                verrors.add('idmap_domain_create.options',
                            'AD service must be enabled and started to '
                            'generate an SSSD-compatible id range')
                verrors.check()

            data['range_low'] = await self.get_sssd_low_range(data['name'])
            data['range_high'] = data['range_low'] + 100000000

        await self.validate('idmap_domain_create', data, verrors)
        await self.validate_options('idmap_domain_create', data, verrors)
        if data.get('certificate_id') and not data['options'].get('ssl'):
            verrors.add('idmap_domain_create.certificate_id',
                        f'The {data["idmap_backend"]} idmap backend does not '
                        'generate LDAP traffic. Certificates do not apply.')
        verrors.check()

        if data['options'].get('ldap_user_dn_password'):
            try:
                DSType[data["name"]]
                domain = (await self.middleware.call("smb.config"))['workgroup']
            except KeyError:
                domain = data["name"]

            secret = data['options'].pop('ldap_user_dn_password')

            await self.middleware.call("directoryservices.set_ldap_secret",
                                       domain, secret)
            await self.middleware.call("directoryservices.backup_secrets")

        final_options = IdmapBackend[data['idmap_backend']].defaults()
        final_options.update(data['options'])
        data['options'] = final_options
        if ha_mode == SMBHAMODE.CLUSTERED:
            return await self.reg_create(old, data)

        data["id"] = await self.middleware.call(
            "datastore.insert", self._config.datastore, data,
            {
                "prefix": self._config.datastore_prefix
            },
        )
        return await self._get_instance(data['id'])

    @accepts(
        Int('id', required=True),
        Patch(
            "idmap_domain_create",
            "idmap_domain_update",
            ("attr", {"update": True})
        )
    )
    async def do_update(self, id, data):
        """
        Update a domain by id.
        """
        await self.middleware.call("smb.cluster_check")
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]

        old = await self.query([('id', '=', id)], {'get': True, 'extra': {'ha_mode': ha_mode.name}})
        new = old.copy()
        if data.get('idmap_backend') and data['idmap_backend'] != old['idmap_backend']:
            """
            Remove options from previous backend because they are almost certainly
            not valid for the new backend.
            """
            new['options'] = {}

        new.update(data)
        tmp = data.copy()
        verrors = ValidationErrors()
        if old['name'] in [x.name for x in DSType] and old['name'] != new['name']:
            verrors.add('idmap_domain_update.name',
                        f'Changing name of default domain {old["name"]} is not permitted')

        if new['options'].get('sssd_compat') and not old['options'].get('sssd_compat'):
            if await self.middleware.call('activedirectory.get_state') != 'HEALTHY':
                verrors.add('idmap_domain_update.options',
                            'AD service must be enabled and started to '
                            'generate an SSSD-compatible id range')
                verrors.check()

            new['range_low'] = await self.get_sssd_low_range(new['name'])
            new['range_high'] = new['range_low'] + 100000000

        if new['idmap_backend'] == 'AUTORID' and new['name'] != 'DS_TYPE_ACTIVEDIRECTORY':
            verrors.add("idmap_domain_update.idmap_backend",
                        "AUTORID is only permitted for the default idmap backend for "
                        "the active directory directory service (DS_TYPE_ACTIVEDIRECTORY).")

        await self.validate('idmap_domain_update', new, verrors)
        await self.validate_options('idmap_domain_update', new, verrors, ['MISSING'])
        tmp['idmap_backend'] = new['idmap_backend']
        if data.get('options'):
            await self.validate_options('idmap_domain_update', tmp, verrors, ['EXTRA'])

        if data.get('certificate_id') and not data['options'].get('ssl'):
            verrors.add('idmap_domain_update.certificate_id',
                        f'The {new["idmap_backend"]} idmap backend does not '
                        'generate LDAP traffic. Certificates do not apply.')
        verrors.check()
        await self.prune_keys(new)
        final_options = IdmapBackend[new['idmap_backend']].defaults()
        final_options.update(new['options'])
        new['options'] = final_options

        if new['options'].get('ldap_user_dn_password'):
            try:
                DSType[new["name"]]
                domain = (await self.middleware.call("smb.config"))['workgroup']
            except KeyError:
                domain = new["name"]

            secret = new['options'].pop('ldap_user_dn_password')
            await self.middleware.call("directoryservices.set_ldap_secret",
                                       domain, secret)
            await self.middleware.call("directoryservices.backup_secrets")

        if ha_mode == SMBHAMODE.CLUSTERED:
            return await self.reg_update(new)

        await self.idmap_compress(new)
        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new,
            {'prefix': self._config.datastore_prefix}
        )
        cache_job = await self.middleware.call('idmap.clear_idmap_cache')
        await cache_job.wait()
        return await self._get_instance(id)

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete a domain by id. Deletion of default system domains is not permitted.
        In case of registry config for clustered server, this will remove all smb4.conf
        entries for the domain associated with the id.
        """
        await self.middleware.call("smb.cluster_check")
        if id <= 5:
            entry = await self._get_instance(id)
            raise CallError(f'Deleting system idmap domain [{entry["name"]}] is not permitted.', errno.EPERM)

        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            return await self.middleware.call("datastore.delete", self._config.datastore, id)

        return await self.reg_delete(id)

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
            result = await self.reg_query(filters, options)

        else:
            result = await super().query(filters, options)

        return result

    @private
    async def name_to_sid(self, name):
        wb = await run([SMBCmd.WBINFO.value, '--name-to-sid', name], check=False)
        if wb.returncode != 0:
            self.logger.debug("wbinfo failed with error: %s",
                              wb.stderr.decode().strip())

        return wb.stdout.decode().strip()

    @private
    async def sid_to_name(self, sid):
        """
        Last two characters of name string encode the account type.
        """
        wb = await run([SMBCmd.WBINFO.value, '--sid-to-name', sid], check=False)
        if wb.returncode != 0:
            self.logger.debug("wbinfo failed with error: %s",
                              wb.stderr.decode().strip())

        return wb.stdout.decode().strip()[:-2]

    @private
    async def sid_to_unixid(self, sid_str):
        rv = None
        gid = None
        uid = None
        wb = await run([SMBCmd.WBINFO.value, '--sid-to-gid', sid_str], check=False)
        if wb.returncode == 0:
            gid = int(wb.stdout.decode().strip())

        wb = await run([SMBCmd.WBINFO.value, '--sid-to-uid', sid_str], check=False)
        if wb.returncode == 0:
            uid = int(wb.stdout.decode().strip())

        if gid and (gid == uid):
            rv = {"id_type": "BOTH", "id": gid}
        elif gid:
            rv = {"id_type": "GROUP", "id": gid}
        elif uid:
            rv = {"id_type": "USER", "id": uid}

        return rv

    @private
    async def unixid_to_sid(self, data):
        """
        Samba generates SIDs for local accounts that lack explicit mapping in
        passdb.tdb or group_mapping.tdb with a prefix of S-1-22-1 (users) and
        S-1-22-2 (groups). This is not returned by wbinfo, but for consistency
        with what appears when viewed over SMB protocol we'll do the same here.
        """
        unixid = data.get("id")
        id = IDType[data.get("id_type", "GROUP")]

        if id == IDType.USER:
            wb = await run([SMBCmd.WBINFO.value, '--uid-to-sid', str(unixid)], check=False)
        else:
            wb = await run([SMBCmd.WBINFO.value, '--gid-to-sid', str(unixid)], check=False)

        if wb.returncode != 0:
            self.logger.warning("Could not convert [%d] to SID: %s",
                                unixid, wb.stderr.decode().strip())
            if WBCErr.DOMAIN_NOT_FOUND.err() in wb.stderr.decode():
                is_local = await self.middleware.call(
                    f'{"user" if id == IDType.USER else "group"}.query',
                    [("uid" if id == IDType.USER else "gid", '=', unixid)],
                    {"count": True}
                )
                if is_local:
                    return f'S-1-22-{1 if id == IDType.USER else 2}-{unixid}'

            return None

        return wb.stdout.decode().strip()

    @private
    async def idmap_from_smbconf(self):
        global_params = await self.middleware.call('smb.reg_globals')
        rv = []
        entries = {}
        next_id = 6
        workgroup = global_params['raw'].get('workgroup')
        security = global_params['raw'].get('security')

        for k, v in global_params['idmap'].items():
            if "*" in k:
                domain = DSType.DS_TYPE_DEFAULT_DOMAIN.name
            else:
                domain = k.strip("idmap config ")
                domain = domain.split(":")[0].strip()
            entry = k.split(":", 1)[1]
            if not entries.get(domain):
                entries[domain] = {}

            entries[domain].update({entry.strip(): v.strip()})

        for k, v in entries.items():
            try:
                range = v.pop('range').split("-")
            except KeyError:
                self.logger.debug("No range specified for domain [%s]\n", k)
                range = [-1, -1]

            entry = {
                "dns_domain_name": None,
                "range_low": int(range[0]),
                "range_high": int(range[1]),
                "idmap_backend": v.pop("backend").upper(),
                "options": v.copy(),
                "certificate": None,
            }
            if k == DSType.DS_TYPE_DEFAULT_DOMAIN.name:
                entry.update({
                    "id": 5,
                    "name": k,
                })
            elif k.casefold() == workgroup and security == "ADS":
                entry.update({
                    "id": 1,
                    "name": DSType.DS_TYPE_ACTIVEDIRECTORY.name,
                })
            else:
                entry.update({
                    "id": next_id,
                    "name": domain,
                })

            rv.append(entry)

        return rv

    @private
    async def idmap_to_smbconf(self, data=None):
        rv = {}
        if data is None:
            idmap = await self.query()
        else:
            idmap = data

        security = await self.middleware.call('smb.getparm', 'security', 'global')
        server_role = await self.middleware.call('smb.getparm', 'server role', 'global')
        workgroup = await self.middleware.call('smb.getparm', 'workgroup', 'global')
        ad_enabled = (security.upper() == 'ADS')
        # In this situation (since we're dealing with idmap backends) we simply check for items set if we have samba_schema
        ldap_enabled = (server_role == 'member server' and security.upper() == 'USER')
        ad_idmap = filter_list(idmap, [('name', '=', DSType.DS_TYPE_ACTIVEDIRECTORY.name)], {'get': True}) if ad_enabled else None

        for i in idmap:
            if i['name'] == DSType.DS_TYPE_DEFAULT_DOMAIN.name:
                if ad_idmap and ad_idmap['idmap_backend'] == 'AUTORID':
                    continue
                domain = "*"
            elif i['name'] == DSType.DS_TYPE_ACTIVEDIRECTORY.name:
                if not ad_enabled:
                    continue
                if i['idmap_backend'] == 'AUTORID':
                    domain = "*"
                else:
                    domain = workgroup
            elif i['name'] == DSType.DS_TYPE_LDAP.name:
                if not ldap_enabled:
                    continue
                domain = workgroup
                # This will need to be re-implemented once LDAP directory service is clustered
                if i['idmap_backend'] == 'LDAP':
                    """
                    In case of default LDAP backend, populate values from ldap form.
                    """
                    idmap_prefix = f"idmap config {domain} :"
                    ldap = await self.middleware.call('ldap.config')
                    rv.update({
                        f"{idmap_prefix} backend": i['idmap_backend'].lower(),
                        f"{idmap_prefix} range": f"{i['range_low']} - {i['range_high']}",
                        f"{idmap_prefix} ldap_base_dn": ldap['basedn'],
                        f"{idmap_prefix} ldap_url": ' '.join(ldap['uri_list']),
                    })
                    continue
            else:
                domain = i['name']

            idmap_prefix = f"idmap config {domain} :"
            rv.update({
                f"{idmap_prefix} backend": i['idmap_backend'].lower(),
                f"{idmap_prefix} range": f"{i['range_low']} - {i['range_high']}"
            })
            for k, v in i['options'].items():
                if v is True:
                    v = "True"
                elif v is False:
                    v = "False"

                rv.update({
                    f"{idmap_prefix} {k}": v,
                })

        return rv

    @private
    async def diff_conf_and_registry(self, data, to_check=None):
        if to_check is None:
            idmaps = await self.idmap_from_smbconf()
        else:
            idmaps = to_check

        r = idmaps
        s_keys = set(data.keys())
        r_keys = set(r.keys())
        intersect = s_keys.intersection(r_keys)
        return {
            'added': {x: data[x] for x in s_keys - r_keys},
            'removed': {x: r[x] for x in r_keys - s_keys},
            'modified': {x: (data[x], r[x]) for x in intersect if data[x] != r[x]},
        }

    @private
    async def synchronize(self):
        ha_mode = await self.middleware.call("smb.get_smb_ha_mode")
        if ha_mode == "CLUSTERED":
            return

        config_idmap = await self.query()
        idmaps = await self.idmap_to_smbconf(config_idmap)
        to_check = (await self.middleware.call('smb.reg_globals'))['idmap']
        diff = await self.diff_conf_and_registry(idmaps, to_check)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)

    @private
    async def ctdb_setup(self):
        """
        A totally uninitialized smb.conf in registry will have no idamp
        range set for the default domain. Use this as test to determine
        whether to set default autorid range. Autorid is generally more
        efficient in ctdb.
        """
        existing_idmap = (await self.middleware.call('smb.reg_globals'))['idmap']
        if existing_idmap.get('idmap config * : range'):
            return

        diff = {"added": {
            "idmap config * : backend": "autorid",
            "idmap config * : range": "90000001 - 100000000"
        }}
        await self.middleware.call('smb.reg_apply_conf_diff', diff)

    @private
    async def reg_query(self, filters, options):
        reg_idmap = await self.middleware.call('idmap.idmap_from_smbconf')
        result = filter_list(reg_idmap, filters, options)
        return result

    @private
    async def reg_create(self, old, data):
        orig = old.copy()
        orig.append(data)
        smbconf = await self.idmap_to_smbconf(orig)
        smbconfold = await self.idmap_to_smbconf(old)
        diff = await self.diff_conf_and_registry(smbconf, smbconfold)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)
        return await self.query([("id", "=", data['id'])], {'get': True, 'extra': {'ha_mode': 'CLUSTERED'}})

    @private
    async def reg_update(self, data):
        orig = await self.query([("id", "!=", data['id'])], {'extra': {'ha_mode': 'CLUSTERED'}})
        orig.append(data)
        smbconf = await self.idmap_to_smbconf(orig)
        diff = await self.diff_conf_and_registry(smbconf)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)
        return await self.query([("id", "=", data['id'])], {'get': True, 'extra': {'ha_mode': 'CLUSTERED'}})

    @private
    async def reg_delete(self, id):
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        remaining = await self.query([('id', '!=', id)], {'extra': {'ha_mode': ha_mode.name}})
        smbconf = await self.idmap_to_smbconf(remaining)
        diff = await self.diff_conf_and_registry(smbconf)
        await self.middleware.call('smb.reg_apply_conf_diff', {'removed': diff['removed']})
