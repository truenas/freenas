import asyncio
import base64
import datetime
import enum
import io
import os
import shutil
import subprocess
import time
from middlewared.plugins.idmap import DSType
from middlewared.schema import accepts, Dict, Int, List, Patch, Str
from middlewared.service import CallError, ConfigService, CRUDService, job, periodic, private, ValidationErrors
import middlewared.sqlalchemy as sa
from middlewared.utils import run, Popen
import middlewared.utils.osc as osc


class keytab(enum.Enum):
    SYSTEM = '/etc/krb5.keytab'
    SAMBA = '/var/db/system/samba4/private/samba.keytab'
    TEST = '/var/db/system/test.keytab'


class KRB5(enum.Enum):
    MIT = 1
    HEIMDAL = 2

    def platform():
        return KRB5.MIT if osc.IS_LINUX else KRB5.HEIMDAL


class KRB_AppDefaults(enum.Enum):
    FORWARDABLE = ('forwardable', 'boolean')
    PROXIABLE = ('proxiable', 'boolean')
    NO_ADDRESSES = ('no-addresses', 'boolean')
    TICKET_LIFETIME = ('ticket_lifetime', 'time')
    RENEW_LIFETIME = ('renew_lifetime', 'time')
    ENCRYPT = ('encrypt', 'boolean')
    FORWARD = ('forward', 'boolean')

    def __str__(self):
        return self.value[0]

    def parm(self):
        return self.value[0]


class KRB_LibDefaults(enum.Enum):
    DEFAULT_REALM = ('default_realm', 'realm')
    ALLOW_WEAK_CRYPTO = ('allow_weak_crypto', 'boolean')
    CLOCKSKEW = ('clockskew', 'time')
    KDC_TIMEOUT = ('kdc_timeout', 'time')
    DEFAULT_CC_TYPE = ('default_cc_type', 'cctype')
    DEFAULT_CC_NAME = ('default_cc_name', 'ccname')
    DEFAULT_ETYPES = ('default_etypes', 'etypes')
    DEFAULT_AS_ETYPES = ('default_as_etypes', 'etypes')
    DEFAULT_TGS_ETYPES = ('default_tgs_etypes', 'etypes')
    DEFAULT_ETYPES_DES = ('default_etypes_des', 'etypes')
    DEFAULT_KEYTAB_NAME = ('default_keytab_name', 'keytab')
    DNS_LOOKUP_KDC = ('dns_lookup_kdc', 'boolean')
    DNS_LOOKUP_REALM = ('dns_lookup_realm', 'boolean')
    KDC_TIMESYNC = ('kdc_timesync', 'boolean')
    MAX_RETRIES = ('max_retries', 'number')
    LARGE_MSG_SIZE = ('large_msg_size', 'number')
    TICKET_LIFETIME = ('ticket_lifetime', 'time')
    RENEW_LIFETIME = ('renew_lifetime', 'time')
    FORWARDABLE = ('forwardable', 'boolean')
    PROXIABLE = ('proxiable', 'boolean')
    VERIFY_AP_REQ_NOFAIL = ('verify_ap_req_nofail', 'boolean')
    WARN_PWEXPIRE = ('warn_pwexpire', 'time')
    HTTP_PROXY = ('http_proxy', 'proxy-spec')
    DNS_PROXY = ('dns_proxy', 'proxy-spec')
    EXTRA_ADDRESSES = ('extra_addresses', 'address')
    TIME_FORMAT = ('time_format', 'string')
    DATE_FORMAT = ('date_format', 'string')
    LOG_UTC = ('log_utc', 'boolean')
    SCAN_INTERFACES = ('scan_interfaces', 'boolean')
    FCACHE_VERSION = ('fcache_version', 'int')
    KRB4_GET_TICKETS = ('krb4_get_tickets', 'boolean')
    FCC_MIT_TICKETFLAGS = ('fcc-mit-ticketflags', 'boolean')

    def __str__(self):
        return self.value[0]

    def parm(self):
        return self.value[0]


class KRB_ETYPE(enum.Enum):
    DES_CBC_CRC = 'des-cbc-crc'
    DES_CBC_MD4 = 'des-cbc-md4'
    DES_CBC_MD5 = 'des-cbc-md5'
    DES3_CBC_SHA1 = 'des3-cbc-sha1'
    ARCFOUR_HMAC_MD5 = 'arcfour-hmac-md5'
    AES128_CTS_HMAC_SHA1_96 = 'aes128-cts-hmac-sha1-96'
    AES256_CTS_HMAC_SHA1_96 = 'aes256-cts-hmac-sha1-96'


class KerberosModel(sa.Model):
    __tablename__ = 'directoryservice_kerberossettings'

    id = sa.Column(sa.Integer(), primary_key=True)
    ks_appdefaults_aux = sa.Column(sa.Text())
    ks_libdefaults_aux = sa.Column(sa.Text())


class KerberosService(ConfigService):
    class Config:
        service = "kerberos"
        datastore = 'directoryservice.kerberossettings'
        datastore_prefix = "ks_"
        cli_namespace = "directory_service.kerberos.settings"

    @accepts(Dict(
        'kerberos_settings_update',
        Str('appdefaults_aux', max_length=None),
        Str('libdefaults_aux', max_length=None),
        update=True
    ))
    async def do_update(self, data):
        """
        `appdefaults_aux` add parameters to "appdefaults" section of the krb5.conf file.

        `libdefaults_aux` add parameters to "libdefaults" section of the krb5.conf file.
        """
        verrors = ValidationErrors()

        old = await self.config()
        new = old.copy()
        new.update(data)
        verrors.add_child(
            'kerberos_settings_update',
            await self._validate_appdefaults(new['appdefaults_aux'])
        )
        verrors.add_child(
            'kerberos_settings_update',
            await self._validate_libdefaults(new['libdefaults_aux'])
        )
        if verrors:
            raise verrors

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            old['id'],
            new,
            {'prefix': 'ks_'}
        )

        await self.middleware.call('etc.generate', 'kerberos')
        return await self.config()

    @private
    async def _klist_test(self):
        """
        Returns false if there is not a TGT or if the TGT has expired.
        """
        if KRB5.platform() == KRB5.MIT:
            klist = await run(['klist', '-s'], check=False)
        else:
            klist = await run(['klist', '-t'], check=False)

        if klist.returncode != 0:
            return False
        return True

    @private
    async def _validate_param_type(self, data):
        supported_validation_types = [
            'boolean',
            'cctype',
            'etypes',
            'keytab',
        ]
        if data['ptype'] not in supported_validation_types:
            return

        if data['ptype'] == 'boolean':
            if data['value'].upper() not in ['YES', 'TRUE', 'NO', 'FALSE']:
                raise CallError(f'[{data["value"]}] is not boolean')

        if data['ptype'] == 'etypes':
            for e in data['value'].split(' '):
                try:
                    KRB_ETYPE(e)
                except Exception:
                    raise CallError(f'[{e}] is not a supported encryption type')

        if data['ptype'] == 'cctype':
            available_types = ['FILE', 'MEMORY']
            if osc.IS_FREEBSD:
                available_types.append('SCC')
            else:
                available_types.append('DIR')

            if data['value'] not in available_types:
                raise CallError(f'[{data["value"]}] is an unsupported cctype. '
                                f'Available types are {", ".join(available_types)}. '
                                'This parameter is case-sensitive')

        if data['ptype'] == 'keytab':
            try:
                keytab(data['value'])
            except Exception:
                raise CallError(f'{data["value"]} is an unsupported keytab path')

    @private
    async def _validate_appdefaults(self, appdefaults):
        verrors = ValidationErrors()
        for line in appdefaults.splitlines():
            param = line.split('=')
            if len(param) == 2 and (param[1].strip())[0] != '{':
                validated_param = list(filter(
                    lambda x: param[0].strip() in (x.value)[0], KRB_AppDefaults
                ))

                if not validated_param:
                    verrors.add(
                        'kerberos_appdefaults',
                        f'{param[0]} is an invalid appdefaults parameter.'
                    )
                    continue

                try:
                    await self._validate_param_type({
                        'ptype': (validated_param[0]).value[1],
                        'value': param[1].strip()
                    })
                except Exception as e:
                    verrors.add(
                        'kerberos_appdefaults',
                        f'{param[0]} has invalid value: {e.errmsg}.'
                    )
                    continue

        return verrors

    @private
    async def _validate_libdefaults(self, libdefaults):
        verrors = ValidationErrors()
        for line in libdefaults.splitlines():
            param = line.split('=')
            if len(param) == 2:
                validated_param = list(filter(
                    lambda x: param[0].strip() in (x.value)[0], KRB_LibDefaults
                ))

                if not validated_param:
                    verrors.add(
                        'kerberos_libdefaults',
                        f'{param[0]} is an invalid libdefaults parameter.'
                    )
                    continue

                try:
                    await self._validate_param_type({
                        'ptype': (validated_param[0]).value[1],
                        'value': param[1].strip()
                    })
                except Exception as e:
                    verrors.add(
                        'kerberos_libdefaults',
                        f'{param[0]} has invalid value: {e.errmsg}.'
                    )

            else:
                verrors.add('kerberos_libdefaults', f'{line} is an invalid libdefaults parameter.')

        return verrors

    @private
    async def do_kinit(self, data):
        dstype = DSType(data['dstype'])
        krb5 = KRB5.platform()
        if data['kerberos_principal']:
            if krb5 == KRB5.MIT:
                kinit = await run(['kinit', '-r', '7d', '-k', data['kerberos_principal']], check=False)
            else:
                kinit = await run(['kinit', '--renewable', '-k', data['kerberos_principal']], check=False)

            if kinit.returncode != 0:
                if dstype == DSType.DS_TYPE_ACTIVEDIRECTORY:
                    raise CallError(f"kinit for domain [{data['domainname']}] "
                                    f"with principal [{data['kerberos_principal']}] "
                                    f"failed: {kinit.stderr.decode()}")

                elif dstype == DSType.LDAP:
                    raise CallError(f"kinit with principal [{data['kerberos_principal']}] "
                                    f"failed: {kinit.stderr.decode()}")
            return True

        if dstype == DSType.DS_TYPE_ACTIVEDIRECTORY:
                principal = f'{data["bindname"]}@{data["domainname"].upper()}'

        elif dstype == DSType.LDAP:
                krb_realm = await self.middleware.call(
                    'kerberos.realm.query',
                    [('id', '=', data['kerberos_realm'])],
                    {'get': True}
                )
                bind_cn = (data['binddn'].split(','))[0].split("=")
                principal = f'{bind_cn[1]}@{krb_realm["realm"]}'

        if krb5 == KRB5.MIT:
            kinit = await Popen(
                ['kinit', '-r', '7d', principal],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
            )
        else:
            kinit = await Popen(
                ['kinit', '--renewable', '--password-file=STDIN', principal],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
            )

        output = await kinit.communicate(input=data['bindpw'].encode())
        if kinit.returncode != 0:
            raise CallError(f"kinit with password failed: {output[1].decode()}")

        return True

    @private
    async def _kinit(self):
        """
        For now we only check for kerberos realms explicitly configured in AD and LDAP.
        """
        data = {}
        ad = await self.middleware.call('activedirectory.config')
        ldap = await self.middleware.call('ldap.config')
        await self.middleware.call('etc.generate', 'kerberos')
        if ad['enable']:
            ad['dstype'] = DSType.DS_TYPE_ACTIVEDIRECTORY.value
            await self.do_kinit(ad)

        if ldap['enable'] and ldap['kerberos_realm']:
            ldap['dstype'] = DSType.DS_TYPE_LDAP.value
            await self.do_kinit(ldap)

    @private
    async def parse_klist(self, data):
        ad_TGT = []
        ldap_TGT = []

        ad = data.get("ad")
        ldap = data.get("ldap")
        klistin = data.get("klistin")
        krb5 = KRB5(data.get("krb5type"))

        if ldap.get('enable') and ldap['kerberos_realm']:
            ldap_realm = await self.middleware.call('kerberos.realm.query',
                                                    [('id', '=', ldap['kerberos_realm'])],
                                                    {'get': True})

        if krb5 == KRB5.MIT:
            tickets = klistin.splitlines()
            default_principal = None
            tlen = len(tickets)

            if ad['enable']:
                dstype = DSType.DS_TYPE_ACTIVEDIRECTORY
            elif ldap['enable']:
                dstype = DSType.DS_TYPE_LDAP
            else:
                return {"ad_TGT": [], "ldap_TGT": []}

            parsed_klist = []
            for idx, e in enumerate(tickets):
                if e.startswith('Default'):
                    default_principal = (e.split(':')[1]).strip()
                if e and e[0].isdigit():
                    d = e.split("  ")
                    issued = time.strptime(d[0], "%m/%d/%y %H:%M:%S")
                    expires = time.strptime(d[1], "%m/%d/%y %H:%M:%S")
                    client = default_principal
                    server = d[2]
                    flags = None
                    etype = None
                    next_two = [idx+1, idx+2]
                    for i in next_two:
                        if i >= tlen:
                            break
                        if tickets[i][0].isdigit():
                            break
                        if tickets[i].startswith("\tEtype"):
                            etype = tickets[i].strip()
                            break
                        if tickets[i].startswith("\trenew"):
                            flags = tickets[i].split("Flags: ")[1]
                            continue

                        extra = tickets[i].split(", ", 1)
                        flags = extra[0].strip()
                        etype = extra[1].strip()

                    parsed_klist.append({
                        'issued': issued,
                        'expires': expires,
                        'client': client,
                        'server': server,
                        'etype': etype,
                        'flags': flags,
                    })

            return {
                "ad_TGT": parsed_klist if dstype == DSType.DS_TYPE_ACTIVEDIRECTORY else [],
                "ldap_TGT": parsed_klist if dstype == DSType.DS_TYPE_LDAP else [],
            }

        tkts = klistin.split('\n\n')
        for tkt in tkts:
            s = tkt.splitlines()
            if len(s) > 4:
                for entry in s:
                    if "Auth time" in entry:
                        issued = time.strptime((entry.split('Auth time: '))[1].lstrip().replace('  ', ' '), '%b %d %H:%M:%S %Y')
                    elif "End time" in entry:
                        expires = time.strptime((entry.split('End time: '))[1].lstrip().replace('  ', ' '), '%b %d %H:%M:%S %Y')
                    elif "Server" in entry:
                        server = (entry.split('Server: '))[1]
                    elif "Client" in entry:
                        client = (entry.split('Client: '))[1]
                    elif 'Ticket etype' in entry:
                        etype = (entry.split('Ticket etype: '))[1]
                    elif 'Ticket flags' in entry:
                        flags = (entry.split('Ticket flags: '))[1].split(',')

                if ad['enable'] and ad['kerberos_realm'] and ad['domainname'] in client:
                    ad_TGT.append({
                        'issued': issued,
                        'expires': expires,
                        'client': client,
                        'server': server,
                        'etype': etype,
                        'flags': flags,
                    })

                elif ldap['enable'] and ldap['kerberos_realm']:
                    if ldap_realm['realm'] in client:
                        ldap_TGT.append({
                            'issued': issued,
                            'expires': expires,
                            'client': client,
                            'server': server,
                            'etype': etype,
                            'flags': flags,
                        })

        return {"ad_TGT": ad_TGT, "ldap_TGT": ldap_TGT}

    @private
    async def _get_cached_klist(self):
        """
        Try to get retrieve cached kerberos tgt info. If it hasn't been cached,
        perform klist, parse it, put it in cache, then return it.
        """
        if await self.middleware.call('cache.has_key', 'KRB_TGT_INFO'):
            return (await self.middleware.call('cache.get', 'KRB_TGT_INFO'))
        ad = await self.middleware.call('activedirectory.config')
        ldap = await self.middleware.call('ldap.config')
        ad_TGT = []
        ldap_TGT = []
        parsed_klist = {}
        if not ad['enable'] and not ldap['enable']:
            return {'ad_TGT': ad_TGT, 'ldap_TGT': ldap_TGT}
        if not ad['enable'] and not ldap['kerberos_realm']:
            return {'ad_TGT': ad_TGT, 'ldap_TGT': ldap_TGT}

        if not await self.status():
            await self.start()
        krb5 = KRB5.platform()
        try:
            if krb5 == KRB5.HEIMDAL:
                klist = await asyncio.wait_for(
                    run(['klist', '-v'], check=False, stdout=subprocess.PIPE),
                    timeout=10.0
                )
            else:
                klist = await asyncio.wait_for(
                    run(['klist', '-ef'], check=False, stdout=subprocess.PIPE),
                    timeout=10.0
                )
        except Exception as e:
            await self.stop()
            raise CallError("Attempt to list kerberos tickets failed with error: %s", e)

        if klist.returncode != 0:
            await self.stop()
            raise CallError(f'klist failed with error: {klist.stderr.decode()}')

        klist_output = klist.stdout.decode()

        parsed_klist = await self.parse_klist({
            "krb5type": krb5.value,
            "klistin": klist_output,
            "ad": ad,
            "ldap": ldap,
        })

        if parsed_klist['ad_TGT'] or parsed_klist['ldap_TGT']:
            await self.middleware.call('cache.put', 'KRB_TGT_INFO', parsed_klist)

        return parsed_klist

    @private
    async def renew(self):
        """
        Compare timestamp of cached TGT info with current timestamp. If we're within 5 minutes
        of expire time, renew the TGT via 'kinit -R'.
        """
        tgt_info = await self._get_cached_klist()
        ret = True

        must_renew = False
        must_reinit = False
        if not tgt_info['ad_TGT'] and not tgt_info['ldap_TGT']:
            must_reinit = True

        if tgt_info['ad_TGT']:
            permitted_buffer = datetime.timedelta(minutes=5)
            current_time = datetime.datetime.now()
            for entry in tgt_info['ad_TGT']:
                tgt_expiry_time = datetime.datetime.fromtimestamp(time.mktime(entry['expires']))
                delta = tgt_expiry_time - current_time
                if datetime.timedelta(minutes=0) > delta:
                    must_reinit = True
                    break
                if permitted_buffer > delta:
                    must_renew = True
                    break

        if tgt_info['ldap_TGT']:
            permitted_buffer = datetime.timedelta(minutes=5)
            current_time = datetime.datetime.now()
            for entry in tgt_info['ldap_TGT']:
                tgt_expiry_time = datetime.datetime.fromtimestamp(time.mktime(entry['expires']))
                delta = tgt_expiry_time - current_time
                if datetime.timedelta(minutes=0) > delta:
                    must_reinit = True
                    break
                if permitted_buffer > delta:
                    must_renew = True
                    break

        if must_renew and not must_reinit:
            try:
                kinit = await asyncio.wait_for(run(['kinit', '-R'], check=False), timeout=15)
                if kinit.returncode != 0:
                    raise CallError(f'kinit -R failed with error: {kinit.stderr.decode()}')
                self.logger.debug(f'Successfully renewed kerberos TGT')
                await self.middleware.call('cache.pop', 'KRB_TGT_INFO')
            except asyncio.TimeoutError:
                self.logger.debug('Attempt to renew kerberos TGT failed after 15 seconds.')

        if must_reinit:
            ret = await self.start()
            await self.middleware.call('cache.pop', 'KRB_TGT_INFO')

        return ret

    @private
    async def status(self):
        """
        Experience in production environments has indicated that klist can hang
        indefinitely. Fail if we hang for more than 10 seconds. This should force
        a kdestroy and new attempt to kinit (depending on why we are checking status).
        _klist_test will return false if there is not a TGT or if the TGT has expired.
        """
        try:
            ret = await asyncio.wait_for(self._klist_test(), timeout=10.0)
            return ret
        except asyncio.TimeoutError:
            self.logger.debug('kerberos ticket status check timed out after 10 seconds.')
            return False

    @private
    async def stop(self):
        await self.middleware.call('cache.pop', 'KRB_TGT_INFO')
        kdestroy = await run(['kdestroy'], check=False)
        if kdestroy.returncode != 0:
            raise CallError(f'kdestroy failed with error: {kdestroy.stderr.decode()}')

        return True

    @private
    async def start(self, realm=None, kinit_timeout=30):
        """
        kinit can hang because it depends on DNS. If it has not returned within
        30 seconds, it is safe to say that it has failed.
        """
        await self.middleware.call('etc.generate', 'kerberos')
        try:
            await asyncio.wait_for(self._kinit(), timeout=kinit_timeout)
        except asyncio.TimeoutError:
            raise CallError(f'Timed out hung kinit after [{kinit_timeout}] seconds')


class KerberosRealmModel(sa.Model):
    __tablename__ = 'directoryservice_kerberosrealm'

    id = sa.Column(sa.Integer(), primary_key=True)
    krb_realm = sa.Column(sa.String(120))
    krb_kdc = sa.Column(sa.String(120))
    krb_admin_server = sa.Column(sa.String(120))
    krb_kpasswd_server = sa.Column(sa.String(120))

    __table_args__ = (
        sa.Index("directoryservice_kerberosrealm_krb_realm", "krb_realm", unique=True),
    )


class KerberosRealmService(CRUDService):
    class Config:
        datastore = 'directoryservice.kerberosrealm'
        datastore_prefix = 'krb_'
        datastore_extend = 'kerberos.realm.kerberos_extend'
        namespace = 'kerberos.realm'
        cli_namespace = 'directory_service.kerberos.realm'

    @private
    async def kerberos_extend(self, data):
        for param in ['kdc', 'admin_server', 'kpasswd_server']:
            data[param] = data[param].split(' ') if data[param] else []

        return data

    @private
    async def kerberos_compress(self, data):
        for param in ['kdc', 'admin_server', 'kpasswd_server']:
            data[param] = ' '.join(data[param])

        return data

    @accepts(
        Dict(
            'kerberos_realm_create',
            Str('realm', required=True),
            List('kdc'),
            List('admin_server'),
            List('kpasswd_server'),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a new kerberos realm. This will be automatically populated during the
        domain join process in an Active Directory environment. Kerberos realm names
        are case-sensitive, but convention is to only use upper-case.

        Entries for kdc, admin_server, and kpasswd_server are not required.
        If they are unpopulated, then kerberos will use DNS srv records to
        discover the correct servers. The option to hard-code them is provided
        due to AD site discovery. Kerberos has no concept of Active Directory
        sites. This means that middleware performs the site discovery and
        sets the kerberos configuration based on the AD site.
        """
        verrors = ValidationErrors()

        verrors.add_child('kerberos_realm_create', await self._validate(data))

        if verrors:
            raise verrors

        data = await self.kerberos_compress(data)
        data["id"] = await self.middleware.call(
            "datastore.insert", self._config.datastore, data,
            {
                "prefix": self._config.datastore_prefix
            },
        )
        await self.middleware.call('etc.generate', 'kerberos')
        await self.middleware.call('service.restart', 'cron')
        return await self._get_instance(data['id'])

    @accepts(
        Int('id', required=True),
        Patch(
            "kerberos_realm_create",
            "kerberos_realm_update",
            ("attr", {"update": True})
        )
    )
    async def do_update(self, id, data):
        """
        Update a kerberos realm by id. This will be automatically populated during the
        domain join process in an Active Directory environment. Kerberos realm names
        are case-sensitive, but convention is to only use upper-case.
        """
        old = await self._get_instance(id)
        new = old.copy()
        new.update(data)

        data = await self.kerberos_compress(new)
        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new,
            {'prefix': self._config.datastore_prefix}
        )

        await self.middleware.call('etc.generate', 'kerberos')
        return await self._get_instance(id)

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete a kerberos realm by ID.
        """
        await self.middleware.call("datastore.delete", self._config.datastore, id)
        await self.middleware.call('etc.generate', 'kerberos')

    @private
    async def _validate(self, data):
        verrors = ValidationErrors()
        realms = await self.query()
        for realm in realms:
            if realm['realm'].upper() == data['realm'].upper():
                verrors.add(f'kerberos_realm', f'kerberos realm with name {realm["realm"]} already exists.')
        return verrors


class KerberosKeytabModel(sa.Model):
    __tablename__ = 'directoryservice_kerberoskeytab'

    id = sa.Column(sa.Integer(), primary_key=True)
    keytab_file = sa.Column(sa.EncryptedText())
    keytab_name = sa.Column(sa.String(120))


class KerberosKeytabService(CRUDService):
    class Config:
        datastore = 'directoryservice.kerberoskeytab'
        datastore_prefix = 'keytab_'
        namespace = 'kerberos.keytab'
        cli_namespace = 'directory_service.kerberos.keytab'

    @accepts(
        Dict(
            'kerberos_keytab_create',
            Str('file', max_length=None),
            Str('name'),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a kerberos keytab. Uploaded keytab files will be merged with the system
        keytab under /etc/krb5.keytab.

        `file` b64encoded kerberos keytab
        `name` name for kerberos keytab
        """
        verrors = ValidationErrors()

        verrors.add_child('kerberos_principal_create', await self._validate(data))

        if verrors:
            raise verrors

        data["id"] = await self.middleware.call(
            "datastore.insert", self._config.datastore, data,
            {
                "prefix": self._config.datastore_prefix
            },
        )
        await self.middleware.call('etc.generate', 'kerberos')

        return await self._get_instance(data['id'])

    @accepts(
        Int('id', required=True),
        Dict(
            'kerberos_keytab_update',
            Str('file'),
            Str('name'),
            register=True
        )
    )
    async def do_update(self, id, data):
        """
        Update kerberos keytab by id.
        """
        old = await self._get_instance(id)
        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        verrors.add_child('kerberos_principal_update', await self._validate(new))

        if verrors:
            raise verrors

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new,
            {'prefix': self._config.datastore_prefix}
        )
        await self.middleware.call('etc.generate', 'kerberos')

        return await self._get_instance(id)

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete kerberos keytab by id, and force regeneration of
        system keytab.
        """
        await self.middleware.call("datastore.delete", self._config.datastore, id)
        if os.path.exists(keytab['SYSTEM'].value):
            os.remove(keytab['SYSTEM'].value)
        await self.middleware.call('etc.generate', 'kerberos')
        await self._cleanup_kerberos_principals()
        await self.middleware.call('kerberos.stop')
        try:
            await self.middleware.call('kerberos.start')
        except Exception as e:
            self.logger.debug(
                'Failed to start kerberos service after deleting keytab entry: %s' % e
            )

    @accepts(Dict(
        'keytab_data',
        Str('name', required=True),
    ))
    @job(lock='upload_keytab', pipes=['input'], check_pipes=True)
    async def upload_keytab(self, job, data):
        """
        Upload a keytab file. This method expects the keytab file to be uploaded using
        the /_upload/ endpoint.
        """
        ktmem = io.BytesIO()
        await self.middleware.run_in_thread(shutil.copyfileobj, job.pipes.input.r, ktmem)
        b64kt = base64.b64encode(ktmem.getvalue())
        return await self.middleware.call('kerberos.keytab.create',
                                          {'name': data['name'], 'file': b64kt.decode()})

    @private
    async def legacy_validate(self, keytab):
        err = await self._validate({'file': keytab})
        try:
            err.check()
        except Exception as e:
            raise CallError(e)

    @private
    async def _cleanup_kerberos_principals(self):
        principal_choices = await self.middleware.call('kerberos.keytab.kerberos_principal_choices')
        ad = await self.middleware.call('activedirectory.config')
        ldap = await self.middleware.call('ldap.config')
        if ad['kerberos_principal'] and ad['kerberos_principal'] not in principal_choices:
            await self.middleware.call(
                'datastore.update',
                'directoryservice.activedirectory',
                ad['id'],
                {'kerberos_principal': ''},
                {'prefix': 'ad_'}
            )
        if ldap['kerberos_principal'] and ldap['kerberos_principal'] not in principal_choices:
            await self.middleware.call(
                'datastore.update',
                'directoryservice.ldap',
                ldap['id'],
                {'kerberos_principal': ''},
                {'prefix': 'ldap_'}
            )

    @private
    async def do_ktutil_list(self, data):
        kt = data.get("kt_name", keytab.SYSTEM.value)
        if KRB5.platform() == KRB5.MIT:
            ktutil = await run(["klist", "-tek"], check=False)
            if ktutil.returncode != 0:
                raise CallError(ktutil.stderr.decode())
            ret = ktutil.stdout.decode().splitlines()
            if len(ret) < 4:
                return []
            ret = '\n'.join(ret[3:])
        else:
            ktutil = await run(["ktutil", "-k", kt, "-v", "list"], check=False)
            if ktutil.returncode != 0:
                raise CallError(ktutil.stderr.decode())
            ret = ktutil.stdout.decode()

        return ret

    @private
    async def _validate(self, data):
        """
        For now validation is limited to checking if we can resolve the hostnames
        configured for the kdc, admin_server, and kpasswd_server can be resolved
        by DNS, and if the realm can be resolved by DNS.
        """
        verrors = ValidationErrors()
        try:
            decoded = base64.b64decode(data['file'])
        except Exception as e:
            verrors.add("kerberos.keytab_create", f"Keytab is a not a properly base64-encoded string: [{e}]")
            return verrors

        with open(keytab['TEST'].value, "wb") as f:
            f.write(decoded)

        try:
            await self.do_ktutil_list({"kt_name": keytab['TEST'].value})
        except CallError as e:
            verrors.add("kerberos.keytab_create", f"Failed to validate keytab: [{e.errmsg}]")

        os.unlink(keytab['TEST'].value)

        return verrors

    @private
    async def _ktutil_list(self, keytab_file=keytab['SYSTEM'].value):
        keytab_entries = []
        try:
            kt_list_output = await self.do_ktutil_list({"kt_name": keytab_file})
        except Exception as e:
            self.logger.warning("Failed to list kerberos keytab [%s]: %s",
                                keytab_file, e)
            kt_list_output = None

        if not kt_list_output:
            return keytab_entries

        if KRB5.platform() == KRB5.HEIMDAL:
            for line in kt_list_output.splitlines():
                fields = line.split()
                if len(fields) >= 4 and fields[0] != 'Vno':
                    if fields[1] == 'unknown':
                        self.logger.warning('excluding unknown encryption type %s from keytab choices', fields[2])
                        continue

                    keytab_entries.append({
                        'kvno': fields[0],
                        'type': fields[1],
                        'principal': fields[2],
                        'date': time.strptime(fields[3], '%Y-%m-%d'),
                        'aliases': fields[4].split() if len(fields) == 5 else []
                    })
        else:
            for idx, line in enumerate(kt_list_output.splitlines()):
                fields = line.split()
                keytab_entries.append({
                    'slot': idx+1,
                    'kvno': fields[0],
                    'principal': fields[3],
                    'etype': fields[4][1:-1].strip('DEPRECATED:'),
                    'etype_deprecated': fields[4][1:].startswith('DEPRECATED'),
                    'date': time.strptime(fields[1], '%m/%d/%y'),
                })

        return keytab_entries

    @accepts()
    async def system_keytab_list(self):
        """
        Returns content of system keytab (/etc/krb5.keytab).
        """
        kt_list = await self._ktutil_list()
        parsed = []
        for entry in kt_list:
            entry['date'] = time.mktime(entry['date'])
            parsed.append(entry)

        return parsed

    @private
    async def _get_nonsamba_principals(self, keytab_list):
        """
        Generate list of Kerberos principals that are not the AD machine account.
        """
        ad = await self.middleware.call('activedirectory.config')
        pruned_list = []
        for i in keytab_list:
            if ad['netbiosname'].casefold() not in i['principal'].casefold():
                pruned_list.append(i)

        return pruned_list

    @private
    async def _generate_tmp_keytab(self):
        """
        Generate a temporary keytab to separate out the machine account keytab principal.
        ktutil copy returns 1 even if copy succeeds.
        """
        if os.path.exists(keytab['SAMBA'].value):
            os.remove(keytab['SAMBA'].value)

        if KRB5.platform() == KRB5.HEIMDAL:
            kt_copy = await run([
                'ktutil', 'copy',
                keytab['SYSTEM'].value,
                keytab['SAMBA'].value],
                check=False
            )
            if kt_copy.stderr.decode():
                raise CallError(f"failed to generate [{keytab['SAMBA'].value}]: {kt_copy.stderr.decode()}")
        else:
            kt_copy = await Popen(['ktutil'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE)
            output = await kt_copy.communicate(
                f'rkt {keytab.SYSTEM.value}\nwkt {keytab.SAMBA.value}\nq\n'.encode()
            )
            if output[1]:
                raise CallError(f"failed to generate [{keytab['SAMBA'].value}]: {output[1].decode()}")

    @private
    async def _prune_keytab_principals(self, to_delete=[]):
        """
        Delete all keytab entries from the tmp keytab that are not samba entries.
        """
        seen_principals = []
        if KRB5.platform() == KRB5.HEIMDAL:
            for i in to_delete:
                if i['principal'] in seen_principals:
                    continue
                ktutil_remove = await run([
                    'ktutil',
                    '-k', keytab['SAMBA'].value,
                    'remove',
                    '-p', i['principal']],
                    check=False
                )
                if ktutil_remove.stderr.decode():
                    raise CallError(f"ktutil_remove failed for [{i}]: {ktutil_remove.stderr.decode()}")
                seen_principals.append(i['principal'])

        else:
            """
            The pruned keytab must be written to a new file to avoid duplication of
            entries.
            """
            rkt = f"rkt {keytab.SAMBA.value}"
            wkt = "wkt /var/db/system/samba4/samba_mit.keytab"
            delents = "\n".join(f"delent {x['slot']}" for x in reversed(to_delete))
            ktutil_remove = await Popen(['ktutil'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE)
            output = await ktutil_remove.communicate(
                f'{rkt}\n{delents}\n{wkt}\nq\n'.encode()
            )
            if output[1]:
                raise CallError(output[1].decode())

            os.remove(keytab.SAMBA.value)
            os.rename("/var/db/system/samba4/samba_mit.keytab", keytab.SAMBA.value)

    @private
    async def kerberos_principal_choices(self):
        """
        Keytabs typically have multiple entries for same principal (differentiated by enc_type).
        Since the enctype isn't relevant in this situation, only show unique principal names.

        Return empty list if system keytab doesn't exist.
        """
        if not os.path.exists(keytab['SYSTEM'].value):
            return []

        try:
            keytab_list = await self._ktutil_list()
        except Exception as e:
            self.logger.trace('"ktutil list" failed. Generating empty list of kerberos principal choices. Error: %s' % e)
            return []

        kerberos_principals = []
        for entry in keytab_list:
            if entry['principal'] not in kerberos_principals:
                kerberos_principals.append(entry['principal'])

        return sorted(kerberos_principals)

    @private
    async def has_nfs_principal(self):
        """
        This method checks whether the kerberos keytab contains an nfs service principal
        """
        principals = await self.kerberos_principal_choices()
        for p in principals:
            if p.startswith("nfs/"):
                return True

        return False

    @private
    async def store_samba_keytab(self):
        """
        Samba will automatically generate system keytab entries for the AD machine account
        (netbios name with '$' appended), and maintain them through machine account password changes.

        Copy the system keytab, parse it, and update the corresponding keytab entry in the freenas configuration
        database.

        The current system kerberos keytab and compare with a cached copy before overwriting it when a new
        keytab is generated through middleware 'etc.generate kerberos'.
        """
        if not os.path.exists(keytab['SYSTEM'].value):
            return False

        encoded_keytab = None
        keytab_list = await self._ktutil_list()
        items_to_remove = await self._get_nonsamba_principals(keytab_list)
        await self._generate_tmp_keytab()
        await self._prune_keytab_principals(items_to_remove)
        with open(keytab['SAMBA'].value, 'rb') as f:
            encoded_keytab = base64.b64encode(f.read())

        if not encoded_keytab:
            self.logger.debug(f"Failed to generate b64encoded version of {keytab['SAMBA'].name}")
            return False

        keytab_file = encoded_keytab.decode()
        entry = await self.query([('name', '=', 'AD_MACHINE_ACCOUNT')])
        if not entry:
            await self.middleware.call(
                'datastore.insert',
                'directoryservice.kerberoskeytab',
                {'keytab_name': 'AD_MACHINE_ACCOUNT', 'keytab_file': keytab_file}
            )
        else:
            id = entry[0]['id']
            updated_entry = {'keytab_name': 'AD_MACHINE_ACCOUNT', 'keytab_file': keytab_file}
            await self.middleware.call('datastore.update', 'directoryservice.kerberoskeytab', id, updated_entry)

        sambakt = await self.query([('name', '=', 'AD_MACHINE_ACCOUNT')])
        if sambakt:
            return sambakt[0]['id']

    @periodic(3600)
    @private
    async def check_updated_keytab(self):
        """
        Check mtime of current kerberos keytab. If it has changed since last check,
        assume that samba has updated it behind the scenes and that the configuration
        database needs to be updated to reflect the change.
        """
        if not await self.middleware.call('system.ready'):
            return

        old_mtime = 0
        ad_state = await self.middleware.call('activedirectory.get_state')
        if ad_state == 'DISABLED' or not os.path.exists(keytab['SYSTEM'].value):
            return

        if (await self.middleware.call("smb.get_smb_ha_mode")) == "LEGACY":
            return

        if await self.middleware.call('cache.has_key', 'KEYTAB_MTIME'):
            old_mtime = await self.middleware.call('cache.get', 'KEYTAB_MTIME')

        new_mtime = (os.stat(keytab['SYSTEM'].value)).st_mtime
        if old_mtime == new_mtime:
            return

        ts = await self.middleware.call('directoryservices.get_last_password_change')
        if ts['dbconfig'] == ts['secrets']:
            return

        self.logger.debug("Machine account password has changed. Stored copies of "
                          "kerberos keytab and directory services secrets will now "
                          "be updated.")

        await self.middleware.call('directoryservices.backup_secrets')
        await self.store_samba_keytab()
        self.logger.trace('Updating stored AD machine account kerberos keytab')
        await self.middleware.call(
            'cache.put',
            'KEYTAB_MTIME',
            (os.stat(keytab['SYSTEM'].value)).st_mtime
        )
