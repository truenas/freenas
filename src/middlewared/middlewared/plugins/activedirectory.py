import datetime
import enum
import errno
import grp
import json
import ntplib
import os
import pwd
import socket
import subprocess
import threading
import time

from dns import resolver
from middlewared.plugins.smb import SMBCmd, SMBPath, SMBHAMODE, WBCErr
from middlewared.schema import accepts, Bool, Dict, Int, List, Str
from middlewared.service import job, private, ConfigService, Service, ValidationError, ValidationErrors
from middlewared.service_exception import CallError
import middlewared.sqlalchemy as sa
from middlewared.utils import run
from middlewared.plugins.directoryservices import DSStatus
from middlewared.plugins.idmap import DSType
import middlewared.utils.osc as osc

from samba.dcerpc.messaging import MSG_WINBIND_ONLINE
from samba.credentials import Credentials
from samba.net import Net
from samba.samba3 import param
from samba.dcerpc import (nbt, netlogon)
from samba import (ntstatus, NTSTATUSError)

LP_CTX = param.get_context()
FEATURE_SEAL = 4

DEFAULT_AD_PARAMETERS = {
    "server role": "member server",
    "kerberos method": "secrets and keytab",
    "security": "ADS",
    "local master": "No",
    "domain master": "No",
    "preferred master": "No",
    "winbind cache time": "7200",
    "winbind max domain connections": "10",
    "client ldap sasl wrapping": "seal",
    "template shell": "/bin/sh",
    "ads dns update": None,
    "realm": None,
    "allow trusted domains": None,
    "winbind enum users": None,
    "winbind enum groups": None,
    "winbind use default domain": None,
    "winbind nss info": None,
}


class neterr(enum.Enum):
    JOINED = 1
    NOTJOINED = 2
    FAULT = 3

    def to_status(errstr):
        errors_to_rejoin = [
            '0xfffffff6',
            'The name provided is not a properly formed account name',
            'The attempted logon is invalid.'
        ]
        for err in errors_to_rejoin:
            if err in errstr:
                return neterr.NOTJOINED

        return neterr.FAULT


class SRV(enum.Enum):
    DOMAINCONTROLLER = '_ldap._tcp.dc._msdcs.'
    FORESTGLOBALCATALOG = '_ldap._tcp.gc._msdcs.'
    GLOBALCATALOG = '_gc._tcp.'
    KERBEROS = '_kerberos._tcp.'
    KERBEROSDOMAINCONTROLLER = '_kerberos._tcp.dc._msdcs.'
    KPASSWD = '_kpasswd._tcp.'
    LDAP = '_ldap._tcp.'
    PDC = '_ldap._tcp.pdc._msdcs.'


class ActiveDirectory_DNS(object):
    def __init__(self, **kwargs):
        super(ActiveDirectory_DNS, self).__init__()
        self.ad = kwargs.get('conf')
        self.logger = kwargs.get('logger')
        return

    def _get_SRV_records(self, host, dns_timeout):
        """
        Set resolver timeout to 1/3 of the lifetime. The timeout defines
        how long to wait before moving on to the next nameserver in resolv.conf
        """
        srv_records = []

        if not host:
            return srv_records

        r = resolver.Resolver()
        r.lifetime = dns_timeout
        r.timeout = r.lifetime / 3

        try:

            answers = r.query(host, 'SRV')
            srv_records = sorted(
                answers,
                key=lambda a: (int(a.priority), int(a.weight))
            )

        except Exception:
            srv_records = []

        return srv_records

    def port_is_listening(self, host, port, timeout=1):
        ret = False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            s.settimeout(timeout)

        try:
            s.connect((host, port))
            ret = True

        except Exception as e:
            self.logger.debug("connection to %s failed with error: %s",
                              host, e)
            ret = False

        finally:
            s.close()

        return ret

    def _get_servers(self, srv_prefix):
        """
        We will first try fo find servers based on our AD site. If we don't find
        a server in our site, then we populate list for whole domain. Ticket #27584
        Domain Controllers, Forest Global Catalog Servers, and Kerberos Domain Controllers
        need the site information placed before the 'msdcs' component of the host entry.t
        """
        servers = []
        if not self.ad['domainname']:
            return servers

        if self.ad['site'] and self.ad['site'] != 'Default-First-Site-Name':
            if 'msdcs' in srv_prefix.value:
                parts = srv_prefix.value.split('.')
                srv = '.'.join([parts[0], parts[1]])
                msdcs = '.'.join([parts[2], parts[3]])
                host = f"{srv}.{self.ad['site']}._sites.{msdcs}.{self.ad['domainname']}"
            else:
                host = f"{srv_prefix.value}{self.ad['site']}._sites.{self.ad['domainname']}"
        else:
            host = f"{srv_prefix.value}{self.ad['domainname']}"

        servers = self._get_SRV_records(host, self.ad['dns_timeout'])

        if not servers and self.ad['site']:
            host = f"{srv_prefix.value}{self.ad['domainname']}"
            servers = self._get_SRV_records(host, self.ad['dns_timeout'])

        return servers

    def get_n_working_servers(self, srv=SRV['DOMAINCONTROLLER'], number=1):
        """
        :get_n_working_servers: often only a few working servers are needed and not the whole
        list available on the domain. This takes the SRV record type and number of servers to get
        as arguments.
        """
        servers = self._get_servers(srv)
        found_servers = []
        for server in servers:
            if len(found_servers) == number:
                break

            host = server.target.to_text(True)
            port = int(server.port)
            if self.port_is_listening(host, port, timeout=self.ad['timeout']):
                server_info = {'host': host, 'port': port}
                found_servers.append(server_info)

        if self.ad['verbose_logging']:
            self.logger.debug(f'Request for [{number}] of server type [{srv.name}] returned: {found_servers}')
        return found_servers


class ActiveDirectory_Conn(object):
    def __init__(self, **kwargs):
        super(ActiveDirectory_Conn, self).__init__()
        self.ad = kwargs.get('conf')
        self.logger = kwargs.get('logger')
        self.cred = Credentials()
        self._init_creds()
        self.netctx = Net(creds=self.cred, lp=LP_CTX)

    def _init_creds(self):
        LP_CTX.load(SMBPath.GLOBALCONF.platform())
        self.cred.set_gensec_features(self.cred.get_gensec_features() | FEATURE_SEAL)
        self.cred.guess()

    def _init_machine_secrets(self):
        try:
            self.cred.set_machine_account(LP_CTX)
        except NTSTATUSError as e:
            if e.args[0] == ntstatus.NT_STATUS_CANT_ACCESS_DOMAIN_INFO:
                return e.args[0]
            else:
                raise CallError(f"Failed to initialize machine account secrets: {e.args[1]}")

        return ntstatus.NT_STATUS_SUCCESS

    def _extend_creds(self):
        status = self._init_machine_secrets()
        if status == ntstatus.NT_STATUS_CANT_ACCESS_DOMAIN_INFO:
            self.logger.warning(f"Failed to initialize secrets for domain [{self.ad['domainname']}]. "
                                "attempting to use credentials from config file.")
            self.cred.set_username(f"{self.ad['bindname']}@{self.ad['domainname'].upper()}")
            self.cred.set_password(self.ad['bindpw'])

    def _do_cldap(self):
        try:
            cldap_ret = self.netctx.finddc(
                domain=self.ad['domainname'].upper(),
                flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE
            )
        except NTSTATUSError as e:
            if e.args[0] == ntstatus.NT_STATUS_OBJECT_NAME_NOT_FOUND:
                raise CallError(f"cldap connection to domain [{self.ad['domainname']}] "
                                f"failed with error: {e.args[1]} This may indicate a DNS error.",
                                errno.ENOENT)
            else:
                raise CallError(f"cldap connection to domain [{self.ad['domainname']}] "
                                f"failed with error: {e[1]}.")

        return cldap_ret

    def conn_check(self, dc=None):
        self._extend_creds()
        if dc is None:
            dc = self.get_pdc()
        netlogon.netlogon(
            f"ncacn_ip_tcp:{dc}[schannel,seal]", LP_CTX, self.cred
        )
        return True

    def get_site(self):
        cldap_ret = self._do_cldap()
        return cldap_ret.client_site

    def get_pdc(self):
        cldap_ret = self._do_cldap()
        return cldap_ret.pdc_dns_name

    def get_domain(self):
        cldap_ret = self._do_cldap()
        return cldap_ret.domain_name


class ActiveDirectoryModel(sa.Model):
    __tablename__ = 'directoryservice_activedirectory'

    id = sa.Column(sa.Integer(), primary_key=True)
    ad_domainname = sa.Column(sa.String(120))
    ad_bindname = sa.Column(sa.String(120))
    ad_bindpw = sa.Column(sa.EncryptedText())
    ad_verbose_logging = sa.Column(sa.Boolean())
    ad_allow_trusted_doms = sa.Column(sa.Boolean())
    ad_use_default_domain = sa.Column(sa.Boolean())
    ad_allow_dns_updates = sa.Column(sa.Boolean())
    ad_disable_freenas_cache = sa.Column(sa.Boolean())
    ad_restrict_pam = sa.Column(sa.Boolean())
    ad_site = sa.Column(sa.String(120), nullable=True)
    ad_timeout = sa.Column(sa.Integer())
    ad_dns_timeout = sa.Column(sa.Integer())
    ad_nss_info = sa.Column(sa.String(120), nullable=True)
    ad_enable = sa.Column(sa.Boolean())
    ad_kerberos_realm_id = sa.Column(sa.ForeignKey('directoryservice_kerberosrealm.id', ondelete='SET NULL'),
                                     index=True, nullable=True)
    ad_kerberos_principal = sa.Column(sa.String(255))
    ad_createcomputer = sa.Column(sa.String(255))


class ActiveDirectoryService(ConfigService):
    class Config:
        service = "activedirectory"
        datastore = 'directoryservice.activedirectory'
        datastore_extend = "activedirectory.ad_extend"
        datastore_prefix = "ad_"
        cli_namespace = "directory_service.activedirectory"

    @private
    async def ad_extend(self, ad):
        smb = await self.middleware.call('smb.config')
        smb_ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if smb_ha_mode == 'STANDALONE':
            ad.update({
                'netbiosname': smb['netbiosname'],
                'netbiosalias': smb['netbiosalias']
            })
        elif smb_ha_mode == 'UNIFIED':
            ngc = await self.middleware.call('network.configuration.config')
            ad.update({
                'netbiosname': ngc['hostname_virtual'],
                'netbiosalias': smb['netbiosalias']
            })
        elif smb_ha_mode == 'LEGACY':
            ngc = await self.middleware.call('network.configuration.config')
            ad.update({
                'netbiosname': ngc['hostname'],
                'netbiosname_b': ngc['hostname_b'],
                'netbiosalias': smb['netbiosalias']
            })

        if ad.get('nss_info'):
            ad['nss_info'] = ad['nss_info'].upper()

        if ad.get('kerberos_realm'):
            ad['kerberos_realm'] = ad['kerberos_realm']['id']

        return ad

    @private
    async def ad_compress(self, ad):
        """
        Convert kerberos realm to id. Force domain to upper-case. Remove
        foreign entries.
        kinit will fail if domain name is lower-case.
        """
        for key in ['netbiosname', 'netbiosalias', 'netbiosname_a', 'netbiosname_b']:
            if key in ad:
                ad.pop(key)

        if ad.get('nss_info'):
            ad['nss_info'] = ad['nss_info'].upper()

        return ad

    @accepts()
    async def nss_info_choices(self):
        """
        Returns list of available LDAP schema choices.
        """
        return await self.middleware.call('directoryservices.nss_info_choices', 'ACTIVEDIRECTORY')

    @private
    async def update_netbios_data(self, old, new):
        smb_ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        must_update = False
        for key in ['netbiosname', 'netbiosalias', 'netbiosname_a', 'netbiosname_b']:
            if key in new and old[key] != new[key]:
                must_update = True if new[key] else False

        if smb_ha_mode == 'STANDALONE' and must_update:
            await self.middleware.call(
                'smb.update',
                {
                    'netbiosname': new['netbiosname'],
                    'netbiosalias': new['netbiosalias']
                }
            )

        elif smb_ha_mode == 'UNIFIED' and must_update:
            await self.middleware.call('smb.update', {'netbiosalias': new['netbiosalias']})
            await self.middleware.call('network.configuration.update', {'hostname_virtual': new['netbiosname']})

        elif smb_ha_mode == 'LEGACY' and must_update:
            await self.middleware.call('smb.update', {'netbiosalias': new['netbiosalias']})
            await self.middleware.call(
                'network.configuration.update',
                {
                    'hostname': new['netbiosname'],
                    'hostname_b': new['netbiosname_b']
                }
            )
        return

    @private
    async def common_validate(self, new, old, verrors):
        if not new["enable"]:
            return

        ldap_enabled = (await self.middleware.call("ldap.config"))['enable']
        if ldap_enabled:
            verrors.add(
                "activedirectory_update.enable",
                "Active Directory service may not be enabled while LDAP service is enabled."
            )
        if new["enable"] and old["enable"] and new["kerberos_realm"] != old["kerberos_realm"]:
            verrors.add(
                "activedirectory_update.kerberos_realm",
                "Kerberos realm may not be be altered while the AD service is enabled. "
                "This is to avoid introducing possible configuration errors that may result "
                "in a production outage."
            )
        if not new["bindpw"] and not new["kerberos_principal"]:
            verrors.add(
                "activedirectory_update.bindname",
                "Bind credentials or kerberos keytab are required to join an AD domain."
            )
        if new["bindpw"] and new["kerberos_principal"]:
            verrors.add(
                "activedirectory_update.kerberos_principal",
                "Simultaneous keytab and password authentication are not permitted."
            )
        if not new["domainname"]:
            verrors.add(
                "activedirectory_update.domainname",
                "AD domain name is required."
            )

    @accepts()
    async def config(self):
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            return await super().config()

        rv = await self.middleware.call('directoryservices.get_conf',
                                        self._config.datastore)
        globals = (await self.middleware.call('smb.reg_globals'))['raw']
        rv.update({
            'domainname': globals.get('realm', ''),
            'use_default_domain': globals.get('winbind use default domain', 'No') == 'Yes',
            'allow_trusted_domains': globals.get('allow trusted domains', 'No') == 'Yes',
            'ads_dns_updates': globals.get('ads dns updates', 'No') == 'Yes',
            'nss_info': globals.get('winbind nss info', ''),
            'enable': globals.get('security', 'user') == 'ADS',
        })
        return await self.middleware.call(self._config.datastore_extend, rv)

    @accepts(Dict(
        'activedirectory_update',
        Str('domainname', required=True),
        Str('bindname'),
        Str('bindpw', private=True),
        Bool('verbose_logging'),
        Bool('use_default_domain'),
        Bool('allow_trusted_doms'),
        Bool('allow_dns_updates'),
        Bool('disable_freenas_cache'),
        Bool('restrict_pam', default=False),
        Str('site', null=True),
        Int('kerberos_realm', null=True),
        Str('kerberos_principal', null=True),
        Int('timeout', default=60),
        Int('dns_timeout', default=10),
        Str('nss_info', null=True, default='', enum=['SFU', 'SFU20', 'RFC2307']),
        Str('createcomputer'),
        Str('netbiosname'),
        Str('netbiosname_b'),
        List('netbiosalias'),
        Bool('enable'),
        update=True
    ))
    async def do_update(self, data):
        """
        Update active directory configuration.
        `domainname` full DNS domain name of the Active Directory domain.

        `bindname` username used to perform the intial domain join.

        `bindpw` password used to perform the initial domain join. User-
        provided credentials are used to obtain a kerberos ticket, which
        is used to perform the actual domain join.

        `verbose_logging` increase logging during the domain join process.

        `use_default_domain` controls whether domain users and groups have
        the pre-windows 2000 domain name prepended to the user account. When
        enabled, the user appears as "administrator" rather than
        "EXAMPLE\administrator"

        `allow_trusted_doms` enable support for trusted domains. If this
        parameter is enabled, then separate idmap backends _must_ be configured
        for each trusted domain, and the idmap cache should be cleared.

        `allow_dns_updates` during the domain join process, automatically
        generate DNS entries in the AD domain for the NAS. If this is disabled,
        then a domain administrator must manually add appropriate DNS entries
        for the NAS. This parameter is recommended for TrueNAS HA servers.

        `disable_freenas_cache` disables active caching of AD users and groups.
        When disabled, only users cached in winbind's internal cache are
        visible in GUI dropdowns. Disabling active caching is recommended
        in environments with a large amount of users.

        `site` AD site of which the NAS is a member. This parameter is auto-
        detected during the domain join process. If no AD site is configured
        for the subnet in which the NAS is configured, then this parameter
        appears as 'Default-First-Site-Name'. Auto-detection is only performed
        during the initial domain join.

        `kerberos_realm` in which the server is located. This parameter is
        automatically populated during the initial domain join. If the NAS has
        an AD site configured and that site has multiple kerberos servers, then
        the kerberos realm is automatically updated with a site-specific
        configuration to use those servers. Auto-detection is only performed
        during initial domain join.

        `kerberos_principal` kerberos principal to use for AD-related
        operations outside of Samba. After intial domain join, this field is
        updated with the kerberos principal associated with the AD machine
        account for the NAS.

        `nss_info` controls how Winbind retrieves Name Service Information to
        construct a user's home directory and login shell. This parameter
        is only effective if the Active Directory Domain Controller supports
        the Microsoft Services for Unix (SFU) LDAP schema.

        `timeout` timeout value for winbind-related operations. This value may
        need to be increased in  environments with high latencies for
        communications with domain controllers or a large number of domain
        controllers. Lowering the value may cause status checks to fail.

        `dns_timeout` timeout value for DNS queries during the initial domain
        join. This value is also set as the NETWORK_TIMEOUT in the ldap config
        file.

        `createcomputer` Active Directory Organizational Unit in which new
        computer accounts are created.

        The OU string is read from top to bottom without RDNs. Slashes ("/")
        are used as delimiters, like `Computers/Servers/NAS`. The backslash
        ("\\") is used to escape characters but not as a separator. Backslashes
        are interpreted at multiple levels and might require doubling or even
        quadrupling to take effect.

        When this field is blank, new computer accounts are created in the
        Active Directory default OU.

        The Active Directory service is started after a configuration
        update if the service was initially disabled, and the updated
        configuration sets `enable` to `True`. The Active Directory
        service is stopped if `enable` is changed to `False`. If the
        configuration is updated, but the initial `enable` state is `True`, and
        remains unchanged, then the samba server is only restarted.

        During the domain join, a kerberos keytab for the newly-created AD
        machine account is generated. It is used for all future
        LDAP / AD interaction and the user-provided credentials are removed.
        """
        await self.middleware.call("smb.cluster_check")
        verrors = ValidationErrors()
        old = await self.config()
        new = old.copy()
        new.update(data)
        new['domainname'] = new['domainname'].upper()
        try:
            await self.update_netbios_data(old, new)
        except Exception as e:
            raise ValidationError('activedirectory_update.netbiosname', str(e))

        await self.common_validate(new, old, verrors)

        if verrors:
            raise verrors

        if new['enable'] and not old['enable']:
            """
            Currently run two health checks prior to validating domain.
            1) Attempt to kinit with user-provided credentials. This is used to
               verify that the credentials are correct.
            2) Check for an overly large time offset. System kerberos libraries
               may not report the time offset as an error during kinit, but the large
               time offset will prevent libads from using the ticket for the domain
               join.
            """
            try:
                await self.middleware.run_in_thread(self.validate_credentials, new)
            except Exception as e:
                raise ValidationError(
                    "activedirectory_update.bindpw",
                    f"Failed to validate bind credentials: {e}"
                )

            try:
                await self.middleware.run_in_thread(self.check_clockskew, new)
            except ntplib.NTPException:
                self.logger.warning("NTP request to Domain Controller failed.",
                                    exc_info=True)
            except Exception as e:
                await self.middleware.call("kerberos.stop")
                raise ValidationError(
                    "activedirectory_update",
                    f"Failed to validate domain configuration: {e}"
                )

        new = await self.ad_compress(new)

        """
        first write relevant portions to our persistent datastore outside smb.conf
        in non-clustered, this will be ctdb, in clustered case we'll write the
        ad config to secrets.tdb.
        """
        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode != SMBHAMODE.CLUSTERED:
            id = new.pop("id")
            await self.middleware.call(
                'datastore.update',
                self._config.datastore,
                id, new, {'prefix': 'ad_'}
            )
        else:
            """
            Write subset of our keys to secrets.tdb. This is replicated to
            other cluster nodes. Remaining info will be pulled from smb.conf
            in the activedirectory.config() method.
            """
            to_write = {
                "id": new["id"],
                "bindname": new["bindname"],
                "verbose_logging": new["verbose_logging"],
                "kerberos_principal": new["kerberos_principal"],
                "kerberos_realm": new["kerberos_realm"],
                "createcomputer": new["createcomputer"],
                "disable_freenas_cache": new["disable_freenas_cache"],
                "restrict_pam": new["restrict_pam"],
                "timeout": new['timeout'],
                "site": new['site'],
                "dns_timeout": new['dns_timeout'],
            }
            await self.middleware.call(
                'directoryservices.set_conf',
                'directoryservice.activedirectory',
                to_write
            )

        """
        get our global config as related to directory services. We will use
        this to generate a diff to apply to the smb.conf. Implicit in this is
        that we only have a single directory service enabled at a time.
        """
        diff = await self.diff_conf_and_registry(new)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)

        start = False
        stop = False

        if not old['enable']:
            if new['enable']:
                start = True
        else:
            if not new['enable']:
                stop = True

        job = None
        if stop:
            await self.stop()
        if start:
            job = (await self.middleware.call('activedirectory.start')).id

        if not stop and not start and new['enable']:
            await self.middleware.call('service.restart', 'cifs')
        ret = await self.config()
        ret.update({'job_id': job})
        return ret

    @private
    async def ad_to_registry(self, data):
        rv = {}
        if data['enable'] is False:
            return rv

        for k, v in DEFAULT_AD_PARAMETERS.items():
            if v is None:
                continue
            rv[k] = v

        rv.update({
            "ads dns update": "Yes" if data.get("allow_dns_updates") else "No",
            "realm": data["domainname"].upper(),
            "allow trusted domains": "Yes" if data.get("allow_trusted_domains") else "No",
            "winbind enum users": "No" if data.get("disable_freenas_cache") else "Yes",
            "winbind enum groups": "No" if data.get("disable_freenas_cache") else "Yes",
            "winbind use default domain": "Yes" if data.get("use_default_domain") else "No",
        })
        if data.get("nss_info"):
            rv.update({"winbind nss info": data["nss_info"]})

        return rv

    @private
    async def diff_conf_and_registry(self, data):
        smbconf = (await self.middleware.call('smb.reg_globals'))['ds']
        to_check = await self.ad_to_registry(data)

        r = smbconf
        s_keys = set(to_check.keys())
        r_keys = set(r.keys())
        intersect = s_keys.intersection(r_keys)
        return {
            'added': {x: to_check[x] for x in s_keys - r_keys},
            'removed': {x: r[x] for x in r_keys - s_keys},
            'modified': {x: (to_check[x], r[x]) for x in intersect if to_check[x] != r[x]},
        }

    @private
    async def synchronize(self, data=None):
        if data is None:
            data = await self.config()

        diff = await self.diff_conf_and_registry(data)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)

    @private
    async def set_state(self, state):
        return await self.middleware.call('directoryservices.set_state', {'activedirectory': state.name})

    @accepts()
    async def get_state(self):
        """
        Wrapper function for 'directoryservices.get_state'. Returns only the state of the
        Active Directory service.
        """
        return (await self.middleware.call('directoryservices.get_state'))['activedirectory']

    @private
    async def set_idmap(self, trusted_domains, our_domain):
        idmap = await self.middleware.call('idmap.query',
                                           [('id', '=', DSType.DS_TYPE_ACTIVEDIRECTORY.value)],
                                           {'get': True})
        idmap_id = idmap.pop('id')
        if not idmap['range_low']:
            idmap['range_low'], idmap['range_high'] = await self.middleware.call('idmap.get_next_idmap_range')
        idmap['dns_domain_name'] = our_domain.upper()
        await self.middleware.call('idmap.update', idmap_id, idmap)
        if trusted_domains:
            await self.middleware.call('idmap.autodiscover_trusted_domains')

    @private
    @job(lock="AD_start")
    async def start(self, job):
        """
        Start AD service. In 'UNIFIED' HA configuration, only start AD service
        on active storage controller.
        """
        await self.middleware.call("smb.cluster_check")
        ad = await self.config()
        smb = await self.middleware.call('smb.config')
        smb_ha_mode = await self.middleware.call('smb.reset_smb_ha_mode')
        if smb_ha_mode == 'UNIFIED':
            if await self.middleware.call('failover.status') != 'MASTER':
                return

        state = await self.get_state()
        if state in [DSStatus['JOINING'], DSStatus['LEAVING']]:
            raise CallError(f'Active Directory Service has status of [{state}]. Wait until operation completes.', errno.EBUSY)

        await self.set_state(DSStatus['JOINING'])
        job.set_progress(0, 'Preparing to join Active Directory')
        if ad['verbose_logging']:
            self.logger.debug('Starting Active Directory service for [%s]', ad['domainname'])
        await self.middleware.call('datastore.update', self._config.datastore, ad['id'], {'ad_enable': True})
        await self.synchronize()
        await self.middleware.call('etc.generate', 'hostname')

        """
        Kerberos realm field must be populated so that we can perform a kinit
        and use the kerberos ticket to execute 'net ads' commands.
        """
        job.set_progress(5, 'Configuring Kerberos Settings.')
        if not ad['kerberos_realm']:
            realms = await self.middleware.call('kerberos.realm.query', [('realm', '=', ad['domainname'])])

            if realms:
                realm_id = realms[0]['id']
            else:
                realm_id = await self.middleware.call('datastore.insert',
                                                      'directoryservice.kerberosrealm',
                                                      {'krb_realm': ad['domainname'].upper()})

            await self.middleware.call('datastore.update',
                                       self._config.datastore,
                                       ad['id'], {'ad_kerberos_realm': realm_id})
            ad = await self.config()

        if not await self.middleware.call('kerberos._klist_test'):
            await self.middleware.call('kerberos.start')

        """
        'workgroup' is the 'pre-Windows 2000 domain name'. It must be set to the nETBIOSName value in Active Directory.
        This must be properly configured in order for Samba to work correctly as an AD member server.
        'site' is the ad site of which the NAS is a member. If sites and subnets are unconfigured this will
        default to 'Default-First-Site-Name'.
        """

        job.set_progress(20, 'Detecting Active Directory Site.')
        if not ad['site']:
            new_site = await self.middleware.call('activedirectory.get_site')
            if new_site != 'Default-First-Site-Name':
                ad = await self.config()
                await self.middleware.call('activedirectory.set_kerberos_servers', ad)

        job.set_progress(30, 'Detecting Active Directory NetBIOS Domain Name.')
        if not smb['workgroup'] or smb['workgroup'] == 'WORKGROUP':
            await self.middleware.call('activedirectory.get_netbios_domain_name')

        await self.middleware.call('etc.generate', 'smb')

        """
        Check response of 'net ads testjoin' to determine whether the server needs to be joined to Active Directory.
        Only perform the domain join if we receive the exact error code indicating that the server is not joined to
        Active Directory. 'testjoin' will fail if the NAS boots before the domain controllers in the environment.
        In this case, samba should be started, but the directory service reported in a FAULTED state.
        """

        job.set_progress(40, 'Performing testjoin to Active Directory Domain')
        ret = await self._net_ads_testjoin(smb['workgroup'])
        if ret == neterr.NOTJOINED:
            job.set_progress(50, 'Joining Active Directory Domain')
            self.logger.debug(f"Test join to {ad['domainname']} failed. Performing domain join.")
            await self._net_ads_join()
            await self._register_virthostname(ad, smb, smb_ha_mode)
            if smb_ha_mode != 'LEGACY':
                """
                Manipulating the SPN entries must be done with elevated privileges. Add NFS service
                principals while we have these on-hand. Once added, force a refresh of the system
                keytab so that the NFS principal will be available for gssd.
                """
                job.set_progress(60, 'Adding NFS Principal entries.')

                try:
                    await self.add_nfs_spn(ad)
                except Exception:
                    self.logger.warning("Failed to add NFS spn to active directory "
                                        "computer object.", exc_info=True)

                job.set_progress(70, 'Storing computer account keytab.')
                kt_id = await self.middleware.call('kerberos.keytab.store_samba_keytab')
                if kt_id:
                    self.logger.debug('Successfully generated keytab for computer account. Clearing bind credentials')
                    await self.middleware.call(
                        'datastore.update',
                        'directoryservice.activedirectory',
                        ad['id'],
                        {'ad_bindpw': '', 'ad_kerberos_principal': f'{ad["netbiosname"].upper()}$@{ad["domainname"]}'}
                    )
                    ad = await self.config()

            ret = neterr.JOINED

            job.set_progress(80, 'Configuring idmap backend and NTP servers.')
            await self.middleware.call('service.update', 'cifs', {'enable': True})
            await self.set_idmap(ad['allow_trusted_doms'], ad['domainname'])
            await self.middleware.call('activedirectory.set_ntp_servers')

        job.set_progress(90, 'Restarting SMB server.')
        await self.middleware.call('idmap.synchronize')
        await self.middleware.call('service.restart', 'cifs')
        await self.middleware.call('etc.generate', 'pam')
        await self.middleware.call('etc.generate', 'nss')
        if ret == neterr.JOINED:
            await self.set_state(DSStatus['HEALTHY'])
            await self.middleware.call('admonitor.start')
            await self.middleware.call('service.start', 'dscache')
            if ad['verbose_logging']:
                self.logger.debug('Successfully started AD service for [%s].', ad['domainname'])

            if smb_ha_mode == "LEGACY" and (await self.middleware.call('failover.status')) == 'MASTER':
                job.set_progress(95, 'starting active directory on standby controller')
                try:
                    await self.middleware.call('failover.call_remote', 'activedirectory.start')
                except Exception:
                    self.logger.warning('Failed to start active directory service on standby controller', exc_info=True)
        else:
            await self.set_state(DSStatus['FAULTED'])
            self.logger.warning('Server is joined to domain [%s], but is in a faulted state.', ad['domainname'])

        job.set_progress(100, f'Active Directory start completed with status [{ret.name}]')
        return ret.name

    @private
    async def stop(self):
        await self.middleware.call("smb.cluster_check")
        ad = await self.config()
        await self.middleware.call('datastore.update', self._config.datastore, ad['id'], {'ad_enable': False})
        await self.set_state(DSStatus['LEAVING'])
        await self.middleware.call('admonitor.stop')
        await self.middleware.call('etc.generate', 'hostname')
        await self.middleware.call('kerberos.stop')
        await self.synchronize()
        await self.middleware.call('idmap.synchronize')
        await self.middleware.call('service.restart', 'cifs')
        await self.middleware.call('etc.generate', 'pam')
        await self.middleware.call('etc.generate', 'nss')
        await self.set_state(DSStatus['DISABLED'])
        await self.middleware.call('service.stop', 'dscache')
        flush = await run([SMBCmd.NET.value, "cache", "flush"], check=False)
        if flush.returncode != 0:
            self.logger.warning("Failed to flush samba's general cache after stopping Active Directory service.")
        if (await self.middleware.call('smb.get_smb_ha_mode')) == "LEGACY" and (await self.middleware.call('failover.status')) == 'MASTER':
            try:
                await self.middleware.call('failover.call_remote', 'activedirectory.stop')
            except Exception:
                self.logger.warning('Failed to stop active directory service on standby controller', exc_info=True)

    @private
    def validate_credentials(self, ad=None):
        """
        Kinit with user-provided credentials is sufficient to determine
        whether the credentials are good. A testbind here is unnecessary.
        """
        if self.middleware.call_sync('kerberos._klist_test'):
            # Short-circuit credential validation if we have a valid tgt
            return

        if ad is None:
            ad = self.middleware.call_sync('activedirectory.config')

        data = ad.copy()
        data['dstype'] = DSType.DS_TYPE_ACTIVEDIRECTORY.value

        try:
            self.middleware.call_sync('kerberos.do_kinit', data)
        except Exception:
            realm = self.middleware.call_sync(
                'kerberos.realm.query',
                [('realm', '=', ad['domainname'])],
                {'get': True}
            )
            self.middleware.call_sync('kerberos.realm.delete', realm['id'])
            raise
        return True

    @private
    def check_clockskew(self, ad=None):
        """
        Uses DNS srv records to determine server with PDC emulator FSMO role and
        perform NTP query to determine current clockskew. Raises exception if
        clockskew exceeds 3 minutes, otherwise returns dict with hostname of
        PDC emulator, time as reported from PDC emulator, and time difference
        between the PDC emulator and the NAS.
        """
        permitted_clockskew = datetime.timedelta(minutes=3)
        nas_time = datetime.datetime.now()
        if not ad:
            ad = self.middleware.call_sync('activedirectory.config')

        try:
            pdc = ActiveDirectory_Conn(conf=ad, logger=self.logger).get_pdc()
            if not pdc:
                self.logger.warning("Unable to find PDC emulator via DNS.")
                return {'pdc': None, 'timestamp': '0', 'clockskew': 0}
        except CallError:
            AD_DNS = ActiveDirectory_DNS(conf=ad, logger=self.logger)
            res = AD_DNS.get_n_working_servers(SRV['DOMAINCONTROLLER'], 1)
            if len(res) == 0:
                self.logger.warning("Unable to find Domain Controller via DNS.")
                return {'pdc': None, 'timestamp': '0', 'clockskew': 0}

            pdc = res[0]['host']

        c = ntplib.NTPClient()
        response = c.request(pdc)
        ntp_time = datetime.datetime.fromtimestamp(response.tx_time)
        clockskew = abs(ntp_time - nas_time)
        if clockskew > permitted_clockskew:
            raise CallError(f'Clockskew between {pdc} and NAS exceeds 3 minutes: {clockskew}')
        return {'pdc': pdc, 'timestamp': str(ntp_time), 'clockskew': str(clockskew)}

    @private
    def validate_domain(self, data=None):
        """
        Methods used to determine AD domain health.
        First we check whether our clock offset has grown to potentially production-impacting
        levels, then we change whether another DC in our AD site is able to take over if the
        DC winbind is currently connected to becomes inaccessible.
        """
        self.middleware.call_sync('activedirectory.check_clockskew', data)
        self.conn_check(data)

    @private
    def conn_check(self, data=None, dc=None):
        """
        Temporarily connect to netlogon share of a DC that isn't the one that
        winbind is currently communicating with in order to validate our credentials
        and ability to failover in case of outage on winbind's current DC.

        We only check a single DC because domains can have a significantly large number
        of domain controllers in a given site.
        """
        if data is None:
            data = self.middleware.call_sync("activedirectory.config")
        if dc is None:
            AD_DNS = ActiveDirectory_DNS(conf=data, logger=self.logger)
            res = AD_DNS.get_n_working_servers(SRV['DOMAINCONTROLLER'], 2)
            if len(res) != 2:
                self.logger.warning("Less than two Domain Controllers are in our "
                                    "Active Directory Site. This may result in production "
                                    "outage if the currently connected DC is unreachable.")
                return False

            """
            In some pathologically bad cases attempts to get the DC that winbind is currently
            communicating with can time out. For this particular health check, the winbind
            error should not be considered fatal.
            """
            wb_dcinfo = subprocess.run([SMBCmd.WBINFO.value, "--dc-info", data["domainname"]],
                                       capture_output=True, check=False)
            if wb_dcinfo.returncode == 0:
                # output "FQDN (ip address)"
                our_dc = wb_dcinfo.stdout.decode().split()[0]
                for dc_to_check in res:
                    thehost = dc_to_check['host']
                    if thehost.casefold() != our_dc.casefold():
                        dc = thehost
            else:
                self.logger.warning("Failed to get DC info from winbindd: %s", wb_dcinfo.stderr.decode())
                dc = res[0]['host']

        try:
            ret = ActiveDirectory_Conn(conf=data, logger=self.logger).conn_check(dc)
        except NTSTATUSError as e:
            if e.args[0] == ntstatus.NT_STATUS_NO_TRUST_SAM_ACCOUNT:
                raise CallError("No SAM Trust Account for this TrueNAS server exists "
                                f"on Domain Controller [{dc}]. This may indicate problems "
                                "with replication between Domain Controllers in the Active "
                                "Directory domain and may impact file sharing services "
                                "dependent on SAM account information being consistent among "
                                "domain controllers", errno=errno.ENOENT)

            raise CallError(f"Netlogon connection to [{dc}] failed with error: {e.args[1]}")

        return ret

    @accepts()
    async def started(self):
        """
        Issue a no-effect command to our DC. This checks if our secure channel connection to our
        domain controller is still alive. It has much less impact than wbinfo -t.
        Default winbind request timeout is 60 seconds, and can be adjusted by the smb4.conf parameter
        'winbind request timeout ='
        """
        verrors = ValidationErrors()
        config = await self.config()
        if not config['enable']:
            return False

        await self.common_validate(config, config, verrors)

        try:
            verrors.check()
        except Exception:
            await self.middleware.call(
                'datastore.update',
                'directoryservice.activedirectory',
                config['id'],
                {'ad_enable': False}
            )
            raise CallError('Automatically disabling ActiveDirectory service due to invalid configuration.',
                            errno.EINVAL)

        """
        Initialize state to "JOINING" until after booted.
        """
        if not await self.middleware.call('system.ready'):
            await self.set_state(DSStatus['JOINING'])
            return True

        """
        Verify winbindd netlogon connection.
        """
        netlogon_ping = await run([SMBCmd.WBINFO.value, '-P'], check=False)
        if netlogon_ping.returncode != 0:
            wberr = netlogon_ping.stderr.decode().strip('\n')
            err = errno.EFAULT
            for wb in WBCErr:
                if wb.err() in wberr:
                    wberr = wberr.replace(wb.err(), wb.value[0])
                    err = wb.value[1] if wb.value[1] else errno.EFAULT
                    break

            raise CallError(wberr, err)

        try:
            cached_state = await self.middleware.call('cache.get', 'DS_STATE')

            if cached_state['activedirectory'] != 'HEALTHY':
                await self.set_state(DSStatus['HEALTHY'])
        except KeyError:
            await self.set_state(DSStatus['HEALTHY'])

        return True

    @private
    async def _register_virthostname(self, ad, smb, smb_ha_mode):
        """
        This co-routine performs virtual hostname aware
        dynamic DNS updates after joining AD to register
        VIP addresses.
        """
        if not ad['allow_dns_updates'] or smb_ha_mode == 'STANDALONE':
            return

        vhost = (await self.middleware.call('network.configuration.config'))['hostname_virtual']
        vips = [i['address'] for i in (await self.middleware.call('interface.ip_in_use', {'static': True}))]
        smb_bind_ips = smb['bindip'] if smb['bindip'] else vips
        to_register = set(vips) & set(smb_bind_ips)
        hostname = f'{vhost}.{ad["domainname"]}'
        cmd = [SMBCmd.NET.value, '-k', 'ads', 'dns', 'register', hostname]
        cmd.extend(to_register)
        netdns = await run(cmd, check=False)
        if netdns.returncode != 0:
            self.logger.debug("hostname: %s, ips: %s, text: %s",
                              hostname, to_register, netdns.stderr.decode())

    @private
    async def _parse_join_err(self, msg):
        if len(msg) < 2:
            raise CallError(msg)

        if "Invalid configuration" in msg[1]:
            """
            ./source3/libnet/libnet_join.c will return configuration erros for the
            following situations:
            - incorrect workgroup
            - incorrect realm
            - incorrect security settings
            Unless users set auxiliary parameters, only the first should be a possibility.
            """
            raise CallError(f'{msg[1].rsplit(")",1)[0]}).', errno.EINVAL)
        else:
            raise CallError(msg[1])

    @private
    async def _net_ads_join(self):
        ad = await self.config()
        if ad['createcomputer']:
            netads = await run([
                SMBCmd.NET.value, '-k', '-U', ad['bindname'], '-d', '5',
                'ads', 'join', f'createcomputer={ad["createcomputer"]}',
                ad['domainname']], check=False)
        else:
            netads = await run([
                SMBCmd.NET.value, '-k', '-U', ad['bindname'], '-d', '5',
                'ads', 'join', ad['domainname']], check=False)

        if netads.returncode != 0:
            await self.set_state(DSStatus['FAULTED'])
            await self._parse_join_err(netads.stdout.decode().split(':', 1))

    @private
    async def _net_ads_testjoin(self, workgroup):
        """
        If neterr.NOTJOINED is returned then we will proceed with joining (or re-joining)
        the AD domain. There are currently two reasons to do this:
        1) we're not joined to AD
        2) our computer account was deleted out from under us
        It's generally better to report an error condition to the end user and let them
        fix it, but situation (2) above is straightforward enough to automatically re-join.
        In this case, the error message presents oddly because stale credentials are stored in
        the secrets.tdb file and the message is passed up from underlying KRB5 library.
        """
        ad = await self.config()
        netads = await run([
            SMBCmd.NET.value, '-k', '-w', workgroup,
            '-d', '5', 'ads', 'testjoin', ad['domainname']],
            check=False
        )
        if netads.returncode != 0:
            errout = netads.stderr.decode()
            with open(f"{SMBPath.LOGDIR.platform()}/domain_testjoin_{int(datetime.datetime.now().timestamp())}.log", "w") as f:
                f.write(errout)

            return neterr.to_status(errout)

        return neterr.JOINED

    @private
    async def _net_ads_setspn(self, spn_list):
        """
        Only automatically add NFS SPN entries on domain join
        if kerberized nfsv4 is enabled.
        """
        if not (await self.middleware.call('nfs.config'))['v4_krb']:
            return False

        for spn in spn_list:
            netads = await run([
                SMBCmd.NET.value, '-k', 'ads', 'setspn',
                'add', spn
            ], check=False)
            if netads.returncode != 0:
                raise CallError('failed to set spn entry '
                                f'[{spn}]: {netads.stdout.decode().strip()}')

        return True

    @accepts()
    async def get_spn_list(self):
        """
        Return list of kerberos SPN entries registered for the server's Active
        Directory computer account. This may not reflect the state of the
        server's current kerberos keytab.
        """
        spnlist = []
        netads = await run([SMBCmd.NET.value, '-k', 'ads', 'setspn', 'list'], check=False)
        if netads.returncode != 0:
            raise CallError(
                f"Failed to generate SPN list: [{netads.stderr.decode().strip()}]"
            )

        for spn in netads.stdout.decode().splitlines():
            if len(spn.split('/')) != 2:
                continue
            spnlist.append(spn.strip())

        return spnlist

    @accepts()
    async def change_trust_account_pw(self):
        """
        Force an update of the AD machine account password. This can be used to
        refresh the Kerberos principals in the server's system keytab.
        """
        workgroup = (await self.middleware.call('smb.config'))['workgroup']
        netads = await run([SMBCmd.NET.value, '-k', 'ads', '-w', workgroup, 'changetrustpw'], check=False)
        if netads.returncode != 0:
            raise CallError(
                f"Failed to update trust password: [{netads.stderr.decode().strip()}] "
                f"stdout: [{netads.stdout.decode().strip()}] "
            )

    @private
    async def add_nfs_spn(self, ad=None):
        if ad is None:
            ad = await self.config()

        ok = await self._net_ads_setspn([
            f'nfs/{ad["netbiosname"].upper()}.{ad["domainname"]}',
            f'nfs/{ad["netbiosname"].upper()}'
        ])
        if not ok:
            return False

        await self.change_trust_account_pw()

        return True

    @accepts()
    async def domain_info(self):
        """
        Returns the following information about the currently joined domain:

        `LDAP server` IP address of current LDAP server to which TrueNAS is connected.

        `LDAP server name` DNS name of LDAP server to which TrueNAS is connected

        `Realm` Kerberos realm

        `LDAP port`

        `Server time` timestamp.

        `KDC server` Kerberos KDC to which TrueNAS is connected

        `Server time offset` current time offset from DC.

        `Last machine account password change`. timestamp
        """
        netads = await run([SMBCmd.NET.value, '-k', 'ads', 'info', '--json'], check=False)
        if netads.returncode != 0:
            raise CallError(netads.stderr.decode())

        return json.loads(netads.stdout.decode())

    @private
    def get_netbios_domain_name(self):
        """
        The 'workgroup' parameter must be set correctly in order for AD join to
        succeed. This is based on the short form of the domain name, which was defined
        by the AD administrator who deployed originally deployed the AD enviornment.
        The only way to reliably get this is to query the LDAP server. This method
        queries and sets it.
        """

        ret = False
        ad = self.middleware.call_sync('activedirectory.config')
        smb = self.middleware.call_sync('smb.config')

        domain = ActiveDirectory_Conn(conf=ad, logger=self.logger).get_domain()

        if domain and smb['workgroup'] != ret:
            self.logger.debug(f'Updating SMB workgroup to match the short form of the AD domain [{ret}]')
            self.middleware.call_sync('datastore.update', 'services.cifs', smb['id'], {'cifs_srv_workgroup': domain})

        return ret

    @private
    def get_kerberos_servers(self, ad=None):
        """
        This returns at most 3 kerberos servers located in our AD site. This is to optimize
        kerberos configuration for locations where kerberos servers may span the globe and
        have equal DNS weighting. Since a single kerberos server may represent an unacceptable
        single point of failure, fall back to relying on normal DNS queries in this case.
        """
        if ad is None:
            ad = self.middleware.call_sync('activedirectory.config')
        AD_DNS = ActiveDirectory_DNS(conf=ad, logger=self.logger)
        krb_kdc = AD_DNS.get_n_working_servers(SRV['KERBEROSDOMAINCONTROLLER'], 3)
        krb_admin_server = AD_DNS.get_n_working_servers(SRV['KERBEROS'], 3)
        krb_kpasswd_server = AD_DNS.get_n_working_servers(SRV['KPASSWD'], 3)
        kdc = [i['host'] for i in krb_kdc]
        admin_server = [i['host'] for i in krb_admin_server]
        kpasswd = [i['host'] for i in krb_kpasswd_server]
        for servers in [kdc, admin_server, kpasswd]:
            if len(servers) == 1:
                return None

        return {
            'krb_kdc': ' '.join(kdc),
            'krb_admin_server': ' '.join(admin_server),
            'krb_kpasswd_server': ' '.join(kpasswd)
        }

    @private
    def set_kerberos_servers(self, ad=None):
        if not ad:
            ad = self.middleware.call_sync('activedirectory.config')
        site_indexed_kerberos_servers = self.get_kerberos_servers(ad)
        if site_indexed_kerberos_servers:
            self.middleware.call_sync(
                'datastore.update',
                'directoryservice.kerberosrealm',
                ad['kerberos_realm'],
                site_indexed_kerberos_servers
            )
            self.middleware.call_sync('etc.generate', 'kerberos')

    @private
    def set_ntp_servers(self):
        """
        Appropriate time sources are a requirement for an AD environment. By default kerberos authentication
        fails if there is more than a 5 minute time difference between the AD domain and the member server.
        If the NTP servers are the default that we ship the NAS with. If this is the case, then we will
        discover the Domain Controller with the PDC emulator FSMO role and set it as the preferred NTP
        server for the NAS.
        """
        ntp_servers = self.middleware.call_sync('system.ntpserver.query')
        ntp_pool = 'freebsd.pool.ntp.og' if osc.IS_FREEBSD else 'debian.pool.ntp.org'
        default_ntp_servers = list(filter(lambda x: ntp_pool in x['address'], ntp_servers))
        if len(ntp_servers) != 3 or len(default_ntp_servers) != 3:
            return

        ad = self.middleware.call_sync('activedirectory.config')
        pdc = ActiveDirectory_Conn(conf=ad, logger=self.logger).get_pdc()
        if not pdc:
            self.logger.warning("Unable to detect PDC emulator for domain. "
                                "Failed to automatically set time source.")
            return

        try:
            self.middleware.call_sync('system.ntpserver.create', {'address': pdc, 'prefer': True})
        except Exception:
            self.logger.warning('Failed to configure NTP for the Active Directory domain. Additional '
                                'manual configuration may be required to ensure consistent time offset, '
                                'which is required for a stable domain join.', exc_info=True)

    @private
    def get_site(self):
        """
        First, use DNS to identify domain controllers
        Then, find a domain controller that is listening for LDAP connection if this information is not cached.
        Then, perform an LDAP query to determine our AD site
        """
        ad = self.middleware.call_sync('activedirectory.config')
        site = ActiveDirectory_Conn(conf=ad, logger=self.logger).get_site()

        if not ad['site']:
            self.middleware.call_sync(
                'datastore.update',
                'directoryservice.activedirectory',
                ad['id'],
                {'ad_site': site}
            )

        return site

    @accepts(
        Dict(
            'leave_ad',
            Str('username', required=True),
            Str('password', required=True, private=True)
        )
    )
    async def leave(self, data):
        """
        Leave Active Directory domain. This will remove computer
        object from AD and clear relevant configuration data from
        the NAS.
        This requires credentials for appropriately-privileged user.
        Credentials are used to obtain a kerberos ticket, which is
        used to perform the actual removal from the domain.
        """
        ad = await self.config()
        smb_ha_mode = await self.middleware.call('smb.get_smb_ha_mode')

        ad['dstype'] = DSType.DS_TYPE_ACTIVEDIRECTORY.value
        ad['bindname'] = data.get("username", "")
        ad['bindpw'] = data.get("password", "")
        ad['kerberos_principal'] = ''

        await self.middleware.call('kerberos.do_kinit', ad)

        netads = await run([SMBCmd.NET.value, '-U', data['username'], '-k', 'ads', 'leave'], check=False)
        if netads.returncode != 0:
            self.logger.warning("Failed to leave domain: %s", netads.stderr.decode())

        if smb_ha_mode != 'LEGACY':
            krb_princ = await self.middleware.call(
                'kerberos.keytab.query',
                [('name', '=', 'AD_MACHINE_ACCOUNT')]
            )
            if krb_princ:
                await self.middleware.call('kerberos.keytab.delete', krb_princ[0]['id'])

        await self.middleware.call('datastore.delete', 'directoryservice.kerberosrealm', ad['kerberos_realm'])

        if netads.returncode == 0:
            try:
                pdir = await self.middleware.call("smb.getparm", "private directory", "GLOBAL")
                ts = time.time()
                os.rename(f"{pdir}/secrets.tdb", f"{pdir}/secrets.tdb.bak.{int(ts)}")
                await self.middleware.call("directoryservices.backup_secrets")
            except Exception:
                self.logger.debug("Failed to remove stale secrets file.", exc_info=True)

        await self.middleware.call('activedirectory.update', {'enable': False, 'site': None})
        if smb_ha_mode == 'LEGACY' and (await self.middleware.call('failover.status')) == 'MASTER':
            try:
                await self.middleware.call('failover.call_remote', 'activedirectory.leave', [data])
            except Exception:
                self.logger.warning("Failed to leave AD domain on passive storage controller.", exc_info=True)

        flush = await run([SMBCmd.NET.value, "cache", "flush"], check=False)
        if flush.returncode != 0:
            self.logger.warning("Failed to flush samba's general cache after leaving Active Directory.")

        self.logger.debug("Successfully left domain: %s", ad['domainname'])

    @private
    @job(lock='fill_ad_cache')
    def fill_cache(self, job, force=False):
        """
        Use UID2SID and GID2SID entries in Samba's gencache.tdb to populate the AD_cache.
        Since this can include IDs outside of our configured idmap domains (Local accounts
        will also appear here), there is a check to see if the ID is inside the idmap ranges
        configured for domains that are known to us. Some samba idmap backends support
        id_type_both, in which case the will be GID2SID entries for AD users. getent group
        succeeds in this case (even though the group doesn't exist in AD). Since these
        we don't want to populate the UI cache with these entries, try to getpwnam for
        GID2SID entries. If it's an actual group, getpwnam will fail. This heuristic
        may be revised in the future, but we want to keep things as simple as possible
        here since the list of entries numbers perhaps in the tens of thousands.
        """
        if self.middleware.call_sync('cache.has_key', 'AD_cache') and not force:
            raise CallError('AD cache already exists. Refusing to generate cache.')

        self.middleware.call_sync('cache.pop', 'AD_cache')
        ad = self.middleware.call_sync('activedirectory.config')
        smb = self.middleware.call_sync('smb.config')
        id_type_both_backends = [
            'RID',
            'AUTORID'
        ]
        if not ad['disable_freenas_cache']:
            """
            These calls populate the winbindd cache
            """
            pwd.getpwall()
            grp.getgrall()
        elif ad['bindname']:
            id = subprocess.run(['/usr/bin/id', f"{smb['workgroup']}\\{ad['bindname']}"], capture_output=True)
            if id.returncode != 0:
                self.logger.debug('failed to id AD bind account [%s]: %s', ad['bindname'], id.stderr.decode())

        netlist = subprocess.run(
            [SMBCmd.NET.value, 'cache', 'list'],
            capture_output=True,
            check=False
        )
        if netlist.returncode != 0:
            raise CallError(f'Winbind cache dump failed with error: {netlist.stderr.decode().strip()}')

        known_domains = []
        local_users = {}
        local_groups = {}
        local_users.update({x['uid']: x for x in self.middleware.call_sync('user.query')})
        local_users.update({x['gid']: x for x in self.middleware.call_sync('group.query')})
        cache_data = {'users': {}, 'groups': {}}
        configured_domains = self.middleware.call_sync('idmap.query')
        user_next_index = group_next_index = 300000000
        for d in configured_domains:
            if d['name'] == 'DS_TYPE_ACTIVEDIRECTORY':
                known_domains.append({
                    'domain': smb['workgroup'],
                    'low_id': d['range_low'],
                    'high_id': d['range_high'],
                    'id_type_both': True if d['idmap_backend'] in id_type_both_backends else False,
                })
            elif d['name'] not in ['DS_TYPE_DEFAULT_DOMAIN', 'DS_TYPE_LDAP']:
                known_domains.append({
                    'domain': d['name'],
                    'low_id': d['range_low'],
                    'high_id': d['range_high'],
                    'id_type_both': True if d['idmap_backend'] in id_type_both_backends else False,
                })

        for line in netlist.stdout.decode().splitlines():
            if line.startswith('Key: IDMAP/UID2SID'):
                cached_uid = int((line.split())[1][14:])
                """
                Do not cache local users. This is to avoid problems where a local user
                may enter into the id range allotted to AD users.
                """
                if local_users.get(cached_uid, None):
                    continue

                for d in known_domains:
                    if cached_uid in range(d['low_id'], d['high_id']):
                        """
                        Samba will generate UID and GID cache entries when idmap backend
                        supports id_type_both.
                        """
                        try:
                            user_data = pwd.getpwuid(cached_uid)
                            cache_data['users'].update({user_data.pw_name: {
                                'id': user_next_index,
                                'uid': user_data.pw_uid,
                                'username': user_data.pw_name,
                                'unixhash': None,
                                'smbhash': None,
                                'group': {},
                                'home': '',
                                'shell': '',
                                'full_name': user_data.pw_gecos,
                                'builtin': False,
                                'email': '',
                                'password_disabled': False,
                                'locked': False,
                                'sudo': False,
                                'sudo_nopasswd': False,
                                'sudo_commands': [],
                                'microsoft_account': False,
                                'attributes': {},
                                'groups': [],
                                'sshpubkey': None,
                                'local': False,
                                'id_type_both': d['id_type_both']
                            }})
                            user_next_index += 1
                            break
                        except KeyError:
                            break

            if line.startswith('Key: IDMAP/GID2SID'):
                cached_gid = int((line.split())[1][14:])
                if local_groups.get(cached_gid, None):
                    continue

                for d in known_domains:
                    if cached_gid in range(d['low_id'], d['high_id']):
                        """
                        Samba will generate UID and GID cache entries when idmap backend
                        supports id_type_both. Actual groups will return key error on
                        attempt to generate passwd struct. It is also possible that the
                        winbindd cache will have stale or expired entries. Failure on getgrgid
                        should not be fatal here.
                        """
                        try:
                            group_data = grp.getgrgid(cached_gid)
                        except KeyError:
                            break

                        cache_data['groups'].update({group_data.gr_name: {
                            'id': group_next_index,
                            'gid': group_data.gr_gid,
                            'group': group_data.gr_name,
                            'builtin': False,
                            'sudo': False,
                            'sudo_nopasswd': False,
                            'sudo_commands': [],
                            'users': [],
                            'local': False,
                            'id_type_both': d['id_type_both']
                        }})
                        group_next_index += 1
                        break

        if not cache_data.get('users'):
            return
        sorted_cache = {}
        sorted_cache['users'] = dict(sorted(cache_data['users'].items()))
        sorted_cache['groups'] = dict(sorted(cache_data['groups'].items()))

        self.middleware.call_sync('cache.put', 'AD_cache', sorted_cache)
        self.middleware.call_sync('dscache.backup')

    @private
    async def get_cache(self):
        """
        Returns cached AD user and group information. If proactive caching is enabled
        then this will contain all AD users and groups, otherwise it contains the
        users and groups that were present in the winbindd cache when the cache was
        last filled. The cache expires and is refilled every 24 hours, or can be
        manually refreshed by calling fill_cache(True).
        """
        if not await self.middleware.call('cache.has_key', 'AD_cache'):
            await self.middleware.call('activedirectory.fill_cache')
            self.logger.debug('cache fill is in progress.')
            return {'users': {}, 'groups': {}}
        return await self.middleware.call('cache.get', 'AD_cache')


class WBStatusThread(threading.Thread):
    def __init__(self, **kwargs):
        super(WBStatusThread, self).__init__()
        self.setDaemon(True)
        self.middleware = kwargs.get('middleware')
        self.logger = self.middleware.logger
        self.finished = threading.Event()
        self.state = MSG_WINBIND_ONLINE

    def parse_msg(self, data):
        if data == str(DSStatus.LEAVING.value):
            return

        try:
            m = json.loads(data)
        except json.decoder.JSONDecodeError:
            self.logger.debug("Unable to decode winbind status message: "
                              "%s", data)
            return

        new_state = self.state

        if not self.middleware.call_sync('activedirectory.config')['enable']:
            self.logger.debug('Ignoring winbind message for disabled AD service: [%s]', m)
            return

        try:
            new_state = DSStatus(m['winbind_message']).value
        except Exception as e:
            self.logger.debug('Received invalid winbind status message [%s]: %s', m, e)
            return

        if m['domain_name_netbios'] != self.middleware.call_sync('smb.config')['workgroup']:
            self.logger.debug(
                'Domain [%s] changed state to %s',
                m['domain_name_netbios'],
                DSStatus(m['winbind_message']).name
            )
            return

        if self.state != new_state:
            self.logger.debug(
                'State of domain [%s] transistioned to [%s]',
                m['forest_name'], DSStatus(m['winbind_message'])
            )
            self.middleware.call_sync('activedirectory.set_state', DSStatus(m['winbind_message']))
            if new_state == DSStatus.FAULTED.value:
                self.middleware.call_sync(
                    "alert.oneshot_create",
                    "ActiveDirectoryDomainOffline",
                    {"domain": m["domain_name_netbios"]}
                )
            else:
                self.middleware.call_sync(
                    "alert.oneshot_delete",
                    "ActiveDirectoryDomainOffline",
                    {"domain": m["domain_name_netbios"]}
                )

        self.state = new_state

    def read_messages(self):
        while not self.finished.is_set():
            with open(f'{SMBPath.RUNDIR.platform()}/.wb_fifo') as f:
                data = f.read()
                for msg in data.splitlines():
                    self.parse_msg(msg)

        self.logger.debug('exiting winbind messaging thread')

    def run(self):
        osc.set_thread_name('ad_monitor_thread')
        try:
            self.read_messages()
        except Exception as e:
            self.logger.debug('Failed to run monitor thread %s', e, exc_info=True)

    def setup(self):
        if not os.path.exists(f'{SMBPath.RUNDIR.platform()}/.wb_fifo'):
            os.mkfifo(f'{SMBPath.RUNDIR.platform()}/.wb_fifo')

    def cancel(self):
        """
        Write to named pipe to unblock open() in thread and exit cleanly.
        """
        self.finished.set()
        with open(f'{SMBPath.RUNDIR.platform()}/.wb_fifo', 'w') as f:
            f.write(str(DSStatus.LEAVING.value))


class ADMonitorService(Service):
    class Config:
        private = True

    def __init__(self, *args, **kwargs):
        super(ADMonitorService, self).__init__(*args, **kwargs)
        self.thread = None
        self.initialized = False
        self.lock = threading.Lock()

    def start(self):
        if not self.middleware.call_sync('activedirectory.config')['enable']:
            self.logger.trace('Active directory is disabled. Exiting AD monitoring.')
            return

        with self.lock:
            if self.initialized:
                return

            thread = WBStatusThread(
                middleware=self.middleware,
            )
            thread.setup()
            self.thread = thread
            thread.start()
            self.initialized = True

    def stop(self):
        thread = self.thread
        if thread is None:
            return

        thread.cancel()
        self.thread = None

        with self.lock:
            self.initialized = False

    def restart(self):
        self.stop()
        self.start()


async def setup(middleware):
    """
    During initial boot let smb_configure script start monitoring once samba's
    rundir is created.
    """
    if await middleware.call('system.ready'):
        await middleware.call('admonitor.start')
