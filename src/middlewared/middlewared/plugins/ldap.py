import asyncio
import enum
import errno
import fcntl
import grp
import ipaddress
import ldap as pyldap
import os
import pwd
import socket
import struct
import sys

from ldap.controls import SimplePagedResultsControl
from urllib.parse import urlparse
from middlewared.schema import accepts, Bool, Dict, Int, List, Str
from middlewared.service import job, private, ConfigService, ValidationErrors
from middlewared.service_exception import CallError
import middlewared.sqlalchemy as sa
from middlewared.utils import run
from middlewared.plugins.directoryservices import DSStatus, SSL


_int32 = struct.Struct('!i')

DEFAULT_LDAP_PARAMETERS = {
    "server role": "member server",
    "kerberos method": None,
    "security": "user",
    "ldap admin dn": None,
    "ldap suffix": None,
    "ldap replication sleep": "1000",
    "ldap passwd sync": "Yes",
    "ldap ssl": None,
    "ldapsam:trusted": "Yes",
    "domain logons": "Yes",
    "passdb backend": None,
    "local master": "No",
    "domain master": "No",
    "preferred master": "No",
}


class NlscdConst(enum.Enum):
    NSLCD_CONF_PATH = '/usr/local/etc/nslcd.conf'
    NSLCD_PIDFILE = '/var/run/nslcd.pid'
    NSLCD_SOCKET = '/var/run/nslcd/nslcd.ctl'
    NSLCD_VERSION = 0x00000002
    NSLCD_ACTION_STATE_GET = 0x00010002
    NSLCD_RESULT_BEGIN = 1
    NSLCD_RESULT_END = 2


class NslcdClient(object):
    def __init__(self, action):
        # set up the socket (store in class to avoid closing it)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        fcntl.fcntl(self.sock, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        # connect to nslcd
        self.sock.connect(NlscdConst.NSLCD_SOCKET.value)
        # self.sock.setblocking(1)
        self.fp = os.fdopen(self.sock.fileno(), 'r+b', 0)
        # write a request header with a request code
        self.action = action
        self.write_int32(NlscdConst.NSLCD_VERSION.value)
        self.write_int32(action)

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    def write(self, value):
        self.fp.write(value)

    def write_int32(self, value):
        self.write(_int32.pack(value))

    def write_bytes(self, value):
        self.write_int32(len(value))
        self.write(value)

    def read(self, size):
        value = b''
        while len(value) < size:
            data = self.fp.read(size - len(value))
            if not data:
                raise IOError('NSLCD protocol cut short')
            value += data
        return value

    def read_int32(self):
        return _int32.unpack(self.read(_int32.size))[0]

    def read_bytes(self):
        return self.read(self.read_int32())

    def read_string(self):
        value = self.read_bytes()
        if sys.version_info[0] >= 3:
            value = value.decode('utf-8')
        return value

    def get_response(self):
        # complete the request if required and check response header
        if self.action:
            # flush the stream
            self.fp.flush()
            # read and check response version number
            if self.read_int32() != NlscdConst.NSLCD_VERSION.value:
                raise IOError('NSLCD protocol error')
            if self.read_int32() != self.action:
                raise IOError('NSLCD protocol error')
            # reset action to ensure that it is only the first time
            self.action = None
        # get the NSLCD_RESULT_* marker and return it
        return self.read_int32()

    def close(self):
        if hasattr(self, 'fp'):
            try:
                self.fp.close()
            except IOError:
                pass

    def __del__(self):
        self.close()


class LDAPQuery(object):
    def __init__(self, **kwargs):
        super(LDAPQuery, self).__init__()
        self.ldap = kwargs.get('conf')
        self.logger = kwargs.get('logger')
        self.hosts = kwargs.get('hosts')
        self.pagesize = 1024
        self._isopen = False
        self._handle = None
        self._rootDSE = None

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        if self._isopen:
            self._close()

    def validate_credentials(self):
        """
        :validate_credentials: simple check to determine whether we can establish
        an ldap session with the credentials that are in the configuration.
        """
        ret = self._open()
        if ret:
            self._close()
        return ret

    def _name_to_errno(self, ldaperr):
        err = errno.EFAULT
        if ldaperr == "INVALID_CREDENTIALS":
            err = errno.EAUTH
        elif ldaperr == "NO_SUCH_OBJECT":
            err = errno.ENOENT
        elif ldaperr == "INVALID_DN_SYNTAX":
            err = errno.EINVAL

        return err

    def _convert_exception(self, ex):
        if issubclass(type(ex), pyldap.LDAPError) and ex.args:
            desc = ex.args[0].get('desc')
            info = ex.args[0].get('info')
            err_str = f"{desc}: {info}" if info else desc
            err = self._name_to_errno(type(ex).__name__)
            raise CallError(err_str, err, type(ex).__name__)
        else:
            raise CallError(str(ex))

    def _open(self):
        """
        We can only intialize a single host. In this case,
        we iterate through a list of hosts until we get one that
        works and then use that to set our LDAP handle.

        SASL GSSAPI bind only succeeds when DNS reverse lookup zone
        is correctly populated. Fall through to simple bind if this
        fails.
        """
        res = None
        if self._isopen:
            return True

        if self.hosts:
            saved_simple_error = None
            saved_gssapi_error = None
            for server in self.hosts:
                try:
                    self._handle = pyldap.initialize(server)
                except Exception as e:
                    self.logger.debug(f'Failed to initialize ldap connection to [{server}]: ({e}). Moving to next server.')
                    continue

                res = None
                pyldap.protocol_version = pyldap.VERSION3
                pyldap.set_option(pyldap.OPT_REFERRALS, 0)
                pyldap.set_option(pyldap.OPT_NETWORK_TIMEOUT, self.ldap['dns_timeout'])

                if SSL(self.ldap['ssl']) != SSL.NOSSL:
                    if self.ldap['certificate']:
                        pyldap.set_option(
                            pyldap.OPT_X_TLS_CERTFILE,
                            f"/etc/certificates/{self.ldap['cert_name']}.crt"
                        )
                        pyldap.set_option(
                            pyldap.OPT_X_TLS_KEYFILE,
                            f"/etc/certificates/{self.ldap['cert_name']}.key"
                        )

                    pyldap.set_option(
                        pyldap.OPT_X_TLS_CACERTFILE,
                        '/etc/ssl/truenas_cacerts.pem'
                    )
                    if self.ldap['validate_certificates']:
                        pyldap.set_option(
                            pyldap.OPT_X_TLS_REQUIRE_CERT,
                            pyldap.OPT_X_TLS_DEMAND
                        )
                    else:
                        pyldap.set_option(
                            pyldap.OPT_X_TLS_REQUIRE_CERT,
                            pyldap.OPT_X_TLS_ALLOW
                        )

                    try:
                        pyldap.set_option(pyldap.OPT_X_TLS_NEWCTX, 0)
                    except Exception:
                        self.logger.warning('Failed to initialize new TLS context.', exc_info=True)

                if SSL(self.ldap['ssl']) == SSL.USESTARTTLS:
                    try:
                        self._handle.start_tls_s()

                    except pyldap.LDAPError as e:
                        self.logger.debug('Encountered error initializing start_tls: %s', e)
                        saved_simple_error = e
                        continue

                if self.ldap['anonbind']:
                    try:
                        res = self._handle.simple_bind_s()
                        break
                    except Exception as e:
                        saved_simple_error = e
                        self.logger.debug('Anonymous bind failed: %s' % e)
                        continue

                if self.ldap['certificate']:
                    try:
                        res = self._handle.sasl_non_interactive_bind_s('EXTERNAL')
                        if self.ldap['verbose_logging']:
                            self.logger.debug('Successfully bound to [%s] using client certificate.', server)
                        break
                    except Exception as e:
                        saved_simple_error = e
                        self.logger.debug('SASL EXTERNAL bind failed.', exc_info=True)
                        continue

                if self.ldap['kerberos_principal']:
                    try:
                        self._handle.set_option(pyldap.OPT_X_SASL_NOCANON, 1)
                        self._handle.sasl_gssapi_bind_s()
                        res = True
                        break
                    except Exception as e:
                        saved_gssapi_error = e
                        self.logger.debug(f'SASL GSSAPI bind failed: {e}. Attempting simple bind')

                try:
                    res = self._handle.simple_bind_s(self.ldap['binddn'], self.ldap['bindpw'])
                    break
                except Exception as e:
                    self.logger.debug(f'Failed to bind to [{server}] using [{self.ldap["binddn"]}]: {e}')
                    saved_simple_error = e
                    continue

            if res:
                self._isopen = True

            elif saved_gssapi_error:
                self._convert_exception(saved_gssapi_error)

            elif saved_simple_error:
                self._convert_exception(saved_simple_error)

        return (self._isopen is True)

    def _close(self):
        self._isopen = False
        if self._handle:
            self._handle.unbind()
            self._handle = None

    def _search(self, basedn='', scope=pyldap.SCOPE_SUBTREE, filter='', timeout=-1, sizelimit=0):
        if not self._handle:
            self._open()

        result = []
        serverctrls = None
        clientctrls = None
        paged = SimplePagedResultsControl(
            criticality=False,
            size=self.pagesize,
            cookie=''
        )
        paged_ctrls = {SimplePagedResultsControl.controlType: SimplePagedResultsControl}

        page = 0
        while True:
            serverctrls = [paged]

            id = self._handle.search_ext(
                basedn,
                scope,
                filterstr=filter,
                attrlist=None,
                attrsonly=0,
                serverctrls=serverctrls,
                clientctrls=clientctrls,
                timeout=timeout,
                sizelimit=sizelimit
            )

            (rtype, rdata, rmsgid, serverctrls) = self._handle.result3(
                id, resp_ctrl_classes=paged_ctrls
            )

            result.extend(rdata)

            paged.size = 0
            paged.cookie = cookie = None
            for sc in serverctrls:
                if sc.controlType == SimplePagedResultsControl.controlType:
                    cookie = sc.cookie
                    if cookie:
                        paged.cookie = cookie
                        paged.size = self.pagesize

                        break

            if not cookie:
                break

            page += 1

        return result

    def parse_results(self, results):
        res = []
        for r in results:
            parsed_data = {}
            if len(r) > 1 and isinstance(r[1], dict):
                for k, v in r[1].items():
                    try:
                        v = list(i.decode() for i in v)
                    except Exception:
                        v = list(str(i) for i in v)
                    parsed_data.update({k: v})

                res.append({
                    'dn': r[0],
                    'data': parsed_data
                })
            else:
                self.logger.debug("Unable to parse results: %s", r)

        return res

    def get_samba_domains(self):
        """
        This returns a list of configured samba domains on the LDAP
        server. This is used to determine whether the LDAP server has
        The Samba LDAP schema. In this case, the SMB service can be
        configured to use Samba's ldapsam passdb backend.
        """
        if not self._handle:
            self._open()
        filter = '(objectclass=sambaDomain)'
        try:
            results = self._search(self.ldap['basedn'], pyldap.SCOPE_SUBTREE, filter)
        except Exception as e:
            self._convert_exception(e)

        return self.parse_results(results)

    def get_root_DSE(self):
        """
        root DSE query is defined in RFC4512 as a search operation
        with an empty baseObject, scope of baseObject, and a filter of
        "(objectClass=*)"
        In theory this should be accessible with an anonymous bind. In practice,
        it's better to use proper auth because configurations can vary wildly.
        """
        if not self._handle:
            self._open()
        filter = '(objectclass=*)'
        results = self._search('', pyldap.SCOPE_BASE, filter)
        return self.parse_results(results)

    def get_dn(self, dn):
        if not self._handle:
            self._open()
        filter = '(objectclass=*)'
        results = self._search(dn, pyldap.SCOPE_SUBTREE, filter)
        return self.parse_results(results)


class LDAPModel(sa.Model):
    __tablename__ = 'directoryservice_ldap'

    id = sa.Column(sa.Integer(), primary_key=True)
    ldap_hostname = sa.Column(sa.String(120))
    ldap_basedn = sa.Column(sa.String(120))
    ldap_binddn = sa.Column(sa.EncryptedText())
    ldap_bindpw = sa.Column(sa.String(120))
    ldap_anonbind = sa.Column(sa.Boolean())
    ldap_ssl = sa.Column(sa.String(120))
    ldap_timeout = sa.Column(sa.Integer())
    ldap_dns_timeout = sa.Column(sa.Integer())
    ldap_has_samba_schema = sa.Column(sa.Boolean())
    ldap_auxiliary_parameters = sa.Column(sa.Text())
    ldap_schema = sa.Column(sa.String(120))
    ldap_enable = sa.Column(sa.Boolean())
    ldap_certificate_id = sa.Column(sa.ForeignKey('system_certificate.id'), index=True, nullable=True)
    ldap_kerberos_realm_id = sa.Column(sa.ForeignKey('directoryservice_kerberosrealm.id'), index=True, nullable=True)
    ldap_kerberos_principal = sa.Column(sa.String(255))
    ldap_validate_certificates = sa.Column(sa.Boolean(), default=True)
    ldap_disable_freenas_cache = sa.Column(sa.Boolean())


class LDAPService(ConfigService):
    class Config:
        service = "ldap"
        datastore = 'directoryservice.ldap'
        datastore_extend = "ldap.ldap_extend"
        datastore_prefix = "ldap_"
        cli_namespace = "directory_service.ldap"

    @private
    async def ldap_extend(self, data):
        data['hostname'] = data['hostname'].split(',') if data['hostname'] else []
        for key in ["ssl", "schema"]:
            data[key] = data[key].upper()

        if data["certificate"] is not None:
            data["cert_name"] = data['certificate']['cert_name']
            data["certificate"] = data['certificate']['id']
        else:
            data["cert_name"] = None

        if data["kerberos_realm"] is not None:
            data["kerberos_realm"] = data["kerberos_realm"]["id"]

        data['uri_list'] = await self.hostnames_to_uris(data)

        return data

    @private
    async def ldap_compress(self, data):
        data['hostname'] = ','.join(data['hostname'])
        for key in ["ssl", "schema"]:
            data[key] = data[key].lower()

        if not data['bindpw']:
            data.pop('bindpw')

        data.pop('uri_list')
        data.pop('cert_name')

        return data

    @accepts()
    async def schema_choices(self):
        """
        Returns list of available LDAP schema choices.
        """
        return await self.middleware.call('directoryservices.nss_info_choices', 'LDAP')

    @accepts()
    async def ssl_choices(self):
        """
        Returns list of SSL choices.
        """
        return await self.middleware.call('directoryservices.ssl_choices', 'LDAP')

    @private
    async def hostnames_to_uris(self, data):
        ret = []
        for h in data['hostname']:
            proto = 'ldaps' if SSL(data['ssl']) == SSL.USESSL else 'ldap'
            parsed = urlparse(f"{proto}://{h}")
            try:
                port = parsed.port
                host = parsed.netloc if not parsed.port else parsed.netloc.rsplit(':', 1)[0]
            except ValueError:
                """
                ParseResult.port will raise a ValueError if the port is not an int
                Ignore for now. ValidationError will be raised in common_validate()
                """
                host, port = h.rsplit(':', 1)

            if port is None:
                port = 636 if SSL(data['ssl']) == SSL.USESSL else 389

            uri = f"{proto}://{host}:{port}"
            ret.append(uri)

        return ret

    @private
    async def common_validate(self, new, old, verrors):
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == "clustered":
            verrors.add("ldap_upate", "Clustered LDAP service not yet implemented")

        if not new["enable"]:
            return

        ad_enabled = (await self.middleware.call("activedirectory.config"))['enable']
        if ad_enabled:
            verrors.add(
                "ldap_update.enable",
                "LDAP service may not be enabled while Active Directory service is enabled."
            )

        if new["certificate"]:
            verrors.extend(await self.middleware.call(
                "certificate.cert_services_validation",
                new["certificate"], "ldap_update.certificate", False
            ))

        if not new["bindpw"] and new["has_samba_schema"]:
            verrors.add(
                "ldap_update.bindpw",
                "Bind credentials are required in order to use samba schema."
            )

        if not new["bindpw"] and not new["kerberos_principal"] and not new["anonbind"]:
            verrors.add(
                "ldap_update.binddn",
                "Bind credentials or kerberos keytab are required for an authenticated bind."
            )
        if new["bindpw"] and new["kerberos_principal"]:
            self.logger.warning("Simultaneous keytab and password authentication "
                                "are selected. Clearing LDAP bind password.")
            new["bindpw"] = ""

        if not new["basedn"]:
            verrors.add(
                "ldap_update.basedn",
                "The basedn parameter is required."
            )
        if not new["hostname"]:
            verrors.add(
                "ldap_update.hostname",
                "The LDAP hostname parameter is required."
            )
        for idx, uri in enumerate(new["uri_list"]):
            parsed = urlparse(uri)
            try:
                port = parsed.port

            except ValueError:
                verrors.add(f"ldap_update.hostname.{idx}",
                            f"Invalid port number: [{port}].")

    @private
    async def convert_ldap_err_to_verr(self, data, e, verrors):
        if e.extra == "INVALID_CREDENTIALS":
            verrors.add('ldap_update.binddn',
                        'Remote LDAP server returned response that '
                        'credentials are invalid.')

        elif e.extra == "STRONG_AUTH_NOT_SUPPORTED" and data['certificate']:
            verrors.add('ldap_update.certificate',
                        'Certificate-based authentication is not '
                        f'supported by remote LDAP server: {e.errmsg}.')

        elif e.extra == "NO_SUCH_OBJECT":
            verrors.add('ldap_update.basedn',
                        'Remote LDAP server returned "NO_SUCH_OBJECT". This may '
                        'indicate that the base DN is syntactically correct, but does '
                        'not exist on the server.')

        elif e.extra == "INVALID_DN_SYNTAX":
            verrors.add('ldap_update.basedn',
                        'Remote LDAP server returned that the base DN is '
                        'syntactically invalid.')

        elif e.extra:
            verrors.add('ldap_update', f'[{e.extra.__name__}]: {e.errmsg}')

        else:
            verrors.add('ldap_update', e.errmsg)

    @private
    async def ldap_validate(self, data, verrors):
        ldap_has_samba_schema = False

        for idx, h in enumerate(data['uri_list']):
            host, port = urlparse(h).netloc.rsplit(':', 1)
            try:
                await self.middleware.call('ldap.port_is_listening', host, int(port), data['dns_timeout'])
            except Exception as e:
                verrors.add(
                    f'ldap_update.hostname.{idx}',
                    f'Failed to open socket to remote LDAP server: {e}'
                )
                return

        try:
            await self.middleware.call('ldap.validate_credentials', data)
        except CallError as e:
            await self.convert_ldap_err_to_verr(data, e, verrors)
            return

        try:
            ldap_has_samba_schema = True if (await self.middleware.call('ldap.get_workgroup', data)) else False
        except CallError as e:
            await self.convert_ldap_err_to_verr(data, e, verrors)

        if data['has_samba_schema'] and not ldap_has_samba_schema:
            verrors.add('ldap_update.has_samba_schema',
                        'Remote LDAP server does not have Samba schema extensions.')

    @accepts(Dict(
        'ldap_update',
        List('hostname', required=True),
        Str('basedn', required=True),
        Str('binddn'),
        Str('bindpw', private=True),
        Bool('anonbind', default=False),
        Str('ssl', default='OFF', enum=['OFF', 'ON', 'START_TLS']),
        Int('certificate', null=True),
        Bool('validate_certificates', default=True),
        Bool('disable_freenas_cache'),
        Int('timeout', default=30),
        Int('dns_timeout', default=5),
        Int('kerberos_realm', null=True),
        Str('kerberos_principal'),
        Bool('has_samba_schema', default=False),
        Str('auxiliary_parameters', default=False, max_length=None),
        Str('schema', default='RFC2307', enum=['RFC2307', 'RFC2307BIS']),
        Bool('enable'),
        update=True
    ))
    async def do_update(self, data):
        """
        `hostname` list of ip addresses or hostnames of LDAP servers with
        which to communicate in order of preference. Failover only occurs
        if the current LDAP server is unresponsive.

        `basedn` specifies the default base DN to use when performing ldap
        operations. The base must be specified as a Distinguished Name in LDAP
        format.

        `binddn` specifies the default bind DN to use when performing ldap
        operations. The bind DN must be specified as a Distinguished Name in
        LDAP format.

        `anonbind` use anonymous authentication.

        `ssl` establish SSL/TLS-protected connections to the LDAP server(s).
        GSSAPI signing is disabled on SSL/TLS-protected connections if
        kerberos authentication is used.

        `certificate` LDAPs client certificate to be used for certificate-
        based authentication.

        `validate_certificates` specifies whether to perform checks on server
        certificates in a TLS session. If enabled, TLS_REQCERT demand is set.
        The server certificate is requested. If no certificate is provided or
        if a bad certificate is provided, the session is immediately terminated.
        If disabled, TLS_REQCERT allow is set. The server certificate is
        requested, but all errors are ignored.

        `kerberos_realm` in which the server is located. This parameter is
        only required for SASL GSSAPI authentication to the remote LDAP server.

        `kerberos_principal` kerberos principal to use for SASL GSSAPI
        authentication to the remote server. If `kerberos_realm` is specified
        without a keytab, then the `binddn` and `bindpw` are used to
        perform to obtain the ticket necessary for GSSAPI authentication.

        `timeout` specifies  a  timeout  (in  seconds) after which calls to
        synchronous LDAP APIs will abort if no response is received.

        `dns_timeout` specifies the timeout (in seconds) after which the
        poll(2)/select(2) following a connect(2) returns in case of no activity
        for openldap. For nslcd this specifies the time limit (in seconds) to
        use when connecting to the directory server. This directly impacts the
        length of time that the LDAP service tries before failing over to
        a secondary LDAP URI.

        `has_samba_schema` determines whether to configure samba to use the
        ldapsam passdb backend to provide SMB access to LDAP users. This feature
        requires the presence of Samba LDAP schema extensions on the remote
        LDAP server.
        """
        verrors = ValidationErrors()
        must_reload = False
        old = await self.config()
        new = old.copy()
        new.update(data)
        new['uri_list'] = await self.hostnames_to_uris(new)
        await self.common_validate(new, old, verrors)
        verrors.check()

        if data.get('certificate') and data['certificate'] != old['certificate']:
            new_cert = await self.middleware.call('certificate.query',
                                                  [('id', '=', data['certificate'])],
                                                  {'get': True})
            new['cert_name'] = new_cert['name']

        if old != new:
            must_reload = True
            if new['enable']:
                await self.middleware.call('ldap.ldap_validate', new, verrors)
                verrors.check()

        await self.ldap_compress(new)
        await self.middleware.call(
            'datastore.update',
            'directoryservice.ldap',
            old['id'],
            new,
            {'prefix': 'ldap_'}
        )

        if must_reload:
            if new['enable']:
                await self.middleware.call('ldap.start')
            else:
                await self.middleware.call('ldap.stop')

        return await self.config()

    @private
    def port_is_listening(self, host, port, timeout=1):
        ret = False

        try:
            ipaddress.IPv6Address(host)
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except ipaddress.AddressValueError:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if timeout:
            s.settimeout(timeout)

        try:
            s.connect((host, port))
            ret = True

        except Exception as e:
            raise CallError(e)

        finally:
            s.close()

        return ret

    @private
    @job(lock="ldapquery")
    def do_ldap_query(self, job, ldap_conf, action, args):
        supported_actions = [
            'get_samba_domains',
            'get_root_DSE',
            'get_dn',
            'validate_credentials',
        ]
        if action not in supported_actions:
            raise CallError(f"Unsuported LDAP query: {action}")

        if ldap_conf is None:
            ldap_conf = self.middleware.call_sync('ldap.config')

        with LDAPQuery(conf=ldap_conf, logger=self.logger, hosts=ldap_conf['uri_list']) as LDAP:
            if action == "get_samba_domains":
                ret = LDAP.get_samba_domains()

            elif action == "get_root_DSE":
                ret = LDAP.get_root_DSE()

            elif action == "get_dn":
                dn = ldap_conf['basedn'] if args is None else args
                ret = LDAP.get_dn(dn)

            elif action == "validate_credentials":
                ret = LDAP.validate_credentials()

        return ret

    @private
    def validate_credentials(self, ldap_config=None):
        ldap_job = self.middleware.call_sync("ldap.do_ldap_query", ldap_config, "validate_credentials", None)
        ret = ldap_job.wait_sync(raise_error=True)
        return ret

    @private
    def get_samba_domains(self, ldap_config=None):
        ldap_job = self.middleware.call_sync("ldap.do_ldap_query", ldap_config, "get_samba_domains", None)
        ret = ldap_job.wait_sync(raise_error=True)
        return ret

    @private
    def get_root_DSE(self, ldap_config=None):
        """
        root DSE is defined in RFC4512, and must include the following:

        `namingContexts` naming contexts held in the LDAP sever

        `subschemaSubentry` subschema entries known by the LDAP server

        `altServer` alternative servers in case this one is unavailable

        `supportedExtension` list of supported extended operations

        `supportedControl` list of supported controls

        `supportedSASLMechnaisms` recognized Simple Authentication and Security layers
        (SASL) [RFC4422] mechanisms.

        `supportedLDAPVersion` LDAP versions implemented by the LDAP server

        In practice, this full data is not returned from many LDAP servers
        """
        ldap_job = self.middleware.call_sync("ldap.do_ldap_query", ldap_config, "get_root_DSE", None)
        ret = ldap_job.wait_sync(raise_error=True)
        return ret

    @private
    def get_dn(self, dn=None, ldap_config=None):
        """
        Outputs contents of specified DN in JSON. By default will target the basedn.
        """
        ldap_job = self.middleware.call_sync("ldap.do_ldap_query", ldap_config, "get_dn", dn)
        ret = ldap_job.wait_sync(raise_error=True)
        return ret

    @private
    async def started(self):
        """
        Returns False if disabled, True if healthy, raises exception if faulted.
        """
        verrors = ValidationErrors()
        ldap = await self.config()
        if not ldap['enable']:
            return False

        await self.common_validate(ldap, ldap, verrors)
        try:
            verrors.check()
        except Exception:
            await self.middleware.call(
                'datastore.update',
                'directoryservice.ldap',
                ldap['id'],
                {'ldap_enable': False}
            )
            raise CallError('Automatically disabling LDAP service due to invalid configuration.',
                            errno.EINVAL)

        """
        Initialize state to "JOINING" until after booted.
        """
        if not await self.middleware.call('system.ready'):
            await self.set_state(DSStatus['JOINING'])
            return True

        try:
            await asyncio.wait_for(self.middleware.call('ldap.get_root_DSE', ldap),
                                   timeout=ldap['timeout'])
        except asyncio.TimeoutError:
            raise CallError(f'LDAP status check timed out after {ldap["timeout"]} seconds.', errno.ETIMEDOUT)

        except CallError:
            raise
        except Exception as e:
            raise CallError(e)

        try:
            cached_state = await self.middleware.call('cache.get', 'DS_STATE')

            if cached_state['ldap'] != 'HEALTHY':
                await self.set_state(DSStatus['HEALTHY'])
        except KeyError:
            await self.set_state(DSStatus['HEALTHY'])

        return True

    @private
    async def get_workgroup(self, ldap=None):
        ret = None
        smb = await self.middleware.call('smb.config')
        if ldap is None:
            ldap = await self.config()

        try:
            ret = await asyncio.wait_for(self.middleware.call('ldap.get_samba_domains', ldap),
                                         timeout=ldap['timeout'])
        except asyncio.TimeoutError:
            raise CallError(f'ldap.get_workgroup timed out after {ldap["timeout"]} seconds.', errno.ETIMEDOUT)

        if len(ret) > 1:
            self.logger.warning('Multiple Samba Domains detected in LDAP environment '
                                'auto-configuration of workgroup map have failed: %s', ret)

        ret = ret[0]['data']['sambaDomainName'][0] if ret else []

        if ret and smb['workgroup'] != ret:
            self.logger.debug(f'Updating SMB workgroup to match the LDAP domain name [{ret}]')
            await self.middleware.call('datastore.update', 'services.cifs', smb['id'], {'cifs_srv_workgroup': ret})

        return ret

    @private
    async def set_state(self, state):
        return await self.middleware.call('directoryservices.set_state', {'ldap': state.name})

    @accepts()
    async def get_state(self):
        """
        Wrapper function for 'directoryservices.get_state'. Returns only the state of the
        LDAP service.
        """
        return (await self.middleware.call('directoryservices.get_state'))['ldap']

    @private
    def get_nslcd_status(self):
        """
        Returns internal nslcd state. nslcd will preferentially use the first LDAP server,
        and only failover if the current LDAP server is unreachable.
        """
        with NslcdClient(NlscdConst.NSLCD_ACTION_STATE_GET.value) as ctx:
            while ctx.get_response() == NlscdConst.NSLCD_RESULT_BEGIN.value:
                nslcd_status = ctx.read_string()

        return nslcd_status

    @private
    async def nslcd_cmd(self, cmd):
        nslcd = await run(['service', 'nslcd', cmd], check=False)
        if nslcd.returncode != 0:
            raise CallError(f'nslcd failed to {cmd} with errror: {nslcd.stderr.decode()}', errno.EFAULT)

    @private
    async def nslcd_status(self):
        nslcd = await run(['service', 'nslcd', 'onestatus'], check=False)
        return True if nslcd.returncode == 0 else False

    @private
    async def start(self):
        """
        Refuse to start service if the service is alreading in process of starting or stopping.
        If state is 'HEALTHY' or 'FAULTED', then stop the service first before restarting it to ensure
        that the service begins in a clean state.
        """
        ldap = await self.config()

        ldap_state = await self.middleware.call('ldap.get_state')
        if ldap_state in ['LEAVING', 'JOINING']:
            raise CallError(f'LDAP state is [{ldap_state}]. Please wait until directory service operation completes.', errno.EBUSY)

        await self.middleware.call('datastore.update', self._config.datastore, ldap['id'], {'ldap_enable': True})
        if ldap['kerberos_realm']:
            await self.middleware.call('kerberos.start')

        await self.middleware.call('etc.generate', 'rc')
        await self.middleware.call('etc.generate', 'nss')
        await self.middleware.call('etc.generate', 'ldap')
        await self.middleware.call('etc.generate', 'pam')

        if not await self.nslcd_status():
            await self.nslcd_cmd('start')
        else:
            await self.nslcd_cmd('restart')

        if ldap['has_samba_schema']:
            await self.middleware.call('smb.initialize_globals')
            await self.synchronize()
            await self.middleware.call('idmap.synchronize')
            await self.middleware.call('smb.store_ldap_admin_password')
            await self.middleware.call('smb.set_passdb_backend', 'ldapsam')
            await self.middleware.call('idmap.synchronize')
            await self.middleware.call('service.restart', 'cifs')

        await self.set_state(DSStatus['HEALTHY'])
        await self.middleware.call('service.start', 'dscache')

    @private
    async def stop(self):
        ldap = await self.config()
        await self.middleware.call('datastore.update', self._config.datastore, ldap['id'], {'ldap_enable': False})
        await self.set_state(DSStatus['LEAVING'])
        await self.middleware.call('etc.generate', 'rc')
        await self.middleware.call('etc.generate', 'nss')
        await self.middleware.call('etc.generate', 'ldap')
        await self.middleware.call('etc.generate', 'pam')
        if ldap['has_samba_schema']:
            await self.synchronize()
            await self.middleware.call('idmap.synchronize')
            await self.middleware.call('service.restart', 'cifs')
            await self.middleware.call('smb.synchronize_passdb')
            await self.middleware.call('smb.synchronize_group_mappings')
        await self.middleware.call('smb.set_passdb_backend', 'tdbsam')
        await self.middleware.call('cache.pop', 'LDAP_cache')
        await self.middleware.call('service.stop', 'dscache')
        await self.nslcd_cmd('stop')
        await self.set_state(DSStatus['DISABLED'])

    @private
    async def ldap_to_registry(self, data):
        rv = {}
        if data['enable'] is False:
            return rv

        for k, v in DEFAULT_LDAP_PARAMETERS.items():
            if v is None:
                continue
            rv[k] = v

        uri_string = " ".join(data["uri_list"])
        rv.update({
            "passdb backend": f'ldapsam:"{uri_string}"',
            "ldap admin dn": data["binddn"],
            "ldap suffix": data["basedn"],
            "ldap ssl": "start tls" if data['ssl'] == "STARTTLS" else "off",
        })

        if data['kerberos_principal']:
            rv.update({"kerberos method": "system keytab"})

        return rv

    @private
    async def diff_conf_and_registry(self, data):
        smbconf = (await self.middleware.call('smb.reg_globals'))['ds']
        to_check = await self.ldap_to_registry(data)

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
    async def synchronize(self):
        conf = await self.config()
        diff = await self.diff_conf_and_registry(conf)
        await self.middleware.call('smb.reg_apply_conf_diff', diff)

    @private
    @job(lock='fill_ldap_cache')
    def fill_cache(self, job, force=False):
        user_next_index = group_next_index = 100000000
        cache_data = {'users': {}, 'groups': {}}

        if self.middleware.call_sync('cache.has_key', 'LDAP_cache') and not force:
            raise CallError('LDAP cache already exists. Refusing to generate cache.')

        self.middleware.call_sync('cache.pop', 'LDAP_cache')

        if (self.middleware.call_sync('ldap.config'))['disable_freenas_cache']:
            self.middleware.call_sync('cache.put', 'LDAP_cache', cache_data)
            self.logger.debug('LDAP cache is disabled. Bypassing cache fill.')
            return

        pwd_list = pwd.getpwall()
        grp_list = grp.getgrall()

        local_uid_list = list(u['uid'] for u in self.middleware.call_sync('user.query'))
        local_gid_list = list(g['gid'] for g in self.middleware.call_sync('group.query'))

        for u in pwd_list:
            is_local_user = True if u.pw_uid in local_uid_list else False
            if is_local_user:
                continue

            cache_data['users'].update({u.pw_name: {
                'id': user_next_index,
                'uid': u.pw_uid,
                'username': u.pw_name,
                'unixhash': None,
                'smbhash': None,
                'group': {},
                'home': '',
                'shell': '',
                'full_name': u.pw_gecos,
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
                'local': False
            }})
            user_next_index += 1

        for g in grp_list:
            is_local_user = True if g.gr_gid in local_gid_list else False
            if is_local_user:
                continue

            cache_data['groups'].update({g.gr_name: {
                'id': group_next_index,
                'gid': g.gr_gid,
                'group': g.gr_name,
                'builtin': False,
                'sudo': False,
                'sudo_nopasswd': False,
                'sudo_commands': [],
                'users': [],
                'local': False
            }})
            group_next_index += 1

        self.middleware.call_sync('cache.put', 'LDAP_cache', cache_data)
        self.middleware.call_sync('dscache.backup')

    @private
    async def get_cache(self):
        if not await self.middleware.call('cache.has_key', 'LDAP_cache'):
            await self.middleware.call('ldap.fill_cache')
            self.logger.debug('cache fill is in progress.')
            return {'users': {}, 'groups': {}}
        return await self.middleware.call('cache.get', 'LDAP_cache')
