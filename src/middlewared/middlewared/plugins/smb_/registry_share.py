from middlewared.service import private, Service, filterable
from middlewared.service_exception import CallError
from middlewared.utils import run, filter_list
from middlewared.plugins.smb import SMBCmd, SMBHAMODE, SMBSharePreset
from middlewared.utils import osc

import errno

FRUIT_CATIA_MAPS = [
    "0x01:0xf001,0x02:0xf002,0x03:0xf003,0x04:0xf004",
    "0x05:0xf005,0x06:0xf006,0x07:0xf007,0x08:0xf008",
    "0x09:0xf009,0x0a:0xf00a,0x0b:0xf00b,0x0c:0xf00c",
    "0x0d:0xf00d,0x0e:0xf00e,0x0f:0xf00f,0x10:0xf010",
    "0x11:0xf011,0x12:0xf012,0x13:0xf013,0x14:0xf014",
    "0x15:0xf015,0x16:0xf016,0x17:0xf017,0x18:0xf018",
    "0x19:0xf019,0x1a:0xf01a,0x1b:0xf01b,0x1c:0xf01c",
    "0x1d:0xf01d,0x1e:0xf01e,0x1f:0xf01f",
    "0x22:0xf020,0x2a:0xf021,0x3a:0xf022,0x3c:0xf023",
    "0x3e:0xf024,0x3f:0xf025,0x5c:0xf026,0x7c:0xf027"
]


class SharingSMBService(Service):

    class Config:
        namespace = 'sharing.smb'

    @private
    async def netconf(self, **kwargs):
        """
        wrapper for net(8) conf. This manages the share configuration, which is stored in
        samba's registry.tdb file.
        """
        action = kwargs.get('action')
        if action not in [
            'listshares',
            'showshare',
            'addshare',
            'delshare',
            'getparm',
            'setparm',
            'delparm'
        ]:
            raise CallError(f'Action [{action}] is not permitted.', errno.EPERM)

        ha_mode = SMBHAMODE[(await self.middleware.call('smb.get_smb_ha_mode'))]
        if ha_mode == SMBHAMODE.CLUSTERED:
            ctdb_healthy = await self.middleware.call('ctdb.general.healthy')
            if not ctdb_healthy:
                raise CallError(
                    "Registry calls not permitted when ctdb unhealthy.", errno.ENXIO
                )

        share = kwargs.get('share')
        args = kwargs.get('args', [])
        cmd = [SMBCmd.NET.value, 'conf', action]

        if share:
            cmd.append(share)

        if args:
            cmd.extend(args)

        netconf = await run(cmd, check=False)
        if netconf.returncode != 0:
            if action != 'getparm':
                self.logger.debug('netconf failure for command [%s] stdout: %s',
                                  cmd, netconf.stdout.decode())
            raise CallError(
                f'net conf {action} [{share}] failed with error: {netconf.stderr.decode()}'
            )

        return netconf.stdout.decode()

    @private
    async def reg_listshares(self):
        return (await self.netconf(action='listshares')).splitlines()[1:]

    @private
    async def reg_addshare(self, data):
        conf = await self.share_to_smbconf(data)
        path = conf.pop('path')
        name = 'homes' if data['home'] else data['name']
        await self.netconf(
            action='addshare',
            share=name,
            args=[path, f'writeable={"N" if data["ro"] else "y"}',
                  f'guest_ok={"y" if data["guestok"] else "N"}']
        )
        for k, v in conf.items():
            await self.reg_setparm(name, k, v)

    @private
    async def reg_delshare(self, share):
        return await self.netconf(action='delshare', share=share)

    @private
    async def reg_showshare(self, share):
        ret = {}
        to_list = ['vfs objects', 'hosts allow', 'hosts deny']
        net = await self.netconf(action='showshare', share=share)
        for param in net.splitlines()[1:]:
            kv = param.strip().split('=', 1)
            k = kv[0].strip()
            v = kv[1].strip()
            ret[k] = v if k not in to_list else v.split()

        return ret

    @private
    async def reg_setparm(self, share, parm, value):
        if type(value) == list:
            value = ' '.join(value)
        return await self.netconf(action='setparm', share=share, args=[parm, value])

    @private
    async def reg_delparm(self, share, parm):
        return await self.netconf(action='delparm', share=share, args=[parm])

    @private
    async def reg_getparm(self, share, parm):
        to_list = ['vfs objects', 'hosts allow', 'hosts deny']
        try:
            ret = (await self.netconf(action='getparm', share=share, args=[parm])).strip()
        except CallError as e:
            if f"Error: given parameter '{parm}' is not set." in e.errmsg:
                # Copy behavior of samba python binding
                return None
            else:
                raise

        return ret.split() if parm in to_list else ret

    @private
    async def get_global_params(self, globalconf):
        if globalconf is None:
            globalconf = {}

        gl = {}
        gl.update({
            'fruit_enabled': globalconf.get('fruit_enabled', None),
            'ad_enabled': globalconf.get('ad_enabled', None),
            'afp_shares': globalconf.get('afp_shares', None),
            'nfs_exports': globalconf.get('nfs_exports', None),
            'smb_shares': globalconf.get('smb_shares', None)
        })
        if gl['afp_shares'] is None:
            gl['afp_shares'] = await self.middleware.call('sharing.afp.query', [['enabled', '=', True]])
        if gl['nfs_exports'] is None:
            gl['nfs_exports'] = await self.middleware.call('sharing.nfs.query', [['enabled', '=', True]])
        if gl['smb_shares'] is None:
            gl['smb_shares'] = await self.middleware.call('sharing.smb.query', [['enabled', '=', True]])
            for share in gl['smb_shares']:
                await self.middleware.call('sharing.smb.strip_comments', share)

        if gl['ad_enabled'] is None:
            gl['ad_enabled'] = (await self.middleware.call('activedirectory.config'))['enable']

        if gl['fruit_enabled'] is None:
            gl['fruit_enabled'] = (await self.middleware.call('smb.config'))['aapl_extensions']

        return gl

    @private
    async def order_vfs_objects(self, vfs_objects):
        vfs_objects_special = ('catia', 'zfs_space', 'fruit', 'streams_xattr', 'shadow_copy_zfs',
                               'noacl', 'ixnas', 'acl_xattr', 'zfsacl', 'crossrename', 'recycle',
                               'zfs_core', 'glusterfs', 'aio_fbsd', 'io_uring')

        vfs_objects_ordered = []

        if 'fruit' in vfs_objects:
            if 'streams_xattr' not in vfs_objects:
                vfs_objects.append('streams_xattr')

        if 'noacl' in vfs_objects:
            if 'ixnas' in vfs_objects:
                vfs_objects.remove('ixnas')

        for obj in vfs_objects:
            if obj not in vfs_objects_special:
                vfs_objects_ordered.append(obj)

        for obj in vfs_objects_special:
            if obj in vfs_objects:
                vfs_objects_ordered.append(obj)

        return vfs_objects_ordered

    @private
    async def diff_middleware_and_registry(self, share, data):
        if share is None:
            raise CallError('Share name must be specified.')

        if data is None:
            data = await self.middleware.call('sharing.smb.query', [('name', '=', share)], {'get': True})

        await self.middleware.call('sharing.smb.strip_comments', data)
        share_conf = await self.share_to_smbconf(data)
        try:
            reg_conf = await self.reg_showshare(share if not data['home'] else 'homes')
        except Exception:
            return None

        s_keys = set(share_conf.keys())
        r_keys = set(reg_conf.keys())
        intersect = s_keys.intersection(r_keys)
        return {
            'added': {x: share_conf[x] for x in s_keys - r_keys},
            'removed': {x: reg_conf[x] for x in r_keys - s_keys},
            'modified': {x: (share_conf[x], reg_conf[x]) for x in intersect if share_conf[x] != reg_conf[x]},
        }

    @private
    async def apply_conf_registry(self, share, diff):
        for k, v in diff['added'].items():
            await self.reg_setparm(share, k, v)

        for k, v in diff['removed'].items():
            await self.reg_delparm(share, k)

        for k, v in diff['modified'].items():
            await self.reg_setparm(share, k, v[0])

    @private
    async def apply_conf_diff(self, target, share, confdiff):
        self.logger.trace('target: [%s], share: [%s], diff: [%s]',
                          target, share, confdiff)
        if target not in ['REGISTRY', 'FNCONF']:
            raise CallError(f'Invalid target: [{target}]', errno.EINVAL)

        if target == 'FNCONF':
            # TODO: add ability to convert the registry back to our sqlite table
            raise CallError('FNCONF target not implemented')

        return await self.apply_conf_registry(share, confdiff)

    @private
    async def add_multiprotocol_conf(self, conf, gl, data):
        nfs_path_list = []
        for export in gl['nfs_exports']:
            nfs_path_list.extend(export['paths'])

        if any(filter(lambda x: f"{conf['path']}/" in f"{x}/", nfs_path_list)):
            self.logger.debug("SMB share [%s] is also an NFS export. "
                              "Applying parameters for mixed-protocol share.", data['name'])
            conf.update({
                "strict locking": "yes",
                "posix locking": "yes",
                "level2 oplocks": "no",
                "oplocks": "no"
            })
            if data['durablehandle']:
                self.logger.warn("Disabling durable handle support on SMB share [%s] "
                                 "due to NFS export of same path.", data['name'])
                await self.middleware.call('datastore.update', 'sharing.cifs_share',
                                           data['id'], {'cifs_durablehandle': False})
                data['durablehandle'] = False

        if any(filter(lambda x: f"{x['path']}/" in f"{conf['path']}/" or f"{conf['path']}/" in f"{x['path']}/", gl['afp_shares'])):
            self.logger.debug("SMB share [%s] is also an AFP share. "
                              "Applying parameters for mixed-protocol share.", data['name'])
            conf.update({
                "fruit:locking": "netatalk",
                "fruit:metadata": "netatalk",
                "fruit:resource": "file",
                "strict locking": "auto",
                "streams_xattr:prefix": "user.",
                "streams_xattr:store_stream_type": "no"
            })

    @private
    @filterable
    async def registry_query(self, filters, options):
        """
        Filterable method for querying SMB shares from the registry
        config. Can be reverted back to registry / smb.conf without
        loss of information. This is necessary to provide consistent
        API for viewing samba's current running configuration, which
        is of particular importance with clustered registry shares.
        """
        try:
            reg_shares = await self.reg_listshares()
        except CallError:
            return []

        rv = []
        for idx, name in enumerate(reg_shares):
            reg_conf = await self.reg_showshare(name)
            is_home = name == "HOMES"
            reg_conf["name"] = "HOMES_SHARE" if is_home else name
            reg_conf["home"] = is_home
            parsed_conf = await self.smbconf_to_share(reg_conf)

            entry = {"id": idx + 1}
            entry.update(parsed_conf)
            rv.append(entry)

        return filter_list(rv, filters, options)

    @private
    async def smbconf_to_share(self, data):
        """
        Wrapper to convert registry share into approximation of
        normal API return for sharing.smb.query.
        Disabled and locked shares are not in samba's running
        configuration in registry.tdb and so we assume that this
        is not the case.
        """
        conf_in = data.copy()
        vfs_objects = conf_in.pop("vfs objects")
        ret = {
            "purpose": "NO_PRESET",
            "path": conf_in.pop("path"),
            "path_suffix": "",
            "home": conf_in.pop("home", False),
            "name": conf_in.pop("name"),
            "guestok": conf_in.pop("guest ok", "yes") == "yes",
            "browsable": conf_in.pop("browseable", "yes") == "yes",
            "hostsallow": conf_in.pop("hosts allow", []),
            "hostsdeny": conf_in.pop("hosts deny", []),
            "abe": conf_in.pop("access based share enumeration", False),
            "acl": True if "acl_xattr" in vfs_objects else False,
            "ro": conf_in.pop("read only", "yes") == "yes",
            "durable handle": conf_in.pop("posix locking", "yes") == "no",
            "streams": True if "streams_xattr" in vfs_objects else False,
            "timemachine": conf_in.pop("fruit:time machine", False),
            "recyclebin": True if "recycle" in vfs_objects else False,
            "cluster_volname": conf_in.pop("glusterfs: volume", ""),
            "fsrvp": False,
            "enabled": True,
            "locked": False,
            "shadowcopy": False,
            "aapl_name_mangling": True if "catia" in vfs_objects else False,
        }
        cluster_logfile = conf_in.pop("glusterfs: logfile", "")
        aux_list = [f"{k} = {v}" for k, v in conf_in.items()]
        ret["auxsmbconf"] = '\n'.join(aux_list)
        return ret

    @private
    async def share_to_smbconf(self, conf_in, globalconf=None):
        data = conf_in.copy()
        gl = await self.get_global_params(globalconf)
        await self.middleware.call('sharing.smb.strip_comments', data)
        conf = {}
        is_clustered = bool(data.get("cluster_volname", ""))

        if data['home'] and gl['ad_enabled']:
            data['path_suffix'] = '%D/%U'
        elif data['home'] and data['path']:
            data['path_suffix'] = '%U'

        if data['path']:
            conf['path'] = '/'.join([data['path'], data['path_suffix']]) if data['path_suffix'] else data['path']
        else:
            conf['path'] = ''

        if osc.IS_FREEBSD:
            data['vfsobjects'] = ['aio_fbsd']
        elif is_clustered:
            conf["glusterfs: volume"] = data["cluster_volname"]
            conf["glusterfs: logfile"] = f'/var/log/samba4/glusterfs-{data["cluster_volname"]}.log'
            data['vfsobjects'] = ['glusterfs', 'io_uring']
        else:
            data['vfsobjects'] = ['zfs_core', 'io_uring']

        if data['comment']:
            conf["comment"] = data['comment']
        if not data['browsable']:
            conf["browseable"] = "no"
        if data['abe']:
            conf["access based share enum"] = "yes"
        if data['hostsallow']:
            conf["hosts allow"] = data['hostsallow']
        if data['hostsdeny']:
            conf["hosts deny"] = data['hostsdeny']
        conf["read only"] = "yes" if data['ro'] else "no"
        conf["guest ok"] = "yes" if data['guestok'] else "no"

        if gl['fruit_enabled']:
            data['vfsobjects'].append('fruit')

        if data['acl']:
            if osc.IS_FREEBSD:
                data['vfsobjects'].append('ixnas')
            else:
                data['vfsobjects'].append('acl_xattr')
        elif osc.IS_FREEBSD:
            data['vfsobjects'].append('noacl')
        else:
            conf["nt acl support"] = "no"

        if data['recyclebin']:
            # crossrename is required for 'recycle' to work across sub-datasets
            # FIXME: crossrename imposes 20MB limit on filesize moves across mountpoints
            # This really needs to be addressed with a zfs-aware recycle bin.
            data['vfsobjects'].extend(['recycle', 'crossrename'])

        if data['shadowcopy'] or data['fsrvp']:
            data['vfsobjects'].append('shadow_copy_zfs')

        if data['durablehandle']:
            conf.update({
                "kernel oplocks": "no",
                "kernel share modes": "no",
                "posix locking": "no",
            })

        if data['fsrvp']:
            data['vfsobjects'].append('zfs_fsrvp')
            conf.update({
                "shadow:ignore_empty_snaps": "false",
                "shadow:include": "fss-*",
            })

        conf.update({
            "nfs4:chown": "true",
            "ea support": "false",
        })

        if data['aapl_name_mangling']:
            data['vfsobjects'].append('catia')
            if gl['fruit_enabled']:
                conf.update({
                    'fruit:encoding': 'native',
                    'mangled names': 'no'
                })
            else:
                conf.update({
                    'catia:mappings': ','.join(FRUIT_CATIA_MAPS),
                    'mangled names': 'no'
                })

        if data['purpose'] == 'ENHANCED_TIMEMACHINE':
            data['vfsobjects'].append('tmprotect')
        elif data['purpose'] == 'WORM_DROPBOX':
            data['vfsobjects'].append('worm')

        if data['streams']:
            data['vfsobjects'].append('streams_xattr')

        conf["vfs objects"] = await self.order_vfs_objects(data['vfsobjects'])

        if gl['fruit_enabled']:
            conf["fruit:metadata"] = "stream"
            conf["fruit:resource"] = "stream"

        if conf["path"]:
            await self.add_multiprotocol_conf(conf, gl, data)

        if data['timemachine']:
            conf["fruit:time machine"] = "yes"
            conf["fruit:locking"] = "none"

        if data['recyclebin']:
            conf.update({
                "recycle:repository": ".recycle/%D/%U" if gl['ad_enabled'] else ".recycle/%U",
                "recycle:keeptree": "yes",
                "recycle:versions": "yes",
                "recycle:touch": "yes",
                "recycle:directory_mode": "0777",
                "recycle:subdir_mode": "0700"
            })

        if not data['auxsmbconf']:
            data['auxsmbconf'] = (SMBSharePreset[data["purpose"]].value)["params"]["auxsmbconf"]

        for param in data['auxsmbconf'].splitlines():
            if not param.strip():
                continue
            try:
                auxparam, val = param.split('=', 1)
                """
                vfs_fruit must be added to all shares if fruit is enabled.
                Support for SMB2 AAPL extensions is determined on first tcon
                to server, and so if they aren't appended to any vfs objects
                overrides via auxiliary parameters, then users may experience
                unexpected behavior.
                """
                if auxparam.strip() == "vfs objects" and gl['fruit_enabled']:
                    vfsobjects = val.strip().split()
                    vfsobjects.append('fruit')
                    conf['vfs objects'] = await self.order_vfs_objects(vfsobjects)
                else:
                    conf[auxparam.strip()] = val.strip()
            except Exception:
                self.logger.debug("[%s] contains invalid auxiliary parameter: [%s]",
                                  data['name'], param)

        return conf
