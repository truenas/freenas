import errno
import json
import os
import subprocess
import stat as pystat
from pathlib import Path

from middlewared.service import private, CallError, ValidationErrors, Service
from middlewared.plugins.smb import SMBBuiltin
from .acl_base import ACLBase, ACLDefault, ACLType


class FilesystemService(Service, ACLBase):

    @private
    def acltool(self, path, action, uid, gid, options):

        flags = "-r"
        flags += "x" if options.get('traverse') else ""
        flags += "C" if options.get('do_chmod') else ""
        flags += "P" if options.get('posixacl') else ""

        acltool = subprocess.run([
            '/usr/bin/nfs4xdr_winacl',
            '-a', action,
            '-O', str(uid), '-G', str(gid),
            flags,
            '-c', path,
            '-p', path], check=False, capture_output=True
        )
        if acltool.returncode != 0:
            raise CallError(f"acltool [{action}] on path {path} failed with error: [{acltool.stderr.decode().strip()}]")

    def _common_perm_path_validate(self, schema, path, recursive, verrors):
        p = Path(path)
        if not p.is_absolute():
            verrors.add(f'{schema}.path', 'Must be an absolute path.')
            return

        if p.is_file() and recursive:
            verrors.add(f'{schema}.path', 'Recursive operations on a file are invalid.')
            return

        if not os.path.realpath(path).startswith('/mnt/'):
            verrors.add(
                f'{schema}.path',
                "Changes to permissions on paths that are not beneath "
                f"the directory /mnt are not permitted: {path}"
            )

        elif len(p.resolve().parents) == 2:
            verrors.add(
                f'{schema}.path',
                f'The specified path is a ZFS pool mountpoint "({path})" '
            )

        elif self.middleware.call_sync('pool.dataset.path_in_locked_datasets', path):
            verrors.add(
                f'{schema}.path',
                'Path component for is currently encrypted and locked'
            )

    def chown(self, job, data):
        job.set_progress(0, 'Preparing to change owner.')
        verrors = ValidationErrors()

        uid = -1 if data['uid'] is None else data.get('uid', -1)
        gid = -1 if data['gid'] is None else data.get('gid', -1)
        options = data['options']

        if uid == -1 and gid == -1:
            verrors.add("filesystem.chown.uid",
                        "Please specify either user or group to change.")

        self._common_perm_path_validate("filesystem.chown",
                                        data['path'],
                                        options.get('recursive', False),
                                        verrors)
        verrors.check()

        if not options['recursive']:
            job.set_progress(100, 'Finished changing owner.')
            os.chown(data['path'], uid, gid)
            return

        job.set_progress(10, f'Recursively changing owner of {data["path"]}.')
        options['posixacl'] = True
        self.acltool(data['path'], 'chown', uid, gid, options)
        job.set_progress(100, 'Finished changing owner.')

    def setperm(self, job, data):
        job.set_progress(0, 'Preparing to set permissions.')
        options = data['options']
        mode = data.get('mode', None)
        verrors = ValidationErrors()

        uid = -1 if data['uid'] is None else data.get('uid', -1)
        gid = -1 if data['gid'] is None else data.get('gid', -1)

        self._common_perm_path_validate("filesystem.setperm",
                                        data['path'],
                                        options.get('recursive', False),
                                        verrors)

        current_acl = self.middleware.call_sync('filesystem.getacl', data['path'])
        acl_is_trivial = current_acl['trivial']
        if not acl_is_trivial and not options['stripacl']:
            verrors.add(
                'filesystem.setperm.mode',
                f'Non-trivial ACL present on [{data["path"]}]. '
                'Option "stripacl" required to change permission.',
            )

        verrors.check()
        is_nfs4acl = current_acl['acltype'] == 'NFS4'

        if mode is not None:
            mode = int(mode, 8)

        setfaclcmd = 'nfs4xdr_setfacl' if is_nfs4acl else 'setfacl'

        stripacl = subprocess.run([setfaclcmd, '-b', data['path']],
                                  check=False, capture_output=True)
        if stripacl.returncode != 0:
            raise CallError(f"Failed to remove POSIX1e ACL from [{data['path']}]: "
                            f"{stripacl.stderr.decode()}")

        if mode:
            os.chmod(data['path'], mode)

        os.chown(data['path'], uid, gid)

        if not options['recursive']:
            job.set_progress(100, 'Finished setting permissions.')
            return

        action = 'clone' if mode else 'strip'
        job.set_progress(10, f'Recursively setting permissions on {data["path"]}.')
        options['posixacl'] = not is_nfs4acl
        options['do_chmod'] = True
        self.acltool(data['path'], action, uid, gid, options)
        job.set_progress(100, 'Finished setting permissions.')

    async def default_acl_choices(self):
        acl_choices = []
        for x in ACLDefault:
            if x.value['visible']:
                acl_choices.append(x.name)

        return acl_choices

    async def get_default_acl(self, acl_type, share_type):
        acl = []
        admin_group = (await self.middleware.call('smb.config'))['admin_group']
        if admin_group:
            acl.append({
                'default': True,
                'tag': 'GROUP',
                'id': (await self.middleware.call('dscache.get_uncached_group', admin_group))['gr_gid'],
                'perms': {'READ': True, 'WRITE': True, 'EXECUTE': True},
            })
        if share_type == 'SMB':
            acl.append({
                'default': True,
                'tag': 'GROUP',
                'id': int(SMBBuiltin['USERS'].value[1][9:]),
                'perms': {'READ': True, 'WRITE': True, 'EXECUTE': True},
            })
        acl.extend((ACLDefault[acl_type].value)['acl'])

        return acl

    @private
    def getacl_nfs4(self, path, simplified):
        flags = "-jn"
        if not simplified:
           flags += "v"

        getacl = subprocess.run(
            ['nfs4xdr_getfacl', flags, path],
            capture_output=True,
            check=False
        )
        if getacl.returncode != 0:
            raise CallError("Failed to get ACL for path [%s]: %s",
                            path, getacl.stderr.decode())

        output = json.loads(getacl.stdout.decode())
        for ace in output['acl']:
            ace['flags'].pop('SUCCESSFUL_ACCESS', None)
            ace['flags'].pop('FAILED_ACCESS', None)

        output['acltype'] = 'NFS4'
        return output

    @private
    def getacl_posix1e(self, path, simplified):
        st = os.stat(path)
        ret = {
            'uid': st.st_uid,
            'gid': st.st_gid,
            'acl': [],
            'flags': {
                'setuid': bool(st.st_mode & pystat.S_ISUID),
                'setgid': bool(st.st_mode & pystat.S_ISGID),
                'sticky': bool(st.st_mode & pystat.S_ISVTX),
            },
            'acltype': ACLType.POSIX1E.name
        }

        ret['uid'] = st.st_uid
        ret['gid'] = st.st_gid

        gfacl = subprocess.run(['getfacl', '-c', '-n', path],
                               check=False, capture_output=True)
        if gfacl.returncode != 0:
            raise CallError(f"Failed to get POSIX1e ACL on path [{path}]: {gfacl.stderr.decode()}")

        # linux output adds extra line to output if it's an absolute path and extra newline at end.
        entries = gfacl.stdout.decode().splitlines()
        entries = entries[:-1]

        for entry in entries:
            if entry.startswith("#"):
                continue
            ace = {
                "default": False,
                "tag": None,
                "id": -1,
                "perms": {
                    "READ": False,
                    "WRITE": False,
                    "EXECUTE": False,
                }
            }

            tag, id, perms = entry.rsplit(":", 2)
            ace['perms'].update({
                "READ": perms[0].casefold() == "r",
                "WRITE": perms[1].casefold() == "w",
                "EXECUTE": perms[2].casefold() == "x",
            })
            if tag.startswith('default'):
                ace['default'] = True
                tag = tag[8:]

            ace['tag'] = tag.upper()
            if id.isdigit():
                ace['id'] = int(id)
            elif ace['tag'] != 'OTHER':
                ace['tag'] += '_OBJ'

            ret['acl'].append(ace)

        ret['trivial'] = (len(ret['acl']) == 3)
        return ret

    def getacl(self, path, simplified):
        if not os.path.exists(path):
            raise CallError('Path not found.', errno.ENOENT)
        # Add explicit check for ACL type
        try:
            ret = self.getacl_nfs4(path, simplified)
        except CallError:
            ret = self.getacl_posix1e(path, simplified)

        return ret

    @private
    def setacl_nfs4(self, job, data):
        job.set_progress(0, 'Preparing to set acl.')
        verrors = ValidationErrors()
        options = data.get('options', {})
        recursive = options.get('recursive', False)
        do_strip = options.get('stripacl', False)

        path = data.get('path', '')
        uid = -1 if data['uid'] is None else data.get('uid', -1)
        gid = -1 if data['gid'] is None else data.get('gid', -1)

        self._common_perm_path_validate("filesystem.setacl",
                                        path, recursive,
                                        verrors)

        aclcheck = ACLType.NFS4.validate(data)
        if not aclcheck['is_valid']:
            for err in aclcheck['errors']:
                verrors.add(
                    'filesystem.setacl.dacl.{err[0]}', err[1]
                )

        if do_strip:
            stripacl = subprocess.run(
                ['nfs4xdr_setfacl', '-b', path],
                capture_output=True,
                check=False
            )
            if stripacl.returncode != 0:
                raise CallError("Failed to strip ACL on path: %s",
                                stripacl.stderr.decode())
        else:
            payload = {
                'acl': data['dacl'],
                'nfs41_flags': data['nfs41_flags']
            }
            json_payload = json.dumps(payload)
            setacl = subprocess.run(
                ['nfs4xdr_setfacl', '-j', json_payload, path],
                capture_output=True,
                check=False
            )
            """
            nfs4xr_setacl with JSON input will return validation
            errors on exit with EX_DATAERR (65).
            """
            if setacl.returncode == 65:
                err = setacl.stderr.decode()
                json_verrors = json.loads(err.split(None, 1)[1])
                raise CallError(json_verrors)
            elif setacl.returncode != 0:
                raise CallError(setacl.stderr.decode())

        if not recursive:
            os.chown(path, uid, gid);
            job.set_progress(100, 'Finished setting NFSv4 ACL.')
            return


        self.acltool(path, 'clone' if not do_strip else 'strip',
                     uid, gid, options)

        job.set_progress(100, 'Finished setting NFSv4 ACL.')

    @private
    def gen_aclstring_posix1e(self, dacl, recursive, verrors):
        """
        This method iterates through provided POSIX1e ACL and
        performs addtional validation before returning the ACL
        string formatted for the setfacl command. In case
        of ValidationError, None is returned.
        """
        has_tag = {
            "USER_OBJ": False,
            "GROUP_OBJ": False,
            "OTHER": False,
            "MASK": False,
            "DEF_USER_OBJ": False,
            "DEF_GROUP_OBJ": False,
            "DEF_OTHER": False,
            "DEF_MASK": False,
        }
        required_entries = ["USER_OBJ", "GROUP_OBJ", "OTHER"]
        has_named = False
        has_def_named = False
        has_default = False

        for idx, ace in enumerate(dacl):
            if idx == 0:
                aclstring = ""
            else:
                aclstring += ","

            if ace['id'] == -1:
                ace['id'] = ''

            who = "DEF_" if ace['default'] else ""
            who += ace['tag']
            duplicate_who = has_tag.get(who)

            if duplicate_who is True:
                verrors.add(
                    'filesystem.setacl.dacl.{idx}',
                    f'More than one {"default" if ace["default"] else ""} '
                    f'{ace["tag"]} entry is not permitted'
                )

            elif duplicate_who is False:
                has_tag[who] = True

            if ace['tag'] in ["USER", "GROUP"]:
                if ace['default']:
                    has_def_named = True
                else:
                    has_named = True

            ace['tag'] = ace['tag'].rstrip('_OBJ').lower()

            if ace['default']:
                has_default = True
                aclstring += "default:"

            aclstring += f"{ace['tag']}:{ace['id']}:"
            aclstring += 'r' if ace['perms']['READ'] else '-'
            aclstring += 'w' if ace['perms']['WRITE'] else '-'
            aclstring += 'x' if ace['perms']['EXECUTE'] else '-'

        if has_named and not has_tag['MASK']:
            verrors.add(
                'filesystem.setacl.dacl',
                'Named (user or group) POSIX ACL entries '
                'require a mask entry to be present in the ACL.'
            )

        elif has_def_named and not has_tag['DEF_MASK']:
            verrors.add(
                'filesystem.setacl.dacl',
                'Named default (user or group) POSIX ACL entries '
                'require a default mask entry to be present in the ACL.'
            )

        if recursive and not has_default:
            verrors.add(
                'filesystem.setacl.dacl',
                'Default ACL entries are required in order to apply '
                'ACL recursively.'
            )

        for entry in required_entries:
            if not has_tag[entry]:
                verrors.add(
                    'filesystem.setacl.dacl',
                    f'Presence of [{entry}] entry is required.'
                )

            if has_default and not has_tag[f"DEF_{entry}"]:
                verrors.add(
                    'filesystem.setacl.dacl',
                    f'Presence of default [{entry}] entry is required.'
                )

        return aclstring

    @private
    def setacl_posix1e(self, job, data):
        job.set_progress(0, 'Preparing to set acl.')
        verrors = ValidationErrors()
        options = data['options']
        recursive = options.get('recursive', False)
        do_strip = options.get('stripacl', False)
        dacl = data.get('dacl', [])
        path = data['path']
        uid = -1 if data['uid'] is None else data.get('uid', -1)
        gid = -1 if data['gid'] is None else data.get('gid', -1)

        self._common_perm_path_validate("filesystem.setacl",
                                        path, recursive,
                                        verrors)

        aclcheck = ACLType.POSIX1E.validate(data)
        if not aclcheck['is_valid']:
            for err in aclcheck['errors']:
                verrors.add(
                    'filesystem.setacl.dacl.{err[0]}', err[1]
                )

        if do_strip and dacl:
            verrors.add(
                'filesystem.setacl.dacl',
                'Simulatenously setting and removing ACL from path is invalid.'
            )

        if not do_strip:
            aclstring = self.gen_aclstring_posix1e(dacl, recursive, verrors)

        verrors.check()

        stripacl = subprocess.run(['setfacl', '-b', path],
                                  check=False, capture_output=True)
        if stripacl.returncode != 0:
            raise CallError(f"Failed to remove POSIX1e ACL from [{path}]: "
                            f"{stripacl.stderr.decode()}")

        job.set_progress(50, 'Setting POSIX1e ACL.')

        if not do_strip:
            setacl = subprocess.run(['setfacl', '-m', aclstring, path],
                                    check=False, capture_output=True)
            if setacl.returncode != 0:
                raise CallError(f'Failed to set ACL [{aclstring}] on path [{path}]: '
                                f'{setacl.stderr.decode()}')

        if not recursive:
            job.set_progress(100, 'Finished setting POSIX1e ACL.')
            return

        options['posixacl'] = True
        self.acltool(data['path'],
                     'clone' if not do_strip else 'strip',
                     uid, gid, options)

        job.set_progress(100, 'Finished setting POSIX1e ACL.')

    def setacl(self, job, data):
        acltype = ACLType[data['acltype']]
        if acltype == ACLType.NFS4:
            return self.setacl_nfs4(job, data)
        else:
            return self.setacl_posix1e(job, data)
