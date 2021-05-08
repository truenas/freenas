import enum
from middlewared.service import accepts, job, ServicePartBase
from middlewared.schema import Bool, Dict, Int, List, Str, UnixPerm
from middlewared.utils import osc

OS_TYPE_FREEBSD = 0x01
OS_TYPE_LINUX = 0x02
OS_FLAG = OS_TYPE_FREEBSD if osc.IS_FREEBSD else OS_TYPE_LINUX


class ACLType(enum.Enum):
    NFS4 = (OS_TYPE_FREEBSD, ['tag', 'id', 'perms', 'flags', 'type'])
    POSIX1E = (OS_TYPE_FREEBSD | OS_TYPE_LINUX, ['default', 'tag', 'id', 'perms'])

    def validate(self, theacl):
        errors = []
        ace_keys = self.value[1]
        if not self.value[0] & OS_FLAG:
            errors.append("The host operating system does not support"
                          f"ACLType [{self.name}]")

        if self != ACLType.NFS4 and theacl.get('nfs41flags'):
            errors.append(f"NFS41 ACL flags are not valid for ACLType [{self.name}]")

        for idx, entry in enumerate(theacl['dacl']):
            extra = set(entry.keys()) - set(ace_keys)
            missing = set(ace_keys) - set(entry.keys())
            if osc.IS_FREEBSD:
                if extra:
                    errors.append(f"ACL entry [{idx}] contains invalid extra key(s): {extra}")
                if missing:
                    errors.append(f"ACL entry [{idx}] is missing required keys(s): {missing}")
            else:
                if extra:
                    errors.append(
                        (idx, f"ACL entry contains invalid extra key(s): {extra}")
                    )
                if missing:
                    errors.append(
                        (idx, f"ACL entry is missing required keys(s): {missing}")
                    )

        return {"is_valid": len(errors) == 0, "errors": errors}


class ACLDefault(enum.Enum):
    NFS4_OPEN = {'visible': True, 'acl': [
        {
            'tag': 'owner@',
            'id': None,
            'perms': {'BASIC': 'FULL_CONTROL'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'group@',
            'id': None,
            'perms': {'BASIC': 'FULL_CONTROL'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'everyone@',
            'id': None,
            'perms': {'BASIC': 'MODIFY'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        }
    ]}
    NFS4_RESTRICTED = {'visible': True, 'acl': [
        {
            'tag': 'owner@',
            'id': None,
            'perms': {'BASIC': 'FULL_CONTROL'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'group@',
            'id': None,
            'perms': {'BASIC': 'MODIFY'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
    ]}
    NFS4_HOME = {'visible': True, 'acl': [
        {
            'tag': 'owner@',
            'id': None,
            'perms': {'BASIC': 'FULL_CONTROL'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'group@',
            'id': None,
            'perms': {'BASIC': 'MODIFY'},
            'flags': {'BASIC': 'NOINHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'everyone@',
            'id': None,
            'perms': {'BASIC': 'TRAVERSE'},
            'flags': {'BASIC': 'NOINHERIT'},
            'type': 'ALLOW'
        },
    ]}
    NFS4_DOMAIN_HOME = {'visible': False, 'acl': [
        {
            'tag': 'owner@',
            'id': None,
            'perms': {'BASIC': 'FULL_CONTROL'},
            'flags': {'BASIC': 'INHERIT'},
            'type': 'ALLOW'
        },
        {
            'tag': 'group@',
            'id': None,
            'perms': {'BASIC': 'MODIFY'},
            'flags': {
                'DIRECTORY_INHERIT': True,
                'INHERIT_ONLY': True,
                'NO_PROPAGATE_INHERIT': True
            },
            'type': 'ALLOW'
        },
        {
            'tag': 'everyone@',
            'id': None,
            'perms': {'BASIC': 'TRAVERSE'},
            'flags': {'BASIC': 'NOINHERIT'},
            'type': 'ALLOW'
        }
    ]}
    POSIX_OPEN = {'visible': True, 'acl': [
        {
            'default': True, 'tag': 'USER_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': True, 'tag': 'GROUP_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': True, 'tag': 'OTHER', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': False, 'tag': 'USER_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': False, 'tag': 'GROUP_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': False, 'tag': 'OTHER', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        }
    ]}
    POSIX_RESTRICTED = {'visible': True, 'acl': [
        {
            'default': True, 'tag': 'USER_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': True, 'tag': 'GROUP_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': True, 'tag': 'OTHER', 'id': -1,
            'perms': {"READ": False, "WRITE": False, "EXECUTE": False},
        },
        {
            'default': False, 'tag': 'USER_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': False, 'tag': 'GROUP_OBJ', 'id': -1,
            'perms': {"READ": True, "WRITE": True, "EXECUTE": True},
        },
        {
            'default': False, 'tag': 'OTHER', 'id': -1,
            'perms': {"READ": False, "WRITE": False, "EXECUTE": False},
        }
    ]}
    OPEN = NFS4_OPEN if osc.IS_FREEBSD else POSIX_OPEN
    RESTRICTED = NFS4_RESTRICTED if osc.IS_FREEBSD else POSIX_RESTRICTED
    HOME = NFS4_HOME if osc.IS_FREEBSD else POSIX_RESTRICTED

    def options():
        return list(ACLDefault.__members__.keys())


class ACLBase(ServicePartBase):

    @accepts(
        Dict(
            'filesystem_acl',
            Str('path', required=True),
            Int('uid', null=True, default=None),
            Int('gid', null=True, default=None),
            List(
                'dacl',
                items=[
                    Dict(
                        'aclentry',
                        Str('tag', enum=['owner@', 'group@', 'everyone@', 'USER', 'GROUP']),
                        Int('id', null=True),
                        Str('type', enum=['ALLOW', 'DENY']),
                        Dict(
                            'perms',
                            Bool('READ_DATA'),
                            Bool('WRITE_DATA'),
                            Bool('APPEND_DATA'),
                            Bool('READ_NAMED_ATTRS'),
                            Bool('WRITE_NAMED_ATTRS'),
                            Bool('EXECUTE'),
                            Bool('DELETE_CHILD'),
                            Bool('READ_ATTRIBUTES'),
                            Bool('WRITE_ATTRIBUTES'),
                            Bool('DELETE'),
                            Bool('READ_ACL'),
                            Bool('WRITE_ACL'),
                            Bool('WRITE_OWNER'),
                            Bool('SYNCHRONIZE'),
                            Str('BASIC', enum=['FULL_CONTROL', 'MODIFY', 'READ', 'TRAVERSE']),
                        ),
                        Dict(
                            'flags',
                            Bool('FILE_INHERIT'),
                            Bool('DIRECTORY_INHERIT'),
                            Bool('NO_PROPAGATE_INHERIT'),
                            Bool('INHERIT_ONLY'),
                            Bool('INHERITED'),
                            Str('BASIC', enum=['INHERIT', 'NOINHERIT']),
                        ),
                    ),
                    Dict(
                        'posix1e_ace',
                        Bool('default', default=False),
                        Str('tag', enum=['USER_OBJ', 'GROUP_OBJ', 'USER', 'GROUP', 'OTHER', 'MASK']),
                        Int('id', default=-1),
                        Dict(
                            'perms',
                            Bool('READ', default=False),
                            Bool('WRITE', default=False),
                            Bool('EXECUTE', default=False),
                        ),
                    )
                ],
            ),
            Dict(
                'nfs41_flags',
                Bool('AUTOINHERIT', default=False),
                Bool('PROTECTED', default=False),
            ),
            Str('acltype', enum=[x.name for x in ACLType], default=ACLType.NFS4.name),
            Dict(
                'options',
                Bool('stripacl', default=False),
                Bool('recursive', default=False),
                Bool('traverse', default=False),
                Bool('canonicalize', default=True)
            )
        )
    )
    @job(lock="perm_change")
    def setacl(self, job, data):
        """
        Set ACL of a given path. Takes the following parameters:
        `path` full path to directory or file.

        `dacl` ACL entries. Formatting depends on the underlying `acltype`. NFS4ACL requires
        NFSv4 entries. POSIX1e requires POSIX1e entries.

        `uid` the desired UID of the file user. If set to None (the default), then user is not changed.

        `gid` the desired GID of the file group. If set to None (the default), then group is not changed.

        `recursive` apply the ACL recursively

        `traverse` traverse filestem boundaries (ZFS datasets)

        `strip` convert ACL to trivial. ACL is trivial if it can be expressed as a file mode without
        losing any access rules.

        `canonicalize` reorder ACL entries so that they are in concanical form as described
        in the Microsoft documentation MS-DTYP 2.4.5 (ACL). This only applies to NFSv4 ACLs.

        For case of NFSv4 ACLs  USER_OBJ, GROUP_OBJ, and EVERYONE with owner@, group@, everyone@ for
        consistency with getfacl and setfacl. If one of aforementioned special tags is used, 'id' must
        be set to None.

        An inheriting empty everyone@ ACE is appended to non-trivial ACLs in order to enforce Windows
        expectations regarding permissions inheritance. This entry is removed from NT ACL returned
        to SMB clients when 'ixnas' samba VFS module is enabled.
        """

    @accepts(
        Str('path'),
        Bool('simplified', default=True),
    )
    def getacl(self, path, simplified):
        """
        Return ACL of a given path. This may return a POSIX1e ACL or a NFSv4 ACL. The acl type is indicated
        by the `ACLType` key.

        Errata about ACLType NFSv4:

        `simplified` returns a shortened form of the ACL permset and flags.

        `TRAVERSE` sufficient rights to traverse a directory, but not read contents.

        `READ` sufficient rights to traverse a directory, and read file contents.

        `MODIFIY` sufficient rights to traverse, read, write, and modify a file. Equivalent to modify_set.

        `FULL_CONTROL` all permissions.

        If the permisssions do not fit within one of the pre-defined simplified permissions types, then
        the full ACL entry will be returned.

        In all cases we replace USER_OBJ, GROUP_OBJ, and EVERYONE with owner@, group@, everyone@ for
        consistency with getfacl and setfacl. If one of aforementioned special tags is used, 'id' must
        be set to None.

        An inheriting empty everyone@ ACE is appended to non-trivial ACLs in order to enforce Windows
        expectations regarding permissions inheritance. This entry is removed from NT ACL returned
        to SMB clients when 'ixnas' samba VFS module is enabled. We also remove it here to avoid confusion.
        """

    @accepts(
        Dict(
            'filesystem_ownership',
            Str('path', required=True),
            Int('uid', null=True, default=None),
            Int('gid', null=True, default=None),
            Dict(
                'options',
                Bool('recursive', default=False),
                Bool('traverse', default=False)
            )
        )
    )
    @job(lock="perm_change")
    def chown(self, job, data):
        """
        Change owner or group of file at `path`.

        `uid` and `gid` specify new owner of the file. If either
        key is absent or None, then existing value on the file is not
        changed.

        `recursive` performs action recursively, but does
        not traverse filesystem mount points.

        If `traverse` and `recursive` are specified, then the chown
        operation will traverse filesystem mount points.
        """

    @accepts(
        Dict(
            'filesystem_permission',
            Str('path', required=True),
            UnixPerm('mode', null=True),
            Int('uid', null=True, default=None),
            Int('gid', null=True, default=None),
            Dict(
                'options',
                Bool('stripacl', default=False),
                Bool('recursive', default=False),
                Bool('traverse', default=False),
            )
        )
    )
    @job(lock="perm_change")
    def setperm(self, job, data):
        """
        Remove extended ACL from specified path.

        If `mode` is specified then the mode will be applied to the
        path and files and subdirectories depending on which `options` are
        selected. Mode should be formatted as string representation of octal
        permissions bits.

        `uid` the desired UID of the file user. If set to None (the default), then user is not changed.

        `gid` the desired GID of the file group. If set to None (the default), then group is not changed.

        `stripacl` setperm will fail if an extended ACL is present on `path`,
        unless `stripacl` is set to True.

        `recursive` remove ACLs recursively, but do not traverse dataset
        boundaries.

        `traverse` remove ACLs from child datasets.

        If no `mode` is set, and `stripacl` is True, then non-trivial ACLs
        will be converted to trivial ACLs. An ACL is trivial if it can be
        expressed as a file mode without losing any access rules.

        """

    @accepts()
    async def default_acl_choices(self):
        """
        Get list of default ACL types.
        """

    @accepts(
        Str('acl_type', default='OPEN', enum=ACLDefault.options()),
        Str('share_type', default='NONE', enum=['NONE', 'AFP', 'SMB', 'NFS']),
    )
    async def get_default_acl(self, acl_type, share_type):
        """
        Returns a default ACL depending on the usage specified by `acl_type`.
        If an admin group is defined, then an entry granting it full control will
        be placed at the top of the ACL. Optionally may pass `share_type` to argument
        to get share-specific template ACL.
        """
