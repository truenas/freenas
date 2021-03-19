from middlewared.service import Service, job, private
from middlewared.service_exception import CallError
from middlewared.utils import run
from middlewared.plugins.smb import SMBCmd, SMBBuiltin, SMBPath

import os
import re

RE_NETGROUPMAP = re.compile(r"^(?P<ntgroup>.+) \((?P<SID>S-[0-9\-]+)\) -> (?P<unixgroup>.+)$")


class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    @private
    async def groupmap_list(self):
        groupmap = {}
        out = await run([SMBCmd.NET.value, 'groupmap', 'list'], check=False)
        if out.returncode != 0:
            raise CallError(f'groupmap list failed with error {out.stderr.decode()}')
        for line in (out.stdout.decode()).splitlines():
            m = RE_NETGROUPMAP.match(line)
            if m:
                entry = m.groupdict()
                groupmap[entry['unixgroup']] = entry

        return groupmap

    @private
    async def add_builtin_group(self, group):
        unixgroup = group
        ntgroup = group[8:].capitalize()
        sid = SMBBuiltin[ntgroup.upper()].value[1]
        gm_add = await run([
            SMBCmd.NET.value, '-d', '0', 'groupmap', 'add', f'sid={sid}',
            'type=builtin', f'unixgroup={unixgroup}', f'ntgroup={ntgroup}'],
            check=False
        )
        if gm_add.returncode != 0:
            raise CallError(
                f'Failed to generate groupmap for [{group}]: ({gm_add.stderr.decode()})'
            )

    @private
    async def groupmap_add(self, group, passdb_backend=None):
        """
        Map Unix group to NT group. This is required for group members to be
        able to access the SMB share. Name collisions with well-known and
        builtin groups must be avoided. Mapping groups with the same
        names as users should also be avoided.
        """
        if passdb_backend is None:
            passdb_backend = await self.middleware.call('smb.getparm', 'passdb backend', 'global')

        if passdb_backend != 'tdbsam':
            return

        if group in SMBBuiltin.unix_groups():
            return await self.add_builtin_group(group)

        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == 'CLUSTERED':
            """
            Remove this check once we have a reliable method of ensuring local groups
            are synchronized between nodes. SMB builtin groups are hard-coded and therefore safe
            to add. They are also required for SMB service to properly function.
            """
            self.logger.debug("Clustered groups not yet implemented in SCALE. "
                              "Skipping groupmap addition for %s.", group)
            return

        disallowed_list = ['USERS', 'ADMINISTRATORS', 'GUESTS']
        existing_groupmap = await self.groupmap_list()

        if existing_groupmap.get(group):
            self.logger.debug('Setting group map for %s is not permitted. '
                              'Entry already exists.', group)
            return False

        if group.upper() in disallowed_list:
            self.logger.debug('Setting group map for %s is not permitted. '
                              'Entry mirrors existing builtin groupmap.', group)
            return False

        next_rid = str(await self.middleware.call("smb.get_next_rid"))
        gm_add = await run(
            [SMBCmd.NET.value, '-d', '0', 'groupmap', 'add', 'type=local', f'rid={next_rid}', f'unixgroup={group}', f'ntgroup={group}'],
            check=False
        )
        if gm_add.returncode != 0:
            raise CallError(
                f'Failed to generate groupmap for [{group}]: ({gm_add.stderr.decode()})'
            )

    @private
    async def groupmap_delete(self, data):
        ntgroup = data.get("ntgroup")
        sid = data.get("sid")
        if not ntgroup and not sid:
            raise CallError("ntgroup or sid is required")

        if ntgroup:
            target = f"ntgroup={ntgroup}"
        elif sid:
            if sid.startswith("S-1-5-32"):
                self.logger.debug("Refusing to delete group mapping for BUILTIN group: %s", sid)
                return

            target = f"sid={sid}"

        gm_delete = await run(
            [SMBCmd.NET.value, '-d' '0', 'groupmap', 'delete', target], check=False
        )

        if gm_delete.returncode != 0:
            self.logger.debug(f'Failed to delete groupmap for [{target}]: ({gm_delete.stderr.decode()})')

    @private
    @job(lock="groupmap_sync")
    async def synchronize_group_mappings(self, job):
        if await self.middleware.call('ldap.get_state') != "DISABLED":
            return

        groupmap = await self.groupmap_list()
        must_remove_cache = False
        passdb_backend = await self.middleware.call('smb.getparm', 'passdb backend', 'global')

        if groupmap:
            sids_fixed = await self.middleware.call('smb.fixsid', groupmap.values())
            if not sids_fixed:
                groupmap = []

        for b in SMBBuiltin:
            entry = groupmap.get(b.value[0])
            if b.name == 'ADMINISTRATORS':
                if len(await self.middleware.call('group.query', [('gid', '=', 544)])) > 1:
                    # Creating an SMB administrators mapping for a duplicate ID is potentially a security issue.
                    self.logger.warn("Multiple groups have GID 544, switching allocation method for "
                                     "SMB Administrators [S-1-5-32-544] to internal winbind method.")
                    continue

            if not entry:
                stale_entry = list(filter(lambda x: b.name.lower().capitalize() == x['ntgroup'], groupmap.values()))
                if stale_entry:
                    must_remove_cache = True
                    await self.groupmap_delete({"ntgroup": b.name.lower().capitalize()})

                await self.groupmap_add(b.value[0], passdb_backend)

        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == 'CLUSTERED':
            """
            Remove this check once we have a reliable method of ensuring local groups
            are synchronized between nodes. SMB builtin groups are hard-coded and therefore safe
            to add. They are also required for SMB service to properly function.
            """
            self.logger.debug("Clustered groups not yet implemented in SCALE. "
                              "Skipping groupmap sychrnoization.")
            return

        groups = await self.middleware.call('group.query', [('builtin', '=', False), ('smb', '=', True)])
        for g in groups:
            if not groupmap.get(g['group']):
                await self.groupmap_add(g['group'], passdb_backend)

        if must_remove_cache:
            if os.path.exists(f'{SMBPath.STATEDIR.platform()}/winbindd_cache.tdb'):
                os.remove(f'{SMBPath.STATEDIR.platform()}/winbindd_cache.tdb')
            flush = await run([SMBCmd.NET.value, 'cache', 'flush'], check=False)
            if flush.returncode != 0:
                self.logger.debug('Attempt to flush cache failed: %s', flush.stderr.decode().strip())
