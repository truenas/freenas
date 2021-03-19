from middlewared.service import Service, job, private
from middlewared.service_exception import CallError
from middlewared.utils import Popen, run
from middlewared.plugins.smb import SMBCmd

import os
import subprocess
import time


class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    @private
    async def passdb_list(self, verbose=False):
        """
        passdb entries for local SAM database. This will be populated with
        local users in an AD environment. Immediately return in ldap enviornment.
        """
        pdbentries = []
        private_dir = await self.middleware.call('smb.getparm', 'privatedir', 'global')
        if not os.path.exists(f'{private_dir}/passdb.tdb'):
            return pdbentries

        if await self.middleware.call('smb.getparm', 'passdb backend', 'global') != 'tdbsam':
            return pdbentries

        if not verbose:
            pdb = await run([SMBCmd.PDBEDIT.value, '-L', '-d', '0'], check=False)
            if pdb.returncode != 0:
                raise CallError(f'Failed to list passdb output: {pdb.stderr.decode()}')
            for p in (pdb.stdout.decode()).splitlines():
                entry = p.split(':')
                try:
                    pdbentries.append({
                        'username': entry[0],
                        'full_name': entry[2],
                        'uid': entry[1],
                    })
                except Exception as e:
                    self.logger.debug('Failed to parse passdb entry [%s]: %s', p, e)

            return pdbentries

        pdb = await run([SMBCmd.PDBEDIT.value, '-Lv', '-d', '0'], check=False)
        if pdb.returncode != 0:
            raise CallError(f'Failed to list passdb output: {pdb.stderr.decode()}')

        for p in (pdb.stdout.decode()).split('---------------'):
            pdbentry = {}
            for entry in p.splitlines():
                parm = entry.split(':')
                if len(parm) != 2:
                    continue

                pdbentry.update({parm[0].rstrip(): parm[1].lstrip() if parm[1] else ''})

            if pdbentry:
                pdbentries.append(pdbentry)

        return pdbentries

    @private
    async def update_passdb_user(self, username, passdb_backend=None):
        """
        Updates a user's passdb entry to reflect the current server configuration.
        Accounts that are 'locked' in the UI will have their corresponding passdb entry
        disabled.
        """
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == "CLUSTERED":
            self.logger.debug("passdb support not yet implemented in clustered TrueNAS.")
            return

        if passdb_backend is None:
            passdb_backend = await self.middleware.call('smb.getparm',
                                                        'passdb backend',
                                                        'global')

        if passdb_backend != 'tdbsam':
            return

        bsduser = await self.middleware.call('user.query', [
            ('username', '=', username),
            ('smb', '=', True),
        ])
        if not bsduser:
            self.logger.debug(f'{username} is not an SMB user, bypassing passdb import')
            return

        smbpasswd_string = bsduser[0]['smbhash'].split(':')
        if len(smbpasswd_string) != 7:
            self.logger.warning("SMB hash for user [%s] is invalid. Authentication for SMB "
                                "sessions for this user will fail until this is repaired. "
                                "This may indicate that configuration was restored without a secret "
                                "seed, and may be repaired by resetting the user password.", username)
            return

        p = await run([SMBCmd.PDBEDIT.value, '-d', '0', '-Lw', username], check=False)
        if p.returncode != 0:
            CallError(f'Failed to retrieve passdb entry for {username}: {p.stderr.decode()}')
        entry = p.stdout.decode()
        if not entry:
            next_rid = str(await self.middleware.call('smb.get_next_rid'))
            self.logger.debug("User [%s] does not exist in the passdb.tdb file. "
                              "Creating entry with rid [%s].", username, next_rid)
            pdbcreate = await Popen(
                [SMBCmd.PDBEDIT.value, '-d', '0', '-a', username, '-U', next_rid, '-t'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
            )
            await pdbcreate.communicate(input=" \n \n".encode())
            setntpass = await run([SMBCmd.PDBEDIT.value, '-d', '0', '--set-nt-hash', smbpasswd_string[3], username], check=False)
            if setntpass.returncode != 0:
                raise CallError(f'Failed to set NT password for {username}: {setntpass.stderr.decode()}')
            if bsduser[0]['locked']:
                disableacct = await run([SMBCmd.SMBPASSWD.value, '-d', username], check=False)
                if disableacct.returncode != 0:
                    raise CallError(f'Failed to disable {username}: {disableacct.stderr.decode()}')
            return

        if entry == bsduser[0]['smbhash']:
            return

        """
        If an invalid global auxiliary parameter is present
        in the smb.conf, then pdbedit will write error messages
        to stdout (two for each invalid parameter, separated by \n).
        The last line of output in this case will be the passdb entry
        in smbpasswd format (-Lw). This is the reason why we pre-emptively
        splitlines() and use last element of resulting list for our checks.
        """
        entry = entry.splitlines()[-1]
        entry = entry.split(':')

        if smbpasswd_string[3] != entry[3]:
            setntpass = await run([SMBCmd.PDBEDIT.value, '-d', '0', '--set-nt-hash', smbpasswd_string[3], username], check=False)
            if setntpass.returncode != 0:
                raise CallError(f'Failed to set NT password for {username}: {setntpass.stderr.decode()}')
        if bsduser[0]['locked'] and 'D' not in entry[4]:
            disableacct = await run([SMBCmd.SMBPASSWD.value, '-d', username], check=False)
            if disableacct.returncode != 0:
                raise CallError(f'Failed to disable {username}: {disableacct.stderr.decode()}')
        elif not bsduser[0]['locked'] and 'D' in entry[4]:
            enableacct = await run([SMBCmd.SMBPASSWD.value, '-e', username], check=False)
            if enableacct.returncode != 0:
                raise CallError(f'Failed to enable {username}: {enableacct.stderr.decode()}')

    @private
    async def remove_passdb_user(self, username):
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == "CLUSTERED":
            self.logger.debug("passdb support not yet implemented in clustered TrueNAS.")
            return

        deluser = await run([SMBCmd.PDBEDIT.value, '-d', '0', '-x', username], check=False)
        if deluser.returncode != 0:
            raise CallError(f'Failed to delete user [{username}]: {deluser.stderr.decode()}')

    @private
    async def passdb_reinit(self, conf_users):
        """
        This method gets called if we need to rebuild passdb.tdb from scratch.
        Back up problematic version first to preserve collateral in case of regression.
        `conf_users` contains results of `user.query`. Since users will receive new
        SID values, we will need to flush samba's cache to ensure consistency.
        """
        private_dir = await self.middleware.call('smb.getparm',
                                                 'private dir',
                                                 'global')
        ts = int(time.time())
        old_path = f'{private_dir}/passdb.tdb'
        new_path = f'{private_dir}/passdb.{ts}.corrupted'
        os.rename(old_path, new_path)
        self.logger.debug("Backing up original passdb to [%s]", new_path)
        for u in conf_users:
            await self.middleware.call('smb.update_passdb_user', u['username'], 'tdbsam')

        net = await run([SMBCmd.NET.value, 'cache', 'flush'], check=False)
        if net.returncode != 0:
            self.logger.warning("Samba gencache flush failed with error: %s", net.stderr.decode())

    @private
    @job(lock="passdb_sync")
    async def synchronize_passdb(self, job):
        """
        Create any missing entries in the passdb.tdb.
        Replace NT hashes of users if they do not match what is the the config file.
        Synchronize the "disabled" state of users
        Delete any entries in the passdb_tdb file that don't exist in the config file.
        This method may cause temporary service disruption for SMB.
        """
        ha_mode = await self.middleware.call('smb.get_smb_ha_mode')
        if ha_mode == "CLUSTERED":
            self.logger.debug("passdb support not yet implemented in clustered TrueNAS.")
            return

        passdb_backend = await self.middleware.call('smb.getparm',
                                                    'passdb backend',
                                                    'global')

        if passdb_backend != 'tdbsam':
            return

        conf_users = await self.middleware.call('user.query', [("smb", "=", True)])
        for u in conf_users:
            await self.middleware.call('smb.update_passdb_user', u['username'], passdb_backend)

        pdb_users = await self.passdb_list()
        if len(pdb_users) > len(conf_users):
            for entry in pdb_users:
                if not any(filter(lambda x: entry['username'] == x['username'], conf_users)):
                    self.logger.debug('Synchronizing passdb with config file: deleting user [%s] from passdb.tdb', entry['username'])
                    try:
                        await self.remove_passdb_user(entry['username'])
                    except Exception:
                        self.logger.warning("Failed to remove passdb user. This may indicate a corrupted passdb. Regenerating.", exc_info=True)
                        await self.passdb_reinit(conf_users)
                        return
