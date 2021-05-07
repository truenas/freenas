from middlewared.schema import Bool, Dict, Ref, Str
from middlewared.service import Service, accepts
from middlewared.plugins.smb import SMBCmd
from middlewared.utils import run, filter_list
import enum
import json


class InfoLevel(enum.Enum):
    AUTH_LOG = 'l'
    ALL = ''
    SESSIONS = 'p'
    SHARES = 'S'
    LOCKS = 'L'
    BYTERANGE = 'B'
    NOTIFICATIONS = 'N'


class SMBService(Service):

    class Config:
        service = 'cifs'
        service_verb = 'restart'

    @accepts(
        Str('info_level', enum=[x.name for x in InfoLevel], default=InfoLevel.ALL.name),
        Ref('query-filters'),
        Ref('query-options'),
        Dict('status_options',
             Bool('verbose', default=True),
             Bool('fast', default=False),
             Str('restrict_user', default=''),
             Str('restrict_session', default=''),
             )
    )
    async def status(self, info_level, filters, options, status_options):
        """
        Returns SMB server status (sessions, open files, locks, notifications).

        `info_level` type of information requests. Defaults to ALL.

        `status_options` additional options to filter query results. Supported
        values are as follows: `verbose` gives more verbose status output
        `fast` causes smbstatus to not check if the status data is valid by
        checking if the processes that the status data refer to all still
        exist. This speeds up execution on busy systems and clusters but
        might display stale data of processes that died without cleaning up
        properly. `restrict_user` specifies the limits results to the specified
        user.
        """
        lvl = InfoLevel[info_level]
        if lvl == InfoLevel.AUTH_LOG:
            ret = []
            try:
                with open("/var/log/samba4/auth_audit.log", "r") as f:
                    logfile_entries = f.read()
            except FileNotFoundError:
                self.logger.warning("SMB auth audit log does not exist "
                                    "this is expected if users have never "
                                    "authenticated to this server.")
                return ret

            for e in logfile_entries.splitlines():
                ret.append(json.loads(e.strip()))

            return filter_list(ret, filters, options)

        """
        Apply some optimizations for case where filter is only asking
        for a specific uid or session id.
        """
        if len(filters) == 1:
            to_check = filters[0][:2]
            if to_check == ["uid", "="]:
                status_options['restrict_user'] = str(filters[0][2])
                filters = []

            elif to_check == ["session_id", "="]:
                status_options['restrict_session'] = str(filters[0][2])
                filters = []

        flags = '-j'
        flags = flags + lvl.value
        flags = flags + 'v' if status_options['verbose'] else flags
        flags = flags + 'f' if status_options['fast'] else flags

        statuscmd = [SMBCmd.STATUS.value, '-d' '0', flags]

        if status_options['restrict_user']:
            statuscmd.extend(['-U', status_options['restrict_user']])

        if status_options['restrict_session']:
            statuscmd.extend(['-s', status_options['restrict_session']])

        smbstatus = await run(statuscmd, check=False)

        if smbstatus.returncode != 0:
            self.logger.debug('smbstatus [{%s}] failed with error: ({%s})',
                              flags, smbstatus.stderr.decode().strip())

        output = json.loads(smbstatus.stdout.decode())

        if lvl == InfoLevel.SESSIONS:
            output = output["sessions"]

        elif lvl == InfoLevel.LOCKS:
            output = output["locked_files"]

        elif lvl == InfoLevel.BYTERANGE:
            output = output["brl"]

        elif lvl == InfoLevel.NOTIFICATIONS:
            output = output["notify"]

        return filter_list(output, filters, options)

    async def client_count(self):
        """
        Return currently connected clients count.
        """
        return await self.middleware.call("smb.status", "SESSIONS", [], {"count": True}, {"fast": True})
