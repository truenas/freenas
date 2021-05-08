import binascii
try:
    from bsd import acl
except ImportError:
    acl = None
import errno
import functools
import grp
import os
import pwd
import select
import shutil

import psutil
try:
    import pyinotify
except ImportError:
    pyinotify = None

from middlewared.main import EventSource
from middlewared.schema import Bool, Dict, Int, Ref, Str, accepts
from middlewared.service import private, CallError, Service, job
from middlewared.utils import filter_list, osc
from middlewared.utils.path import is_child
from middlewared.plugins.pwenc import PWENC_FILE_SECRET


class FilesystemService(Service):

    class Config:
        cli_namespace = 'storage.filesystem'

    @accepts(Str('path', required=True), Ref('query-filters'), Ref('query-options'))
    def listdir(self, path, filters, options):
        """
        Get the contents of a directory.

        Each entry of the list consists of:
          name(str): name of the file
          path(str): absolute path of the entry
          realpath(str): absolute real path of the entry (if SYMLINK)
          type(str): DIRECTORY | FILESYSTEM | SYMLINK | OTHER
          size(int): size of the entry
          mode(int): file mode/permission
          uid(int): user id of entry owner
          gid(int): group id of entry onwer
          acl(bool): extended ACL is present on file
        """
        if not os.path.exists(path):
            raise CallError(f'Directory {path} does not exist', errno.ENOENT)

        if not os.path.isdir(path):
            raise CallError(f'Path {path} is not a directory', errno.ENOTDIR)

        rv = []
        for entry in os.scandir(path):
            if entry.is_symlink():
                etype = 'SYMLINK'
            elif entry.is_dir():
                etype = 'DIRECTORY'
            elif entry.is_file():
                etype = 'FILE'
            else:
                etype = 'OTHER'

            data = {
                'name': entry.name,
                'path': entry.path,
                'realpath': os.path.realpath(entry.path) if etype == 'SYMLINK' else entry.path,
                'type': etype,
            }
            try:
                stat = entry.stat()
                data.update({
                    'size': stat.st_size,
                    'mode': stat.st_mode,
                    'acl': False if self.acl_is_trivial(data["realpath"]) else True,
                    'uid': stat.st_uid,
                    'gid': stat.st_gid,
                })
            except FileNotFoundError:
                data.update({'size': None, 'mode': None, 'acl': None, 'uid': None, 'gid': None})
            rv.append(data)
        return filter_list(rv, filters=filters or [], options=options or {})

    @accepts(Str('path'))
    def stat(self, path):
        """
        Return the filesystem stat(2) for a given `path`.
        """
        try:
            stat = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            raise CallError(f'Path {path} not found', errno.ENOENT)

        stat = {
            'size': stat.st_size,
            'mode': stat.st_mode,
            'uid': stat.st_uid,
            'gid': stat.st_gid,
            'atime': stat.st_atime,
            'mtime': stat.st_mtime,
            'ctime': stat.st_ctime,
            'dev': stat.st_dev,
            'inode': stat.st_ino,
            'nlink': stat.st_nlink,
        }

        try:
            stat['user'] = pwd.getpwuid(stat['uid']).pw_name
        except KeyError:
            stat['user'] = None

        try:
            stat['group'] = grp.getgrgid(stat['gid']).gr_name
        except KeyError:
            stat['group'] = None

        stat['acl'] = False if self.acl_is_trivial(path) else True

        return stat

    @private
    @accepts(
        Str('path'),
        Str('content', max_length=2048000),
        Dict(
            'options',
            Bool('append', default=False),
            Int('mode'),
        ),
    )
    def file_receive(self, path, content, options):
        """
        Simplified file receiving method for small files.

        `content` must be a base 64 encoded file content.
        """
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if options.get('append'):
            openmode = 'ab'
        else:
            openmode = 'wb+'
        with open(path, openmode) as f:
            f.write(binascii.a2b_base64(content))
        mode = options.get('mode')
        if mode:
            os.chmod(path, mode)
        if path == PWENC_FILE_SECRET:
            self.middleware.call_sync('pwenc.reset_secret_cache')
        return True

    @private
    @accepts(
        Str('path'),
        Dict(
            'options',
            Int('offset'),
            Int('maxlen'),
        ),
    )
    def file_get_contents(self, path, options):
        """
        Get contents of a file `path` in base64 encode.

        DISCLAIMER: DO NOT USE THIS FOR BIG FILES (> 500KB).
        """
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            if options.get('offset'):
                f.seek(options['offset'])
            data = binascii.b2a_base64(f.read(options.get('maxlen'))).decode().strip()
        return data

    @accepts(Str('path'))
    @job(pipes=["output"])
    async def get(self, job, path):
        """
        Job to get contents of `path`.
        """

        if not os.path.isfile(path):
            raise CallError(f'{path} is not a file')

        with open(path, 'rb') as f:
            await self.middleware.run_in_thread(shutil.copyfileobj, f, job.pipes.output.w)

    @accepts(
        Str('path'),
        Dict(
            'options',
            Bool('append', default=False),
            Int('mode'),
        ),
    )
    @job(pipes=["input"])
    async def put(self, job, path, options):
        """
        Job to put contents to `path`.
        """
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        if options.get('append'):
            openmode = 'ab'
        else:
            openmode = 'wb+'

        with open(path, openmode) as f:
            await self.middleware.run_in_thread(shutil.copyfileobj, job.pipes.input.r, f)

        mode = options.get('mode')
        if mode:
            os.chmod(path, mode)
        return True

    @accepts(Str('path'))
    def statfs(self, path):
        """
        Return stats from the filesystem of a given path.

        Raises:
            CallError(ENOENT) - Path not found
        """
        try:
            st = os.statvfs(path)
        except FileNotFoundError:
            raise CallError('Path not found.', errno.ENOENT)

        for partition in sorted(psutil.disk_partitions(), key=lambda p: len(p.mountpoint), reverse=True):
            if is_child(os.path.realpath(path), partition.mountpoint):
                break
        else:
            raise CallError('Unable to find mountpoint.')

        return {
            'flags': [],
            'fstype': partition.fstype,
            'source': partition.device,
            'dest': partition.mountpoint,
            'blocksize': st.f_frsize,
            'total_blocks': st.f_blocks,
            'free_blocks': st.f_bfree,
            'avail_blocks': st.f_bavail,
            'files': st.f_files,
            'free_files': st.f_ffree,
            'name_max': st.f_namemax,
            'fsid': [],
            'total_bytes': st.f_blocks * st.f_frsize,
            'free_bytes': st.f_bfree * st.f_frsize,
            'avail_bytes': st.f_bavail * st.f_frsize,
        }

    @accepts(Str('path'))
    def acl_is_trivial(self, path):
        """
        Returns True if the ACL can be fully expressed as a file mode without losing
        any access rules, or if the path does not support NFSv4 ACLs (for example
        a path on a tmpfs filesystem).
        """
        if not os.path.exists(path):
            raise CallError(f'Path not found [{path}].', errno.ENOENT)

        if osc.IS_LINUX:
            acl = self.middleware.call_sync('filesystem.getacl', path, True)
            return acl['trivial']

        if not os.pathconf(path, 64):
            return True

        return acl.ACL(file=path).is_trivial


class FileFollowTailEventSource(EventSource):

    """
    Retrieve last `no_of_lines` specified as an integer argument for a specific `path` and then
    any new lines as they are added. Specified argument has the format `path:no_of_lines` ( `/var/log/messages:3` ).

    `no_of_lines` is optional and if it is not specified it defaults to `3`.

    However `path` is required for this.
    """

    def run_sync(self):
        if ':' in self.arg:
            path, lines = self.arg.rsplit(':', 1)
            lines = int(lines)
        else:
            path = self.arg
            lines = 3
        if not os.path.exists(path):
            # FIXME: Error?
            return

        bufsize = 8192
        fsize = os.stat(path).st_size
        if fsize < bufsize:
            bufsize = fsize
        i = 0
        with open(path, encoding='utf-8', errors='ignore') as f:
            data = []
            while True:
                i += 1
                if bufsize * i > fsize:
                    break
                f.seek(fsize - bufsize * i)
                data.extend(f.readlines())
                if len(data) >= lines or f.tell() == 0:
                    break

            self.send_event('ADDED', fields={'data': ''.join(data[-lines:])})
            f.seek(fsize)

            if osc.IS_FREEBSD:
                gen = self._follow_freebsd(f)
            else:
                gen = self._follow_linux(path, f)

            for data in gen:
                self.send_event('ADDED', fields={'data': data})

    def _follow_freebsd(self, f):
        kqueue = select.kqueue()

        ev = [select.kevent(
            f.fileno(),
            filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
            fflags=select.KQ_NOTE_DELETE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_WRITE | select.KQ_NOTE_ATTRIB,
        )]
        kqueue.control(ev, 0, 0)

        while not self._cancel_sync.is_set():
            events = kqueue.control([], 1, 1)
            if not events:
                continue
            # TODO: handle other file operations other than just extend/write
            yield f.read()

    def _follow_linux(self, path, f):
        queue = []
        watch_manager = pyinotify.WatchManager()
        notifier = pyinotify.Notifier(watch_manager)
        watch_manager.add_watch(path, pyinotify.IN_MODIFY, functools.partial(self._follow_linux_callback, queue, f))

        data = f.read()
        if data:
            yield data

        while not self._cancel_sync.is_set():
            notifier.process_events()

            data = "".join(queue)
            if data:
                yield data
            queue[:] = []

            if notifier.check_events():
                notifier.read_events()

        notifier.stop()

    def _follow_linux_callback(self, queue, f, event):
        data = f.read()
        if data:
            queue.append(data)


def setup(middleware):
    middleware.register_event_source('filesystem.file_tail_follow', FileFollowTailEventSource)
