from samba.samba3 import libsmb_samba_internal as libsmb
from samba.dcerpc import security
from samba.samba3 import param as s3param
from samba import credentials
import subprocess
# from samba import NTSTATUSError


class SMB(object):
    """
    Python implementation of basic SMB operations for protocol testing.
    This provides sufficient functionality to connect to remote SMB share,
    create and delete files, read, write, and list, make, and remove
    directories.

    Basic workflow can be something like this:

    c = SMB.connect(<ip address>, <share>, <username>, <password>)
    c.mkdir("testdir")
    fh = c.create_file("testdir/testfile")
    c.write(fh, b"Test base stream")
    fh2 = c.create_file("testdir/testfile:stream")
    c.write(fh, b"Test alternate data stream")
    c.read(fh)
    c.read(fh2)
    c.close(fh, True)
    c.ls("testdir")
    c.disconnect()
    """
    def __init__(self, **kwargs):
        self._connection = None
        self._open_files = {}
        self._cred = None
        self._lp = None
        self._user = None
        self._share = None
        self._host = None
        self._smb1 = False

    def connect(self, **kwargs):
        host = kwargs.get("host")
        share = kwargs.get("share")
        username = kwargs.get("username")
        password = kwargs.get("password")
        smb1 = kwargs.get("smb1", False)

        self._lp = s3param.get_context()
        self._lp.load_default()
        self._cred = credentials.Credentials()
        self._cred.guess(self._lp)

        if username is not None:
            self._cred.set_username(username)
        if password is not None:
            self._cred.set_password(password)

        self._host = host
        self._share = share
        self._smb1 = smb1
        self._connection = libsmb.Conn(
            host,
            share,
            self._lp,
            self._cred,
            force_smb1=smb1,
        )

    def disconnect(self):
        open_files = list(self._open_files.keys())
        for f in open_files:
            self.close(f)

        del(self._connection)
        del(self._cred)
        del(self._lp)

    def show_connection(self):
        return {
            "connected": True if self._connection is not None else False,
            "host": self._host,
            "share": self._share,
            "smb1": self._smb1,
            "username": self._user,
            "open_files": self._open_files,
        }

    def mkdir(self, path):
        return self._connection.mkdir(path)

    def rmdir(self, path):
        return self._connection.rmdir(path)

    def ls(self, path):
        return self._connection.list(path)

    def create_file(self, file, mode, attributes=None, do_create=False):
        dosmode = 0
        f = None
        for char in str(attributes):
            if char == "h":
                dosmode += libsmb.FILE_ATTRIBUTE_HIDDEN
            elif char == "r":
                dosmode += libsmb.FILE_ATTRIBUTE_READONLY
            elif char == "s":
                dosmode += libsmb.FILE_ATTRIBUTE_SYSTEM
            elif char == "a":
                dosmode += libsmb.FILE_ATTRIBUTE_ARCHIVE

        if mode == "r":
            f = self._connection.create(
                file,
                CreateDisposition=1 if not do_create else 3,
                DesiredAccess=security.SEC_GENERIC_READ,
                FileAttributes=dosmode,
            )
        elif mode == "w":
            f = self._connection.create(
                file,
                CreateDisposition=3,
                DesiredAccess=security.SEC_GENERIC_ALL,
                FileAttributes=dosmode,
            )

        self._open_files[f] = {
            "filename": file,
            "fh": f,
            "mode": mode,
            "attributes": dosmode
        }
        return f

    def close(self, idx, delete=False):
        if delete:
            self._connection.delete_on_close(
                self._open_files[idx]["fh"],
                True
            )
        self._connection.close(self._open_files[idx]["fh"])
        self._open_files.pop(idx)
        return self._open_files

    def read(self, idx=0, offset=0, cnt=1024):
        return self._connection.read(
            self._open_files[idx]["fh"], offset, cnt
        )

    def write(self, idx=0, data=None, offset=0):
        return self._connection.write(
            self._open_files[idx]["fh"], data, offset
        )

    def _parse_quota(self, quotaout):
        ret = []
        for entry in quotaout:
            e = entry.split(":")
            if len(e) != 2:
                continue

            user = e[0].strip()
            used, soft, hard = e[1].split("/")

            ret.append({
                "user": user,
                "used": int(used.strip()),
                "soft_limit": int(soft.strip()) if soft.strip() != "NO LIMIT" else None,
                "hard_limit": int(hard.strip()) if hard.strip() != "NO LIMIT" else None,
            })

        return ret

    def get_quota(self, **kwargs):
        host = kwargs.get("host")
        share = kwargs.get("share")
        username = kwargs.get("username")
        password = kwargs.get("password")
        do_list = kwargs.get("list")
        smb1 = kwargs.get("smb1", False)

        cmd = [
            "smbcquotas", f"//{host}/{share}",
            "-U", f"{username}%{password}",
        ]
        if do_list:
            cmd.append("-L")

        if smb1:
            cmd.extend(["-m", "NT1"])

        smbcquotas = subprocess.run(cmd, capture_output=True)
        quotaout = smbcquotas.stdout.decode().splitlines()
        return self._parse_quota(quotaout)

    def set_quota(self, **kwargs):
        host = kwargs.get("host")
        share = kwargs.get("share")
        username = kwargs.get("username")
        password = kwargs.get("password")
        target = kwargs.get("target")
        hard_limit = kwargs.get("hardlimit", 0)
        soft_limit = kwargs.get("softlimit", 0)
        smb1 = kwargs.get("smb1", False)

        cmd = [
            "smbcquotas", f"//{host}/{share}",
            "-S", f"UQLIM:{target}:{soft_limit}/{hard_limit}",
            "-U", f"{username}%{password}",
        ]
        if smb1:
            cmd.extend(["-m", "NT1"])

        smbcquotas = subprocess.run(cmd, capture_output=True)
        quotaout = smbcquotas.stdout.decode().splitlines()
        return self._parse_quota(quotaout)
