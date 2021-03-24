import socket
from urllib.parse import quote


class CTLDControl:
    socket = "/tmp/ctld.sock"

    def __init__(self):
        self.sock = None

    def open(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket)

    def close(self):
        self.sock.close()
        self.sock = None

    def cmd(self, command, id, args=[]):
        line = ' '.join([command, quote(id), *args])
        line = line.encode()

        if self.sock.send(line) != len(line):
            raise RuntimeError("Failed writing to socket")

        ret = self.sock.recv(4096)
        ret = ret.decode()

        if not ret.startswith("OK"):
            raise RuntimeError("ctld-control: {}".format(ret))

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def auth_group_set(self, id, type_, auths):
        """
        Parameters
        ----------

        auths : list of 4-tuples (user, secret, peeruser, peersecret)

        """
        type_ = type_.lower()
        args = ["type={}".format(type_)]
        a = []
        if type_ == "chap":
            a = [':'.join([quote(x) for x in i[:2]]) for i in auths if len(i[1]) >= 12]
        elif type_ == "chap-mutual":
            a = [':'.join([quote(x) for x in i[:4]]) for i in auths if len(i[1]) >= 12 and len(i[3]) >= 12]

        args += ["auth={}".format(quote(i)) for i in a]

        return self.cmd("auth-group-set", id, args)

    def auth_group_del(self, id):
        return self.cmd("auth-group-del", id, [])

    def lun_set(self, id, ctl_lun, path, blocksize, serial, device_id, size, pblocksize=None, **options):
        args=[
            "ctl-lun={}".format(ctl_lun),
            "path={}".format(quote(path)),
            "blocksize={}".format(blocksize),
            "serial={}".format(quote(serial)),
            "device-id={}".format(quote(device_id)),
        ]

        if size != 0:
            args.append("size={}".format(size))

        if pblocksize is not None:
            args.append("option=pblocksize={}".format(pblocksize))

        for key, value in options.items():
            args.append("option={}={}".format(key, quote(str(value))))

        return self.cmd("lun-set", id, args)

    def lun_del(self, id):
        return self.cmd("lun-del", id)

    def target_add(self, id, alias=None, pgs=[], ag=None):
        args = []

        if alias is not None:
            args.append('alias={}'.format(quote(alias)))

        args += [
            'portal-group={}'.format(pg)
            for pg in pgs
        ]

        if ag is not None:
            args.append('auth-group={}'.format(ag))

        return self.cmd("target-add", id, args)

    def target_del(self, id):
        return self.cmd("target-del", id)

    def target_set_luns(self, id, luns=[]):
        return self.cmd("target-set-lun", id, luns)