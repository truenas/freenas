from psutil._pslinux import Connections

from middlewared.service import Service


class NFSService(Service):
    def client_count(self):
        """
        Return currently connected clients count.
        """

        """
        As NFS does not have an explicit umount request, Ganesha does not remove clients and the following snippet
        does not work correctly:

        bus = dbus.SystemBus()
        proxy = bus.get_object("org.ganesha.nfsd", "/org/ganesha/nfsd/ClientMgr")
        iface = dbus.Interface(proxy, dbus_interface="org.ganesha.nfsd.clientmgr")
        return len(iface.ShowClients()[1])

        We should reconsider our approach if they ever fix this.
        """

        with open("/var/run/ganesha.pid") as f:
            pid = int(f.read())

        clients = set()
        for connection in Connections().retrieve("inet", pid):
            if connection.laddr.port == 2049 and connection.status == "ESTABLISHED":
                clients.add(connection.raddr.ip)

        return len(clients)
