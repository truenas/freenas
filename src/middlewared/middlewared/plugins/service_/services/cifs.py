from middlewared.service_exception import CallError
from middlewared.utils import osc

from .base import SimpleService, ServiceState


class CIFSService(SimpleService):
    name = "cifs"
    reloadable = True

    etc = ["smb", "smb_share"]

    freebsd_rc = "smbd"
    freebsd_pidfile = "/var/run/samba4/smbd.pid"

    systemd_unit = "smbd"

    async def _get_state_freebsd(self):
        return ServiceState(
            (await self._freebsd_service("smbd", "status")).returncode == 0,
            [],
        )

    async def start(self):
        announce = (await self.middleware.call("network.configuration.config"))["service_announcement"]
        if osc.IS_FREEBSD:
            await self._freebsd_service("smbd", "start", force=True)
            await self._freebsd_service("winbindd", "start", force=True)
        if osc.IS_LINUX:
            is_clustered = await self.middleware.call("smb.getparm", "clustering", "global")
            if is_clustered:
                cluster_healthy = await self.middleware.call("ctdb.general.healthy")
                if not cluster_healthy:
                    self.middleware.logger.warning("Cluster is unhealthy. Refusing to start SMB service.")
                    return

            await self._systemd_unit("smbd", "start")
            await self._systemd_unit("winbind", "start")
        if announce["netbios"]:
            if osc.IS_FREEBSD:
                await self._freebsd_service("nmbd", "start", force=True)
            if osc.IS_LINUX:
                await self._systemd_unit("nmbd", "start")
        if announce["wsd"]:
            if osc.IS_FREEBSD:
                await self._freebsd_service("wsdd", "start", force=True)
            if osc.IS_LINUX:
                await self._systemd_unit("wsdd", "start")
                # FIXME: Need debian package

    async def after_start(self):
        await self.middleware.call("service.reload", "mdns")

        try:
            await self.middleware.call("smb.add_admin_group", "", True)
        except Exception as e:
            raise CallError(e)

    async def stop(self):
        if osc.IS_FREEBSD:
            await self._freebsd_service("smbd", "stop", force=True)
            await self._freebsd_service("winbindd", "stop", force=True)
            await self._freebsd_service("nmbd", "stop", force=True)
            await self._freebsd_service("wsdd", "stop", force=True)
        if osc.IS_LINUX:
            await self._systemd_unit("smbd", "stop")
            await self._systemd_unit("winbind", "stop")
            await self._systemd_unit("nmbd", "stop")
            await self._systemd_unit("wsdd", "stop")

    async def after_stop(self):
        await self.middleware.call("service.reload", "mdns")

    async def before_reload(self):
        reload_jid = await self.middleware.call('sharing.smb.sync_registry')
        await reload_jid.wait()

    async def after_reload(self):
        await self.middleware.call("service.reload", "mdns")
