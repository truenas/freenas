from middlewared.service import Service, accepts
from middlewared.utils import run
from middlewared.schema import Dict, Bool
from fenced.fence import ExitCode as FencedExitCodes


class FencedForceService(Service):

    class Config:
        namespace = 'failover.fenced'
        private = True

    @accepts(Dict(
        'fenced_start',
        Bool('force', default=False),
    ))
    async def start(self, data):
        """
        Start the fenced daemon.

        `force` Boolean when True will forcefully
                start the fenced program. Note,
                this will ignore any other persistent
                reservations on the disks. When set
                to false, will check to see if there
                are existing keys on the disks and
                if they change, then will fail.
        """
        # fenced will reserve nvme drives so we need to make sure
        # that the boot disks (newer generation m-series use nvme boot drives)
        # are excluded (-ed flag) from fenced so SCSI reservations are not
        # placed on them
        boot_disks = ','.join(await self.middleware.call('boot.get_disks'))

        cmd = ['fenced', '-ed', f'{boot_disks}']
        cmd.append('--force') if data['force'] else None
        cp = await run(cmd, check=False)
        return cp.returncode

    async def stop(self):
        """
        Stop the fenced daemon.
        """
        cp = await run(['pkill', '-9', '-f', 'fenced'], check=False)
        return not bool(cp.returncode)


async def _run_fenced_on_single_node(middleware, event_type, args):
    """
    Run fenced on single node systems always. This is to, hopefully, prevent
    a very rare scenario of data corruption when a single node system is
    upgraded to an HA system and proper procedures aren't followed.
    """
    # HA licensed systems call fenced in the `event.py` plugin
    # so don't call it here
    if await middleware.call('failover.licensed'):
        return

    # if not HA capable hardware, then nothing to do
    if await middleware.call('system.product_type') != 'ENTERPRISE':
        return

    if args['id'] == 'ready':
        # be sure we stop fenced first before we start it since > 1
        # fenced processes will panic the system. There are safeguards
        # in the fenced program for this scenario, however, best to
        # play it safe
        await middleware.call('failover.fenced.stop')
        rc = await middleware.call('failover.fenced.start', {'force': True})
        for i in FencedExitCodes:
            if rc == i.value:
                middleware.logger.error(f'Fenced failed to start because: {i.name}')


async def setup(middleware):
    middleware.event_subscribe('system', _run_fenced_on_single_node)
