from datetime import timedelta
import os
import json
import logging

try:
    from freenasOS import Update
    from freenasOS.Update import PendingUpdates
except ImportError:
    Update = PendingUpdates = None

from middlewared.alert.base import (AlertClass, SimpleOneShotAlertClass, AlertCategory, AlertLevel, Alert,
                                    FilePresenceAlertSource, ThreadedAlertSource)
from middlewared.alert.schedule import IntervalSchedule

UPDATE_APPLIED_SENTINEL = "/tmp/.updateapplied"

log = logging.getLogger("update_check_alertmod")


# FIXME: use update plugin
def is_update_applied(update_version):
    if Update is None:
        return False
    active_be_msg = 'Please reboot the system to activate this update.'
    # TODO: The below boot env name should really be obtained from the update code
    # for now we just duplicate that code here
    if update_version.startswith(Update.Avatar() + "-"):
        update_boot_env = update_version[len(Update.Avatar() + "-"):]
    else:
        update_boot_env = "%s-%s" % (Update.Avatar(), update_version)

    found = False
    msg = ''
    for clone in Update.ListClones():
        if clone['realname'] == update_boot_env:
            if clone['active'] != 'R':
                active_be_msg = 'Please activate {0} via'.format(update_boot_env) + \
                                ' the Boot Environment Tab and Reboot to use this updated version.'
            msg = 'Update: {0} has already been applied. {1}'.format(update_version, active_be_msg)
            found = True
            break

    return (found, msg)


class HasUpdateAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.INFO
    title = "Update Available"
    text = "A system update is available. Go to System -> Update to download and apply the update."


class HasUpdateAlertSource(ThreadedAlertSource):
    schedule = IntervalSchedule(timedelta(hours=1))

    run_on_backup_node = False

    def check_sync(self):
        try:
            self.middleware.call_sync("datastore.query", "system.update", [], {"get": True})
        except IndexError:
            self.middleware.call_sync("datastore.insert", "system.update", {
                "upd_autocheck": True,
                "upd_train": "",
            })

        path = self.middleware.call_sync("update.get_update_location")
        if not path:
            return


        updates = None
        try:
            if PendingUpdates:
                updates = PendingUpdates(path)
        except Exception:
            pass

        if updates:
            return Alert(HasUpdateAlertClass)


class UpdateNotAppliedAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = "Update Not Applied"
    text = "%s"


class UpdateNotAppliedAlertSource(ThreadedAlertSource):
    schedule = IntervalSchedule(timedelta(minutes=10))

    def check_sync(self):
        if os.path.exists(UPDATE_APPLIED_SENTINEL):
            try:
                with open(UPDATE_APPLIED_SENTINEL, "rb") as f:
                    data = json.loads(f.read().decode("utf8"))
            except Exception:
                log.error(
                    "Could not load UPDATE APPLIED SENTINEL located at {0}".format(
                        UPDATE_APPLIED_SENTINEL
                    ),
                    exc_info=True
                )
                return

            if is_update_applied:
                update_applied, msg = is_update_applied(data["update_version"])
                if update_applied:
                    return Alert(UpdateNotAppliedAlertClass, msg)


class UpdateFailedAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Update Failed"
    text = "Update failed. See /data/update.failed for details."


class UpdateFailedAlertSource(FilePresenceAlertSource):
    path = "/data/update.failed"
    klass = UpdateFailedAlertClass


class CurrentVersionIsNotEnterpriseReadyAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Current System Version Is Not Enterprise-Ready"
    text = (
        "Current system version %(current_version)s is not Enterprise-Ready. The latest Enterprise-Ready version is "
        "%(new_version)s."
    )

    async def delete(self, alerts, query):
        return []
