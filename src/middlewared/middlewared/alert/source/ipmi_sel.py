from datetime import timedelta
import logging
import os

from middlewared.alert.base import (AlertClass, DismissableAlertClass, AlertCategory, AlertLevel, Alert, AlertSource,
                                    UnavailableException)
from middlewared.alert.schedule import IntervalSchedule
from middlewared.plugins.ipmi_.utils import parse_ipmitool_output
from middlewared.service_exception import CallError
from middlewared.utils import run

logger = logging.getLogger(__name__)


def has_ipmi():
    return any(os.path.exists(p) for p in ["/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"])


class IpmiTool:
    def __init__(self):
        self.errors = 0

    async def __call__(self, args):
        result = await run(["ipmitool"] + args, check=False, encoding="utf8", errors="ignore")
        if result.returncode != 0:
            self.errors += 1
            if self.errors < 5:
                raise UnavailableException()

            raise CallError(f"ipmitool failed (code={result.returncode}): {result.stderr}")

        self.errors = 0
        return result.stdout


ipmitool = IpmiTool()


def parse_sel_information(output):
    return {
        k.strip(): v.strip()
        for k, v in [line.split(":", 1) for line in output.split("\n") if line.strip() and ":" in line]
    }


class IPMISELAlertClass(AlertClass, DismissableAlertClass):
    category = AlertCategory.HARDWARE
    level = AlertLevel.WARNING
    title = "IPMI System Event"

    @classmethod
    def format(cls, args):
        text = "%(sensor)s %(direction)s %(event)s"
        if args["verbose"] is not None:
            text += ": %(verbose)s."
        else:
            text += "."

        return text % args

    async def dismiss(self, alerts, alert):
        datetimes = [a.datetime for a in alerts if a.datetime <= alert.datetime]
        if await self.middleware.call("keyvalue.has_key", IPMISELAlertSource.dismissed_datetime_kv_key):
            d = await self.middleware.call("keyvalue.get", IPMISELAlertSource.dismissed_datetime_kv_key)
            d = d.replace(tzinfo=None)
            datetimes.append(d)

        await self.middleware.call("keyvalue.set", IPMISELAlertSource.dismissed_datetime_kv_key, max(datetimes))
        return [a for a in alerts if a.datetime > alert.datetime]


class IPMISELAlertSource(AlertSource):
    schedule = IntervalSchedule(timedelta(minutes=5))

    dismissed_datetime_kv_key = "alert:ipmi_sel:dismissed_datetime"

    # https://github.com/openbmc/ipmitool/blob/master/include/ipmitool/ipmi_sel.h#L297

    IPMI_SENSORS = (
        "Redundancy State",
        "Temperature",
        "Voltage",
        "Current",
        "Fan",
        "Physical Security",
        "Platform Security",
        "Processor",
        "Power Supply",
        "Memory",
        "System Firmware Error",
        "Critical Interrupt",
        "Management Subsystem Health",
        "Battery",
    )

    IPMI_EVENTS_WHITELIST = (
        ("Power Unit", "Soft-power control failure"),
        ("Power Unit", "Failure detected"),
        ("Power Unit", "Predictive failure"),
        ("Event Logging Disabled", "Log full"),
        ("Event Logging Disabled", "Log almost full"),
        ("System Event", "Undetermined system hardware failure"),
        ("Cable/Interconnect", "Config Error"),
    )

    IPMI_EVENTS_BLACKLIST = (
        ("Redundancy State", "Fully Redundant"),
        ("Processor", "Presence detected"),
        ("Power Supply", "Presence detected"),
    )

    async def check(self):
        if not has_ipmi():
            return

        return await self._produce_alerts_for_ipmitool_output(await ipmitool(["-c", "sel", "elist"]))

    async def _produce_alerts_for_ipmitool_output(self, output):
        alerts = []

        records = parse_ipmitool_output(output)

        records = [
            record for record in records
            if (
                (
                    any(record.sensor.startswith(f"{sensor} #0x")
                        for sensor in self.IPMI_SENSORS) or
                    any(record.sensor.startswith(f"{sensor} #0x") and record.event == event
                        for sensor, event in self.IPMI_EVENTS_WHITELIST)
                ) and
                not any(record.sensor.startswith(f"{sensor} #0x") and record.event == event
                        for sensor, event in self.IPMI_EVENTS_BLACKLIST)
            )
        ]

        if records:
            if await self.middleware.call("keyvalue.has_key", self.dismissed_datetime_kv_key):
                dismissed_datetime = (
                    (await self.middleware.call("keyvalue.get", self.dismissed_datetime_kv_key)).replace(tzinfo=None)
                )
            else:
                # Prevent notifying about existing alerts on first install/upgrade
                dismissed_datetime = max(record.datetime for record in records)
                await self.middleware.call("keyvalue.set", self.dismissed_datetime_kv_key, dismissed_datetime)

            for record in records:
                if record.datetime <= dismissed_datetime:
                    continue

                args = dict(record._asdict())
                args.pop("id")
                args.pop("datetime")

                alerts.append(Alert(
                    IPMISELAlertClass,
                    args,
                    key=[args, record.datetime.isoformat()],
                    datetime=record.datetime,
                ))

        return alerts


class IPMISELSpaceLeftAlertClass(AlertClass):
    category = AlertCategory.HARDWARE
    level = AlertLevel.WARNING
    title = "IPMI System Event Log Low Space Left"
    text = "IPMI System Event Log low space left: %(free)s (%(used)s used)."


class IPMISELSpaceLeftAlertSource(AlertSource):
    schedule = IntervalSchedule(timedelta(minutes=5))

    async def check(self):
        if not has_ipmi():
            return

        return self._produce_alert_for_ipmitool_output(await ipmitool(["sel", "info"]))

    def _produce_alert_for_ipmitool_output(self, output):
        sel_information = parse_sel_information(output)
        try:
            percent_used = int(sel_information["Percent Used"].rstrip("%"))
        except ValueError:
            return

        if percent_used > 90:
            return Alert(
                IPMISELSpaceLeftAlertClass,
                {
                    "free": sel_information["Free Space"],
                    "used": sel_information["Percent Used"],
                },
                key=None,
            )
