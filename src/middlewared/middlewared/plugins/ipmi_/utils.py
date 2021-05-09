# -*- coding=utf-8 -*-
from collections import namedtuple
from datetime import datetime
import csv
import logging

logger = logging.getLogger(__name__)

__all__ = ["IPMISELRecord", "parse_ipmitool_output", "parse_ipmi_sel_record"]

IPMISELRecord = namedtuple("IPMISELRecord", ["id", "datetime", "sensor", "event", "direction", "verbose"])


def parse_ipmitool_output(output):
    records = []
    for row in csv.reader(output.split("\n")):
        if row:
            try:
                record = parse_ipmi_sel_record(row)
            except Exception:
                logger.warning("Failed to parse IPMI SEL record %r", row)
            else:
                if record:
                    records.append(record)

    return records


def parse_ipmi_sel_record(row):
    if row[1].strip() == "Pre-Init":
        return None

    m, d, y = tuple(map(int, row[1].split("/")))
    h, i, s = tuple(map(int, row[2].split(":")))
    return IPMISELRecord(
        id=int(row[0], 16),
        datetime=datetime(y, m, d, h, i, s),
        sensor=row[3],
        event=row[4],
        direction=row[5],
        verbose=row[6] if len(row) > 6 else None
    )
