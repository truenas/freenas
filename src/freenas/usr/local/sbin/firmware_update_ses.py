#!/usr/bin/env python
#
# Copyright (c) 2020 iXsystems, Inc.
# All rights reserved.
# This file is a part of TrueNAS
# and may not be copied and/or distributed
# without the express permission of iXsystems.

import json
import logging
import logging.config
import logging.handlers
import os
import re
import sys
import subprocess

UPDATE_FAILED_SENTINEL = "/data/.ses_firmware_update_failed"
UPDATE_LOG = "/data/ses_firmware_update.log"
UPDATE_PATH = "/usr/local/lib/firmware/ses"

logger = logging.getLogger(__name__)


def run(args, check=True):
    logger.debug("Running %r", args)
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8", errors="ignore",
                          check=check)


def write_update_failed_sentinel():
    with open(UPDATE_FAILED_SENTINEL, "w"):
        pass


class Updater:
    def __init__(self):
        self.found = False

        with open(os.path.join(UPDATE_PATH, "manifest.json")) as f:
            manifest = json.load(f)

        self.update_path = os.path.join(UPDATE_PATH, manifest["file"])
        self.update_version = manifest["version"]

        devlist = run(["camcontrol", "devlist"]).stdout
        m = re.search(r"<CELESTIC R0904-F0001-01 ([0-9]+)>.*\((ses[0-9]+),", devlist)
        if m:
            self.found = True
            self.current_version = m.group(1)
            self.ses = m.group(2)
            logger.info("Found enclosure with firmware version %r at %r", self.current_version, self.ses)
        else:
            logger.info("Enclosure not found")

    def need_update(self):
        if not self.found:
            return False

        if self.current_version == self.update_version:
            logger.info("Current version is already the newest")
            return False

        logger.info("Need to update version %r to %r", self.current_version, self.update_version)
        return True

    def run_update(self):
        run(["sg_ses_microcode", "-b", "4k", "-m", "7", "-I", self.update_path, f"/dev/{self.ses}"])
        return True


if __name__ == "__main__":
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "formatter": {
                "format": "[%(asctime)s] %(message)s",
            },
        },
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "formatter": "formatter",
                "level": "DEBUG",
                "filename": UPDATE_LOG,
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "formatter",
                "level": "DEBUG",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "": {
                "handlers": ["console", "file"],
                "level": "DEBUG",
                "propagate": True,
            },
        },
    })

    if os.path.exists(UPDATE_FAILED_SENTINEL):
        # Prevent a firmware flash failure from causing a boot loop
        logger.info("Failure sentinel present, skipping SES firmware update")
        sys.exit(255)

    try:
        updater = Updater()
        if updater.need_update():
            if updater.run_update():
                logger.info("SES firmware update is successful")
                sys.exit(0)
            else:
                logger.error("SES firmware update is unsuccessful")
                write_update_failed_sentinel()
                sys.exit(1)
        else:
            logger.info("No SES firmware update needed")
            sys.exit(1)
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError):
            logger.error("Command %r failed with return code %r\n%s", e.cmd, e.returncode, e.stdout)
        else:
            logger.error("Unhandled exception while performing SES firmware update", exc_info=True)
        write_update_failed_sentinel()
        sys.exit(1)
