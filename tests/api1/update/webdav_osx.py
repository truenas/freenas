#!/usr/bin/env python3.6

# Author: Eric Turgeon
# License: BSD
# Location for tests into REST API of FreeNAS

import sys
import os

apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET_OUTPUT, DELETE, DELETE_ALL

DATASET = "webdavshare"
DATASET_PATH = "/mnt/tank/%s/" % DATASET
TMP_FILE = "/tmp/testfile.txt"
SHARE_NAME = "webdavshare"
SHARE_USER = "webdav"
SHARE_PASS = "davtest2"


# Clean up any leftover items from previous failed test runs
def test_00_cleanup_tests():
    payload1 = {"webdav_name": SHARE_NAME,
                "webdav_comment": "Auto-created by API tests",
                "webdav_path": DATASET_PATH}
    DELETE_ALL("/sharing/webdav/", payload1)
    PUT("/services/services/webdav/", {"srv_enable": False})
    DELETE("/storage/volume/1/datasets/%s/" % DATASET)


def test_01_Creating_dataset_for_WebDAV_use():
    assert POST("/storage/volume/tank/datasets/", {"name": DATASET}) == 201


def test_02_Changing_permissions_on_DATASET_PATH():
    payload = {"mp_path": DATASET_PATH,
               "mp_acl": "unix",
               "mp_mode": "777",
               "mp_user": "root",
               "mp_group": "wheel"}
    assert PUT("/storage/permission/", payload) == 201


def test_03_Creating_WebDAV_share_on_DATASET_PATH():
    payload = {"webdav_name": SHARE_NAME,
               "webdav_comment": "Auto-created by API tests",
               "webdav_path": DATASET_PATH}
    assert POST("/sharing/webdav/", payload) == 201


def test_04_Starting_WebDAV_service():
    assert PUT("/services/services/webdav/", {"srv_enable": True}) == 200


def test_05_Changing_password_for_webdev():
    payload = {"webdav_password": SHARE_PASS}
    assert PUT("/services/services/webdav/", payload) == 200


def test_06_Stopping_WebDAV_service():
    assert PUT("/services/services/webdav/", {"srv_enable": False}) == 200


def test_07_Verifying_that_the_WebDAV_service_has_stopped():
    assert GET_OUTPUT("/services/services/webdav",
                      "srv_state") == "STOPPED"
