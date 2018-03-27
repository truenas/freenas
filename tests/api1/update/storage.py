#!/usr/bin/env python3.6

# Author: Eric Turgeon
# License: BSD
# Location for tests into REST API of FreeNAS

import sys
import os

apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST  # , GET_OUTPUT


# Check updating a ZVOL
def test_01_Updating_ZVOL():
    payload = {"volsize": "50M"}
    assert PUT("/storage/volume/tank/zvols/testzvol1/", payload) == 201


# Check rolling back a ZFS snapshot
def test_02_Rolling_back_ZFS_snapshot_tank_test():
    payload = {"force": True}
    assert POST("/storage/snapshot/tank@test/rollback/", payload) == 202


# Check to verify snapshot was rolled back
# def test_03_Check_to_verify_snapshot_was_rolled_back():
#     GET_OUTPUT("/storage/volume/tank/datasets/", "name") == "snapcheck"
