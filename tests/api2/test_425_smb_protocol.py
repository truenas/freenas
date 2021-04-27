#!/usr/bin/env python3

import pytest
import sys
import os
import enum
from time import sleep
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET, DELETE, wait_on_job
from auto_config import ip, pool_name, scale, dev_test
from pytest_dependency import depends
from protocols import SMB

reason = 'Skip for testing'
# comment pytestmark for development testing with --dev-test
pytestmark = pytest.mark.skipif(dev_test, reason=reason)


dataset = f"{pool_name}/smb-proto"
dataset_url = dataset.replace('/', '%2F')
SMB_NAME = "SMBPROTO"
smb_path = "/mnt/" + dataset
group = 'root' if scale else 'wheel'
module_prefix = 'zfs_core' if scale else 'ixnas'


guest_path_verification = {
    "user": "shareuser",
    "group": group,
    "acl": True
}


root_path_verification = {
    "user": "root",
    "group": group,
    "acl": False
}


class DOSmode(enum.Enum):
    READONLY = 1
    HIDDEN = 2
    SYSTEM = 4
    ARCHIVE = 32


SMB_USER = "smbuser"
SMB_PWD = "smb1234"


@pytest.mark.dependency(name="SMB_DATASET_CREATED")
def test_001_creating_smb_dataset():
    payload = {
        "name": dataset,
        "share_type": "SMB"
    }
    results = POST("/pool/dataset/", payload)
    assert results.status_code == 200, results.text


def test_002_get_next_uid_for_smbuser():
    results = GET('/user/get_next_uid/')
    assert results.status_code == 200, results.text
    global next_uid
    next_uid = results.json()


@pytest.mark.dependency(name="SMB_USER_CREATED")
def test_003_creating_shareuser_to_test_acls(request):
    depends(request, ["SMB_DATASET_CREATED"])
    global smbuser_id
    payload = {
        "username": SMB_USER,
        "full_name": "SMB User",
        "group_create": True,
        "password": SMB_PWD,
        "uid": next_uid,
    }
    results = POST("/user/", payload)
    assert results.status_code == 200, results.text
    smbuser_id = results.json()


def test_004_changing_dataset_permissions_of_smb_dataset(request):
    depends(request, ["SMB_USER_CREATED"])
    global smbproto_job_id
    payload = {
        "acl": [],
        "mode": "777",
        "user": SMB_USER,
        "group": group,
        "options": {"stripacl": True, "recursive": True}
    }
    results = POST(f"/pool/dataset/id/{dataset_url}/permission/", payload)
    assert results.status_code == 200, results.text
    smbproto_job_id = results.json()


@pytest.mark.dependency(name="SMB_PERMISSION_SET")
def test_005_verify_the_job_id_is_successful(request):
    depends(request, ["SMB_USER_CREATED"])
    job_status = wait_on_job(smbproto_job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


@pytest.mark.dependency(name="SMB_SHARE_CREATED")
def test_006_creating_a_smb_share_path(request):
    depends(request, ["SMB_PERMISSION_SET"])
    global payload, results, smb_id
    payload = {
        "comment": "SMB Protocol Testing Share",
        "path": smb_path,
        "name": SMB_NAME,
        "auxsmbconf": f"{module_prefix}:base_user_quota = 1G"
    }
    results = POST("/sharing/smb/", payload)
    assert results.status_code == 200, results.text
    smb_id = results.json()['id']


@pytest.mark.dependency(name="SMB_SERVICE_STARTED")
def test_007_starting_cifs_service(request):
    depends(request, ["SMB_SHARE_CREATED"])
    payload = {"service": "cifs"}
    results = POST("/service/start/", payload)
    assert results.status_code == 200, results.text
    sleep(1)


def test_008_checking_to_see_if_smb_service_is_running(request):
    depends(request, ["SMB_SHARE_CREATED"])
    results = GET("/service?service=cifs")
    assert results.json()[0]["state"] == "RUNNING", results.text


@pytest.mark.dependency(name="SHARE_IS_WRITABLE")
def test_009_share_is_writable(request):
    """
    This test creates creates an empty file, sets "delete on close" flag, then
    closes it. NTStatusError should be raised containing failure details
    if we are for some reason unable to access the share.

    This test will fail if smb.conf / smb4.conf does not exist on client / server running test.
    """
    depends(request, ["SMB_SHARE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    fd = c.create_file("testfile", "w")
    c.close(fd, True)
    c.disconnect()


@pytest.mark.parametrize('dm', DOSmode)
def test_010_check_dosmode_create(request, dm):
    """
    This tests the setting of different DOS attributes through SMB2 Create.
    after setting
    """
    depends(request, ["SHARE_IS_WRITABLE"])
    if dm.value > DOSmode.SYSTEM.value:
        return

    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    if dm == DOSmode.READONLY:
        c.create_file(dm.name, "w", "r")
    elif dm == DOSmode.HIDDEN:
        c.create_file(dm.name, "w", "h")
    elif dm == DOSmode.SYSTEM:
        c.create_file(dm.name, "w", "s")
    dir_listing = c.ls("/")
    for f in dir_listing:
        if f['name'] != dm.name:
            continue
        # Archive is automatically set by kernel
        to_check = f['attrib'] & ~DOSmode.ARCHIVE.value
        c.disconnect()
        assert (to_check & dm.value) != 0, f


def test_011_check_dos_ro_cred_handling(request):
    """
    This test creates a file with readonly attribute set, then
    uses the open fd to write data to the file.
    """
    depends(request, ["SHARE_IS_WRITABLE"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    fd = c.create_file("RO_TEST", "w", "r")
    c.write(fd, b"TESTING123\n")
    c.disconnect()


@pytest.mark.dependency(name="SMB1_ENABLED")
def test_050_enable_smb1(request):
    depends(request, ["SMB_SHARE_CREATED"])
    payload = {
        "enable_smb1": True,
    }
    results = PUT("/smb/", payload)
    assert results.status_code == 200, results.text


@pytest.mark.dependency(name="SHARE_IS_WRITABLE_SMB1")
def test_051_share_is_writable_smb1(request):
    """
    This test creates creates an empty file, sets "delete on close" flag, then
    closes it. NTStatusError should be raised containing failure details
    if we are for some reason unable to access the share.

    This test will fail if client min protocol != NT1 in smb.conf of SMB client.
    Sample smb.conf entry:

    [global]
    client min protocol = nt1
    """
    depends(request, ["SMB_SHARE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    fd = c.create_file("testfile", "w")
    c.close(fd, True)
    c.disconnect()


@pytest.mark.parametrize('dm', DOSmode)
def test_052_check_dosmode_create_smb1(request, dm):
    """
    This tests the setting of different DOS attributes through SMB1 create.
    after setting
    """
    depends(request, ["SHARE_IS_WRITABLE"])
    if dm.value > DOSmode.SYSTEM.value:
        return

    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    if dm == DOSmode.READONLY:
        c.create_file(f'{dm.name}_smb1', "w", "r")
    elif dm == DOSmode.HIDDEN:
        c.create_file(f'{dm.name}_smb1', "w", "h")
    elif dm == DOSmode.SYSTEM:
        c.create_file(f'{dm.name}_smb1', "w", "s")
    dir_listing = c.ls("/")
    for f in dir_listing:
        if f['name'] != f'{dm.name}_smb1':
            continue
        # Archive is automatically set by kernel
        to_check = f['attrib'] & ~DOSmode.ARCHIVE.value
        c.disconnect()
        assert (to_check & dm.value) != 0, f


@pytest.mark.dependency(name="STREAM_TESTFILE_CREATED")
def test_060_create_base_file_for_streams_tests(request):
    """
    Create the base file that we will use for further stream tests.
    """
    depends(request, ["SMB_SHARE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    fd = c.create_file("streamstestfile", "w")
    c.close(fd)
    c.disconnect()


@pytest.mark.dependency(name="STREAM_WRITTEN_SMB2")
def test_061_create_and_write_stream_smb2(request):
    """
    Create our initial stream and write to it over SMB2/3 protocol.
    Start with offset 0.
    """
    depends(request, ["STREAM_TESTFILE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    fd = c.create_file("streamstestfile:smb2_stream", "w")
    c.write(fd, b'test1', 0)
    c.close(fd)

    fd2 = c.create_file("streamstestfile:smb2_stream", "w")
    contents = c.read(fd2, 0, 5)
    c.close(fd2)
    c.disconnect()
    assert(contents.decode() == "test1")


@pytest.mark.dependency(name="LARGE_STREAM_WRITTEN_SMB2")
def test_062_write_stream_large_offset_smb2(request):
    """
    Append to our existing stream over SMB2/3 protocol. Specify an offset that will
    cause resuling xattr to exceed 64KiB default xattr size limit in Linux.
    """
    depends(request, ["STREAM_TESTFILE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    fd = c.create_file("streamstestfile:smb2_stream", "w")
    c.write(fd, b'test2', 131072)
    c.close(fd)

    fd2 = c.create_file("streamstestfile:smb2_stream", "w")
    contents = c.read(fd2, 131072, 5)
    c.close(fd2)
    c.disconnect()
    assert(contents.decode() == "test2")


def test_063_stream_delete_on_close_smb2(request):
    """
    Set delete_on_close on alternate datastream over SMB2/3 protocol, close, then verify
    stream was deleted.

    TODO: I have open MR to expand samba python bindings to support stream enumeration.
    Verifcation of stream deletion will have to be added once this is merged.
    """
    depends(request, ["STREAM_WRITTEN_SMB2", "LARGE_STREAM_WRITTEN_SMB2"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=False)
    fd = c.create_file("streamstestfile:smb2_stream", "w")
    c.close(fd, True)

    c.disconnect()


@pytest.mark.dependency(name="STREAM_WRITTEN_SMB1")
def test_065_create_and_write_stream_smb1(request):
    """
    Create our initial stream and write to it over SMB1 protocol.
    Start with offset 0.
    """
    depends(request, ["STREAM_TESTFILE_CREATED"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    fd = c.create_file("streamstestfile:smb1_stream", "w")
    c.write(fd, b'test1', 0)
    c.close(fd)

    fd2 = c.create_file("streamstestfile:smb1_stream", "w")
    contents = c.read(fd2, 0, 5)
    c.close(fd2)
    c.disconnect()
    assert(contents.decode() == "test1")


@pytest.mark.dependency(name="LARGE_STREAM_WRITTEN_SMB1")
def test_066_write_stream_large_offset_smb1(request):
    """
    Append to our existing stream over SMB1 protocol. Specify an offset that will
    cause resuling xattr to exceed 64KiB default xattr size limit in Linux.
    """
    depends(request, ["STREAM_WRITTEN_SMB1"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    fd = c.create_file("streamstestfile:smb1_stream", "w")
    c.write(fd, b'test2', 131072)
    c.close(fd)

    fd2 = c.create_file("streamstestfile:smb1_stream", "w")
    contents = c.read(fd2, 131072, 5)
    c.close(fd2)
    c.disconnect()
    assert(contents.decode() == "test2")


def test_067_stream_delete_on_close_smb1(request):
    """
    Set delete_on_close on alternate datastream over SMB1 protocol, close, then verify
    stream was deleted.

    TODO: I have open MR to expand samba python bindings to support stream enumeration.
    Verifcation of stream deletion will have to be added once this is merged.
    """
    depends(request, ["STREAM_WRITTEN_SMB1", "LARGE_STREAM_WRITTEN_SMB1"])
    c = SMB()
    c.connect(host=ip, share=SMB_NAME, username=SMB_USER, password=SMB_PWD, smb1=True)
    fd = c.create_file("streamstestfile:smb1_stream", "w")
    c.close(fd, True)

    c.disconnect()


"""
At this point we grant SMB_USER SeDiskOperatorPrivilege by making it a member
of the local group builtin_administrators. This privilege is required to manipulate
SMB quotas.
"""


@pytest.mark.dependency(name="BA_ADDED_TO_USER")
def test_089_add_to_builtin_admins(request):
    depends(request, ["SHARE_IS_WRITABLE"])
    ba = GET('/group?group=builtin_administrators').json()
    assert len(ba) != 0

    userinfo = GET(f'/user/id/{smbuser_id}').json()
    groups = userinfo['groups']
    groups.append(ba[0]['id'])

    payload = {'groups': groups}
    results = PUT(f"/user/id/{smbuser_id}/", payload)
    assert results.status_code == 200, f"res: {results.text}, payload: {payload}"


@pytest.mark.parametrize('proto', ["SMB2"])
def test_090_test_auto_smb_quota(request, proto):
    """
    Since the share is configured wtih ixnas:base_user_quota parameter,
    the first SMB tree connect should have set a ZFS user quota on the
    underlying dataset. Test querying through the SMB protocol.

    Currently SMB1 protocol is disabled because of hard-coded check in
    source3/smbd/nttrans.c to only allow root to get/set quotas.
    """
    depends(request, ["BA_ADDED_TO_USER"])
    c = SMB()
    qt = c.get_quota(
        host=ip,
        share=SMB_NAME,
        username=SMB_USER,
        password=SMB_PWD,
        smb1=(proto == "SMB1")
    )

    # There should only be one quota entry
    assert len(qt) == 1, qt

    # username is prefixed with server netbios name "SERVER\user"
    assert qt[0]['user'].endswith(SMB_USER), qt

    # Hard and Soft limits should be set to value above (1GiB)
    assert qt[0]['soft_limit'] == (2 ** 30), qt
    assert qt[0]['hard_limit'] == (2 ** 30), qt


def test_091_remove_auto_quota_param(request):
    depends(request, ["SMB_SHARE_CREATED"])
    results = PUT(f"/sharing/smb/id/{smb_id}/", {"auxsmbconf": ""})
    assert results.status_code == 200, results.text


@pytest.mark.parametrize('proto', ["SMB2"])
def test_092_set_smb_quota(request, proto):
    """
    This test checks our ability to set a ZFS quota
    through the SMB protocol by first setting a 2 GiB
    quota, then reading it through the SMB protocol, then
    resetting to zero.
    """
    depends(request, ["BA_ADDED_TO_USER"])
    new_quota = 2 * (2**30)
    c = SMB()
    qt = c.set_quota(
        host=ip,
        share=SMB_NAME,
        username=SMB_USER,
        password=SMB_PWD,
        hardlimit=new_quota,
        target=SMB_USER,
        smb1=(proto == "SMB1")
    )
    assert len(qt) == 1, qt
    assert qt[0]['user'].endswith(SMB_USER), qt
    assert qt[0]['soft_limit'] == new_quota, qt
    assert qt[0]['hard_limit'] == new_quota, qt

    qt = c.get_quota(
        host=ip,
        share=SMB_NAME,
        username=SMB_USER,
        password=SMB_PWD,
        smb1=(proto == "SMB1")
    )
    assert len(qt) == 1, qt
    assert qt[0]['user'].endswith(SMB_USER), qt
    assert qt[0]['soft_limit'] == new_quota, qt
    assert qt[0]['hard_limit'] == new_quota, qt

    qt = c.set_quota(
        host=ip,
        share=SMB_NAME,
        username=SMB_USER,
        password=SMB_PWD,
        hardlimit=0,
        target=SMB_USER,
        smb1=(proto == "SMB1")
    )
    assert len(qt) == 1, qt
    assert qt[0]['user'].endswith(SMB_USER), qt
    assert qt[0]['soft_limit'] is None, qt
    assert qt[0]['hard_limit'] is None, qt

    qt = c.get_quota(
        host=ip,
        share=SMB_NAME,
        username=SMB_USER,
        password=SMB_PWD,
        smb1=(proto == "SMB1")
    )
    assert len(qt) == 1, qt
    assert qt[0]['user'].endswith(SMB_USER), qt
    assert qt[0]['soft_limit'] is None, qt
    assert qt[0]['hard_limit'] is None, qt


def test_100_delete_smb_user(request):
    depends(request, ["SMB_USER_CREATED"])
    results = DELETE(f"/user/id/{smbuser_id}/", {"delete_group": True})
    assert results.status_code == 200, results.text


def test_101_delete_smb_share(request):
    depends(request, ["SMB_SHARE_CREATED"])
    results = DELETE(f"/sharing/smb/id/{smb_id}")
    assert results.status_code == 200, results.text


def test_102_disable_smb1(request):
    depends(request, ["SMB1_ENABLED"])
    payload = {
        "enable_smb1": False,
    }
    results = PUT("/smb/", payload)
    assert results.status_code == 200, results.text


def test_103_stopping_smb_service(request):
    depends(request, ["SMB_SERVICE_STARTED"])
    payload = {"service": "cifs"}
    results = POST("/service/stop/", payload)
    assert results.status_code == 200, results.text
    sleep(1)


def test_104_checking_if_smb_is_stoped(request):
    depends(request, ["SMB_SERVICE_STARTED"])
    results = GET("/service?service=cifs")
    assert results.json()[0]['state'] == "STOPPED", results.text


def test_105_destroying_smb_dataset(request):
    depends(request, ["SMB_DATASET_CREATED"])
    results = DELETE(f"/pool/dataset/id/{dataset_url}/")
    assert results.status_code == 200, results.text
