import asyncio
from datetime import datetime
import textwrap

from mock import ANY, Mock
import pytest

from middlewared.alert.source.ipmi_sel import (
    parse_sel_information,
    IPMISELAlertClass, IPMISELSpaceLeftAlertClass,
    IPMISELAlertSource, IPMISELSpaceLeftAlertSource,
    Alert,
)
from middlewared.plugins.ipmi_.utils import IPMISELRecord, parse_ipmitool_output


def test__parse_ipmitool_output():
    events = parse_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Watchdog2 #0xca,Timer interrupt (),Asserted
        a,07/05/2017,03:17:30,Temperature PECI CPU1,Upper Non-critical going high,Asserted,Reading 144 > Threshold 81 degrees C
    """))

    assert events[0] == IPMISELRecord(
        id=9,
        datetime=datetime(2017, 4, 20, 6, 3, 7),
        sensor="Watchdog2 #0xca",
        event="Timer interrupt ()",
        direction="Asserted",
        verbose=None
    )

    assert events[1] == IPMISELRecord(
        id=10,
        datetime=datetime(2017, 7, 5, 3, 17, 30),
        sensor="Temperature PECI CPU1",
        event="Upper Non-critical going high",
        direction="Asserted",
        verbose="Reading 144 > Threshold 81 degrees C"
    )


def test__parse_sel_information():
    info = parse_sel_information(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 9860 bytes
        Percent Used     : 2%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """))

    assert info["Free Space"] == "9860 bytes"
    assert info["Percent Used"] == "2%"


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__works():
    middleware = Mock()
    fut1 = asyncio.Future()
    fut1.set_result(True)
    fut2 = asyncio.Future()
    fut2.set_result(datetime.min)
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": fut1,
        "keyvalue.get": fut2,
    }[method])

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Power Unit #0xca,Failure detected,Asserted
    """)) == [
        Alert(
            IPMISELAlertClass,
            args=dict(
                sensor="Power Unit #0xca",
                event="Failure detected",
                direction="Asserted",
                verbose=None
            ),
            _key=ANY,
            datetime=datetime(2017, 4, 20, 6, 3, 7),
        )
    ]


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__works_filters_dismissed_events():
    middleware = Mock()
    fut1 = asyncio.Future()
    fut1.set_result(True)
    fut2 = asyncio.Future()
    fut2.set_result(datetime(2017, 4, 20, 6, 3, 7))
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": fut1,
        "keyvalue.get": fut2,
    }[method])

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Power Unit #0xca,Failure detected,Asserted
        9,04/20/2017,06:03:08,Power Unit #0xca,Failure detected,Asserted
    """)) == [
        Alert(
            IPMISELAlertClass,
            args=dict(
                sensor="Power Unit #0xca",
                event="Failure detected",
                direction="Asserted",
                verbose=None
            ),
            _key=ANY,
            datetime=datetime(2017, 4, 20, 6, 3, 8),
        )
    ]


@pytest.mark.asyncio
async def test_ipmi_sel_alert_source__first_run():
    def _create_future(m, *args):
        fut = asyncio.Future()
        fut.set_result(m(*args))
        return fut
    m2 = Mock()
    middleware = Mock()
    middleware.call = lambda method, *args: ({
        "keyvalue.has_key": lambda *args: _create_future(Mock(return_value=False), *args),
        "keyvalue.set": lambda *args: _create_future(m2, *args),
    }[method](*args))

    source = IPMISELAlertSource(middleware)

    assert await source._produce_alerts_for_ipmitool_output(textwrap.dedent("""\
        9,04/20/2017,06:03:07,Power Unit #0xca,Failure detected,Asserted
    """)) == []

    m2.assert_called_once_with("alert:ipmi_sel:dismissed_datetime", datetime(2017, 4, 20, 6, 3, 7))


def test_ipmi_sel_space_left_alert_source__does_not_emit():
    assert IPMISELSpaceLeftAlertSource(None)._produce_alert_for_ipmitool_output(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 9860 bytes
        Percent Used     : 2%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """)) is None


def test_ipmi_sel_space_left_alert_source__emits():
    assert IPMISELSpaceLeftAlertSource(None)._produce_alert_for_ipmitool_output(textwrap.dedent("""\
        SEL Information
        Version          : 1.5 (v1.5, v2 compliant)
        Entries          : 19
        Free Space       : 260 bytes
        Percent Used     : 98%
        Last Add Time    : 07/05/2018 23:32:08
        Last Del Time    : Not Available
        Overflow         : false
        Supported Cmds   : 'Reserve' 'Get Alloc Info'
        # of Alloc Units : 512
        Alloc Unit Size  : 20
        # Free Units     : 493
        Largest Free Blk : 493
        Max Record Size  : 20
    """)) == Alert(
        IPMISELSpaceLeftAlertClass,
        args={
            "free": "260 bytes",
            "used": "98%",
        },
        key=None,
    )
