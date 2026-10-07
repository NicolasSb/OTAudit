from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest

from otaudit.models import Capture, Device, Report
from otaudit.report import _duration

START = datetime(2023, 11, 14, 22, 0, tzinfo=UTC)


def report_lasting(delta: timedelta | None) -> Report:
    capture = Capture(
        path="x.pcap",
        started_at=START if delta is not None else None,
        ended_at=START + delta if delta is not None else None,
    )
    return Report(scope=_scope(), capture=capture, generated_at=START)


def _scope():
    from otaudit.models import Scope, Window

    return Scope(
        engagement="e",
        authorized_by="a",
        reference="r",
        window=Window(start=START, end=START + timedelta(hours=6)),
        targets=["10.42.7.0/26"],
    )


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(seconds=42), "42 s"),
        (timedelta(minutes=3, seconds=7), "3 min 07 s"),
        (timedelta(hours=2, minutes=5), "2 h 05 min"),
        (None, "unknown"),
    ],
)
def test_duration_formatting(delta, expected):
    assert _duration(report_lasting(delta)) == expected


def test_out_of_scope_devices_are_listed():
    report = report_lasting(timedelta(seconds=1))
    report = report.model_copy(
        update={
            "devices": [
                Device(address=IPv4Address("10.42.7.20"), in_scope=True),
                Device(address=IPv4Address("10.42.9.80"), in_scope=False),
            ]
        }
    )

    assert [str(device.address) for device in report.out_of_scope_devices] == ["10.42.9.80"]


def test_host_without_industrial_role_shows_a_dash():
    from otaudit.report import render

    report = report_lasting(timedelta(seconds=1)).model_copy(
        update={"devices": [Device(address=IPv4Address("10.42.7.40"), other_ports=[23])]}
    )

    assert "| 10.42.7.40 | - |" in render(report)
