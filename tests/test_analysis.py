from datetime import UTC, datetime
from ipaddress import IPv4Address

from otaudit.analysis import Analyser, analyse
from otaudit.models import Protocol
from otaudit.net import Segment


def device(devices, address):
    return next(item for item in devices if item.address == IPv4Address(address))


def conversation(conversations, client, server):
    return next(
        item
        for item in conversations
        if item.client == IPv4Address(client) and item.server == IPv4Address(server)
    )


def test_inventory_from_the_sample_capture(sample_capture, sample_scope):
    capture, devices, _ = analyse(sample_capture, sample_scope)

    assert capture.packets > 0
    assert capture.industrial_frames > 0
    assert capture.within_window
    assert {str(item.address) for item in devices} >= {
        "10.42.7.10",
        "10.42.7.20",
        "10.42.7.30",
        "10.42.9.80",
    }
    assert device(devices, "10.42.7.20").roles == ["server"]
    assert device(devices, "10.42.7.10").roles == ["client"]


def test_scope_membership_is_resolved(sample_capture, sample_scope):
    _, devices, _ = analyse(sample_capture, sample_scope)

    assert device(devices, "10.42.7.20").in_scope
    assert not device(devices, "10.42.9.80").in_scope
    assert not device(devices, "10.42.9.80").excluded


def test_modbus_functions_and_writes_are_counted(sample_capture, sample_scope):
    _, _, conversations = analyse(sample_capture, sample_scope)
    polling = conversation(conversations, "10.42.7.10", "10.42.7.20")

    assert polling.protocol is Protocol.MODBUS
    assert polling.requests == 41
    assert polling.responses == 41
    assert polling.writes == 1
    assert polling.functions["read holding registers"] == 40
    assert polling.unit_ids == [1]


def test_exceptions_are_counted(sample_capture, sample_scope):
    _, _, conversations = analyse(sample_capture, sample_scope)
    noisy = conversation(conversations, "10.42.7.10", "10.42.7.22")

    assert noisy.exceptions == {"illegal data address": 20}
    assert noisy.exception_ratio == 0.5


def test_identification_is_attached_to_the_device(sample_capture, sample_scope):
    _, devices, _ = analyse(sample_capture, sample_scope)

    assert device(devices, "10.42.7.21").identification["vendor"] == "Schneider Electric"
    assert device(devices, "10.42.7.30").identification["article_number"].startswith("6ES7")
    assert device(devices, "10.42.7.30").identification["plc_name"] == "LINE2_CPU"


def test_s7_write_is_seen(sample_capture, sample_scope):
    _, _, conversations = analyse(sample_capture, sample_scope)
    engineering = conversation(conversations, "10.42.7.11", "10.42.7.30")

    assert engineering.protocol is Protocol.S7COMM
    assert engineering.writes == 1


def test_legacy_service_is_recorded(sample_capture, sample_scope):
    _, devices, _ = analyse(sample_capture, sample_scope)

    assert device(devices, "10.42.7.20").other_ports == [23]


def test_polling_statistics(sample_capture, sample_scope):
    _, _, conversations = analyse(sample_capture, sample_scope)
    polling = conversation(conversations, "10.42.7.10", "10.42.7.20")

    assert polling.mean_interval_ms is not None
    assert 200 < polling.mean_interval_ms < 1200


def test_capture_outside_the_window_is_flagged(sample_scope, tmp_path):
    from otaudit.synthesis import CaptureBuilder, modbus_request

    builder = CaptureBuilder(start=1_600_000_000.0)
    builder.add(
        0.0, "10.42.7.10", "10.42.7.20", 40000, 502, modbus_request(1, 1, 3, b"\x00\x00\x00\x01")
    )
    path = builder.write(tmp_path / "out-of-window.pcap")

    capture, _, _ = analyse(path, sample_scope)

    assert not capture.within_window


def test_empty_capture_yields_nothing(sample_scope, tmp_path):
    from otaudit.pcapfile import write_pcap

    path = tmp_path / "empty.pcap"
    write_pcap(path, [])
    capture, devices, conversations = analyse(path, sample_scope)

    assert capture.packets == 0
    assert capture.started_at is None
    assert devices == []
    assert conversations == []


def test_segment_without_payload_registers_the_role(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(
        Segment(
            timestamp=datetime(2023, 11, 14, 22, 0, tzinfo=UTC).timestamp(),
            source=IPv4Address("10.42.7.10"),
            destination=IPv4Address("10.42.7.20"),
            source_port=40000,
            destination_port=502,
            sequence=1,
            flags=0x02,
            payload=b"",
            vlan=None,
        )
    )

    assert analyser.devices()[1].roles == ["server"]
    assert analyser.conversations() == []


def _segment(source, destination, source_port, destination_port, flags, payload=b"", sequence=1):
    return Segment(
        timestamp=datetime(2023, 11, 14, 22, 0, tzinfo=UTC).timestamp(),
        source=IPv4Address(source),
        destination=IPv4Address(destination),
        source_port=source_port,
        destination_port=destination_port,
        sequence=sequence,
        flags=flags,
        payload=payload,
        vlan=None,
    )


def test_refused_connection_does_not_count_as_a_service(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 51200, 23, flags=0x02))
    analyser.feed(_segment("10.42.7.20", "10.42.7.10", 23, 51200, flags=0x14))

    assert device(analyser.devices(), "10.42.7.20").other_ports == []


def test_unanswered_connection_attempt_does_not_count_as_a_service(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 51200, 23, flags=0x02))

    assert device(analyser.devices(), "10.42.7.20").other_ports == []


def test_accepted_connection_counts_as_a_service(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 51200, 23, flags=0x02))
    analyser.feed(_segment("10.42.7.20", "10.42.7.10", 23, 51200, flags=0x12))

    assert device(analyser.devices(), "10.42.7.20").other_ports == [23]


def test_client_ephemeral_port_is_not_mistaken_for_a_service(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 44818, 443, flags=0x18, payload=b"x"))

    assert device(analyser.devices(), "10.42.7.10").other_ports == []
