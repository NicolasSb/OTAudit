from datetime import UTC, datetime
from ipaddress import IPv4Address

from otaudit import net
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


def _datagram(source, destination, source_port, destination_port, payload=b"\x00"):
    return Segment(
        timestamp=datetime(2023, 11, 14, 22, 0, tzinfo=UTC).timestamp(),
        source=IPv4Address(source),
        destination=IPv4Address(destination),
        source_port=source_port,
        destination_port=destination_port,
        sequence=0,
        flags=0,
        payload=payload,
        vlan=None,
        transport=net.PROTOCOL_UDP,
    )


def test_udp_service_answering_is_recorded(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_datagram("10.42.7.10", "10.42.7.20", 50000, 161))
    analyser.feed(_datagram("10.42.7.20", "10.42.7.10", 161, 50000))

    assert device(analyser.devices(), "10.42.7.20").other_ports == [161]
    assert analyser.packets == 1


def test_unanswered_udp_request_is_not_recorded(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_datagram("10.42.7.10", "10.42.7.20", 50000, 161))

    assert device(analyser.devices(), "10.42.7.20").other_ports == []


def test_tftp_answer_from_a_new_port_is_recorded(sample_scope):
    # A TFTP server answers from a fresh port, never from 69.
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_datagram("10.42.7.10", "10.42.7.20", 50000, 69))
    analyser.feed(_datagram("10.42.7.20", "10.42.7.10", 61234, 50000))

    assert device(analyser.devices(), "10.42.7.20").other_ports == [69]


def test_bacnet_between_equal_ports_is_recorded(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, flags=0x18))
    analyser.feed(_datagram("10.42.7.20", "10.42.7.63", 47808, 47808))

    assert device(analyser.devices(), "10.42.7.20").other_ports == [47808]


def test_host_seen_only_through_a_legacy_service_is_inventoried(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.40", "10.42.7.11", 23, 51200, flags=0x18, payload=b"login: "))

    switch = device(analyser.devices(), "10.42.7.40")
    assert switch.roles == []
    assert switch.protocols == []
    assert switch.other_ports == [23]


def test_host_with_nothing_to_report_is_left_out(sample_scope):
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.40", "10.42.7.11", 51200, 443, flags=0x18, payload=b"x"))

    assert analyser.devices() == []


def test_reused_connection_is_not_a_stream_gap(sample_scope):
    from otaudit.synthesis import modbus_request

    request = modbus_request(1, 1, 3, b"\x00\x00\x00\x01")
    analyser = Analyser(sample_scope)
    for initial in (1000, 900_000):
        analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, 0x02, sequence=initial))
        analyser.feed(
            _segment("10.42.7.10", "10.42.7.20", 40000, 502, 0x18, request, sequence=initial + 1)
        )

    assert analyser.stream_gaps == 0
    assert conversation(analyser.conversations(), "10.42.7.10", "10.42.7.20").requests == 2


def test_lost_first_segment_after_syn_is_a_stream_gap(sample_scope):
    from otaudit.synthesis import modbus_request

    request = modbus_request(1, 1, 3, b"\x00\x00\x00\x01")
    analyser = Analyser(sample_scope)
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, 0x02, sequence=1000))
    analyser.feed(_segment("10.42.7.10", "10.42.7.20", 40000, 502, 0x18, request, sequence=1013))

    assert analyser.stream_gaps == 1


def test_umas_stop_counts_as_a_control_request(sample_scope):
    analyser = Analyser(sample_scope)
    stop = bytes.fromhex("000800000004005a0141")
    failed = bytes.fromhex("000800000004005a01fd")
    analyser.feed(_segment("10.42.7.11", "10.42.7.21", 40000, 502, 0x18, stop))
    analyser.feed(_segment("10.42.7.21", "10.42.7.11", 502, 40000, 0x18, failed))

    engineering = conversation(analyser.conversations(), "10.42.7.11", "10.42.7.21")
    assert engineering.controls == 1
    assert engineering.functions == {"umas: stop plc": 1}
    assert engineering.exceptions == {"umas error": 1}


def test_written_ranges_are_merged_per_unit_and_table(sample_scope):
    from otaudit.synthesis import modbus_request

    analyser = Analyser(sample_scope)
    writes = [
        modbus_request(1, 1, 6, b"\x00\x64\x00\x01"),
        modbus_request(2, 1, 6, b"\x00\x65\x00\x01"),
        modbus_request(3, 1, 16, b"\x00\xc8\x00\x03\x06" + b"\x00" * 6),
        modbus_request(4, 1, 6, b"\x00\x64\x00\x02"),
        modbus_request(5, 2, 5, b"\x00\x10\xff\x00"),
    ]
    sequence = 1
    for frame in writes:
        analyser.feed(
            _segment("10.42.7.10", "10.42.7.20", 40000, 502, 0x18, frame, sequence=sequence)
        )
        sequence += len(frame)

    polling = conversation(analyser.conversations(), "10.42.7.10", "10.42.7.20")
    assert polling.written == {
        "unit 1 holding registers": [(100, 101), (200, 202)],
        "unit 2 coils": [(16, 16)],
    }
    assert polling.written_ranges == [
        "unit 1 holding registers 100-101, 200-202",
        "unit 2 coils 16",
    ]
