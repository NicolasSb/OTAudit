"""Blocks are packed field by field from the pcapng specification
(draft-ietf-opsawg-pcapng), not produced by a writer, so a misreading of the
format cannot be hidden by the same misreading on the writing side."""

import struct

import pytest

from otaudit.pcapfile import LINKTYPE_ETHERNET, LINKTYPE_RAW, PcapError, Record, write_pcap
from otaudit.pcapng import PcapngReader, open_capture

BYTE_ORDER_MAGIC = 0x1A2B3C4D


def block(kind, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def section(endian="<"):
    body = struct.pack(endian + "IHHq", BYTE_ORDER_MAGIC, 1, 0, -1)
    return block(0x0A0D0D0A, body, endian)


def interface(linktype=LINKTYPE_ETHERNET, options=b"", endian="<"):
    return block(1, struct.pack(endian + "HHI", linktype, 0, 0) + options, endian)


def tsresol(value, endian="<"):
    return struct.pack(endian + "HH", 9, 1) + bytes([value, 0, 0, 0]) + b"\x00" * 4


def enhanced(data, ticks, interface_id=0, original=None, endian="<"):
    original = len(data) if original is None else original
    header = struct.pack(
        endian + "IIIII", interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), original
    )
    return block(6, header + data, endian)


def read(path):
    with PcapngReader(path) as reader:
        return list(reader)


def test_enhanced_packet_in_microseconds(tmp_path):
    path = tmp_path / "capture.pcapng"
    path.write_bytes(section() + interface() + enhanced(b"\x01\x02\x03", 1_700_000_000_500_000))

    (record,) = read(path)

    assert record.data == b"\x01\x02\x03"
    assert record.timestamp == pytest.approx(1_700_000_000.5)
    assert record.linktype == LINKTYPE_ETHERNET
    assert not record.truncated


def test_big_endian_section(tmp_path):
    path = tmp_path / "be.pcapng"
    path.write_bytes(
        section(">") + interface(endian=">") + enhanced(b"\xaa", 1_700_000_000_250_000, endian=">")
    )

    (record,) = read(path)

    assert record.data == b"\xaa"
    assert record.timestamp == pytest.approx(1_700_000_000.25)


def test_nanosecond_resolution_option(tmp_path):
    path = tmp_path / "ns.pcapng"
    path.write_bytes(
        section() + interface(options=tsresol(9)) + enhanced(b"\x01", 1_700_000_000_500_000_000)
    )

    (record,) = read(path)

    assert record.timestamp == pytest.approx(1_700_000_000.5)


def test_power_of_two_resolution_option(tmp_path):
    path = tmp_path / "pow2.pcapng"
    path.write_bytes(section() + interface(options=tsresol(0x8A)) + enhanced(b"\x01", 3 * 1024))

    (record,) = read(path)

    assert record.timestamp == pytest.approx(3.0)


def test_each_packet_takes_the_linktype_of_its_interface(tmp_path):
    path = tmp_path / "two.pcapng"
    path.write_bytes(
        section()
        + interface(LINKTYPE_ETHERNET)
        + interface(LINKTYPE_RAW)
        + enhanced(b"\x01", 1, interface_id=1)
        + enhanced(b"\x02", 2, interface_id=0)
    )

    assert [record.linktype for record in read(path)] == [LINKTYPE_RAW, LINKTYPE_ETHERNET]


def test_truncated_packet_is_flagged(tmp_path):
    path = tmp_path / "snap.pcapng"
    path.write_bytes(section() + interface() + enhanced(b"\x01\x02", 1, original=1500))

    (record,) = read(path)

    assert record.truncated


def test_obsolete_packet_block_is_read(tmp_path):
    path = tmp_path / "old.pcapng"
    ticks = 1_700_000_000_000_000
    body = struct.pack("<HHIIII", 0, 0, ticks >> 32, ticks & 0xFFFFFFFF, 2, 2) + b"\xab\xcd"
    path.write_bytes(section() + interface() + block(2, body))

    (record,) = read(path)

    assert record.data == b"\xab\xcd"
    assert record.timestamp == pytest.approx(1_700_000_000.0)


def test_blocks_without_packets_are_skipped(tmp_path):
    path = tmp_path / "extra.pcapng"
    name_resolution = block(4, b"\x00\x00\x00\x00")
    statistics = block(5, struct.pack("<III", 0, 0, 0))
    simple_packet = block(3, struct.pack("<I", 1) + b"\x01")
    path.write_bytes(
        section()
        + interface()
        + name_resolution
        + statistics
        + simple_packet
        + enhanced(b"\x01", 1)
    )

    assert [record.data for record in read(path)] == [b"\x01"]


def test_new_section_resets_interfaces(tmp_path):
    path = tmp_path / "sections.pcapng"
    path.write_bytes(
        section()
        + interface(LINKTYPE_ETHERNET)
        + section()
        + interface(LINKTYPE_RAW)
        + enhanced(b"\x01", 1, interface_id=0)
    )

    assert [record.linktype for record in read(path)] == [LINKTYPE_RAW]


def test_packet_on_undeclared_interface_is_rejected(tmp_path):
    path = tmp_path / "orphan.pcapng"
    path.write_bytes(section() + interface() + enhanced(b"\x01", 1, interface_id=3))

    with pytest.raises(PcapError, match="interface 3"):
        read(path)


def test_truncated_block_is_rejected(tmp_path):
    path = tmp_path / "cut.pcapng"
    path.write_bytes((section() + interface() + enhanced(b"\x01\x02\x03\x04", 1))[:-6])

    with pytest.raises(PcapError, match="truncated block"):
        read(path)


def test_bad_byte_order_magic_is_rejected(tmp_path):
    path = tmp_path / "bad.pcapng"
    path.write_bytes(block(0x0A0D0D0A, struct.pack("<IHHq", 0xDEADBEEF, 1, 0, -1)))

    with pytest.raises(PcapError, match="byte-order magic"):
        read(path)


def test_open_capture_picks_the_reader_from_the_magic(tmp_path):
    classic = tmp_path / "classic.pcap"
    write_pcap(classic, [Record(timestamp=1.0, data=b"\x01", original_length=1)])
    modern = tmp_path / "modern.pcapng"
    modern.write_bytes(section() + interface(LINKTYPE_RAW) + enhanced(b"\x02", 1))

    with open_capture(classic) as reader:
        assert [(r.data, r.linktype) for r in reader] == [(b"\x01", LINKTYPE_ETHERNET)]
    with open_capture(modern) as reader:
        assert [(r.data, r.linktype) for r in reader] == [(b"\x02", LINKTYPE_RAW)]


def test_analysis_reads_pcapng_like_pcap(sample_capture, sample_scope, tmp_path):
    from otaudit.analysis import analyse
    from otaudit.pcapfile import PcapReader

    with PcapReader(sample_capture) as reader:
        packets = b"".join(
            enhanced(record.data, round(record.timestamp * 1_000_000)) for record in reader
        )
    converted = tmp_path / "demo.pcapng"
    converted.write_bytes(section() + interface() + packets)

    _, pcap_devices, pcap_conversations = analyse(sample_capture, sample_scope)
    _, pcapng_devices, pcapng_conversations = analyse(converted, sample_scope)

    assert pcapng_devices == pcap_devices
    assert pcapng_conversations == pcap_conversations
