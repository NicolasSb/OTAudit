import struct

import pytest

from otaudit.pcapfile import (
    LINKTYPE_ETHERNET,
    MAGIC_NANOSECONDS,
    PcapError,
    PcapReader,
    Record,
    write_pcap,
)


def test_round_trip(tmp_path):
    path = tmp_path / "capture.pcap"
    records = [
        Record(timestamp=1_700_000_000.5, data=b"\x01\x02\x03", original_length=3),
        Record(timestamp=1_700_000_001.25, data=b"\x04", original_length=1),
    ]
    write_pcap(path, records)

    with PcapReader(path) as reader:
        assert reader.linktype == LINKTYPE_ETHERNET
        read = list(reader)

    assert [item.data for item in read] == [b"\x01\x02\x03", b"\x04"]
    assert read[0].timestamp == pytest.approx(1_700_000_000.5)
    assert read[1].timestamp == pytest.approx(1_700_000_001.25)


def test_truncated_record_is_flagged(tmp_path):
    path = tmp_path / "capture.pcap"
    write_pcap(path, [Record(timestamp=1.0, data=b"\x01\x02", original_length=1500)])
    with PcapReader(path) as reader:
        record = next(iter(reader))
    assert record.truncated


def test_big_endian_and_nanosecond_magic(tmp_path):
    path = tmp_path / "be.pcap"
    header = struct.pack(">IHHiIII", MAGIC_NANOSECONDS, 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET)
    body = struct.pack(">IIII", 1_700_000_000, 500_000_000, 2, 2) + b"\xaa\xbb"
    path.write_bytes(header + body)

    with PcapReader(path) as reader:
        record = next(iter(reader))

    assert reader.endian == ">"
    assert record.timestamp == pytest.approx(1_700_000_000.5)


def test_unknown_magic_is_rejected(tmp_path):
    path = tmp_path / "nope.pcap"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError, match="pcapng"):
        PcapReader(path)


def test_short_file_is_rejected(tmp_path):
    path = tmp_path / "short.pcap"
    path.write_bytes(b"\x00" * 10)
    with pytest.raises(PcapError, match="shorter"):
        PcapReader(path)


def test_truncated_payload_is_rejected(tmp_path):
    path = tmp_path / "cut.pcap"
    write_pcap(path, [Record(timestamp=1.0, data=b"\x01\x02\x03\x04", original_length=4)])
    path.write_bytes(path.read_bytes()[:-2])
    with pytest.raises(PcapError, match="truncated record payload"), PcapReader(path) as reader:
        list(reader)
