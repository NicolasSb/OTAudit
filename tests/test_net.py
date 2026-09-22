import struct
from ipaddress import IPv4Address

from otaudit import net
from otaudit.pcapfile import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW, Record
from otaudit.synthesis import tcp_frame


def record(data: bytes) -> Record:
    return Record(timestamp=1.0, data=data, original_length=len(data))


def test_decodes_ethernet_ipv4_tcp():
    frame = tcp_frame("10.0.0.1", "10.0.0.2", 40000, 502, 1000, b"payload")
    segment = net.decode(record(frame), LINKTYPE_ETHERNET)

    assert segment is not None
    assert segment.source == IPv4Address("10.0.0.1")
    assert segment.destination == IPv4Address("10.0.0.2")
    assert segment.source_port == 40000
    assert segment.destination_port == 502
    assert segment.sequence == 1000
    assert segment.payload == b"payload"
    assert segment.vlan is None


def test_decodes_vlan_tagged_frame():
    frame = tcp_frame("10.0.0.1", "10.0.0.2", 40000, 502, 1, b"x")
    tagged = frame[:12] + struct.pack("!HHH", 0x8100, 0x0065, 0x0800) + frame[14:]
    segment = net.decode(record(tagged), LINKTYPE_ETHERNET)

    assert segment is not None
    assert segment.vlan == 101
    assert segment.payload == b"x"


def test_raw_and_sll_linktypes():
    frame = tcp_frame("10.0.0.1", "10.0.0.2", 40000, 502, 1, b"x")
    ip_packet = frame[14:]

    assert net.decode(record(ip_packet), LINKTYPE_RAW) is not None

    sll = b"\x00" * 14 + struct.pack("!H", 0x0800) + ip_packet
    assert net.decode(record(sll), LINKTYPE_LINUX_SLL) is not None


def test_skips_non_ipv4_and_non_tcp():
    arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28
    assert net.decode(record(arp), LINKTYPE_ETHERNET) is None

    frame = bytearray(tcp_frame("10.0.0.1", "10.0.0.2", 40000, 502, 1, b"x"))
    frame[14 + 9] = 17  # UDP
    assert net.decode(record(bytes(frame)), LINKTYPE_ETHERNET) is None


def test_skips_non_initial_fragment():
    frame = bytearray(tcp_frame("10.0.0.1", "10.0.0.2", 40000, 502, 1, b"x"))
    frame[14 + 6 : 14 + 8] = struct.pack("!H", 0x0001)
    assert net.decode(record(bytes(frame)), LINKTYPE_ETHERNET) is None


def test_unknown_linktype_and_short_frames():
    assert net.decode(record(b"\x00" * 60), 999) is None
    assert net.decode(record(b"\x00" * 8), LINKTYPE_ETHERNET) is None
