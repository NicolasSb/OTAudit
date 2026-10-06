"""Link, network and transport decoding, down to the TCP or UDP payload."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from .pcapfile import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    Record,
)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


@dataclass(frozen=True)
class Segment:
    timestamp: float
    source: IPv4Address
    destination: IPv4Address
    source_port: int
    destination_port: int
    sequence: int
    flags: int
    payload: bytes
    vlan: int | None
    transport: int = PROTOCOL_TCP

    @property
    def flow(self) -> tuple[IPv4Address, int, IPv4Address, int]:
        return self.source, self.source_port, self.destination, self.destination_port


def decode(record: Record, linktype: int) -> Segment | None:
    """Return the TCP segment or UDP datagram carried by a record, or None.

    Anything that is not IPv4 TCP or UDP is skipped silently: a capture taken on
    a control network carries ARP, STP and multicast discovery that the audit
    does not use. UDP datagrams come back as segments with no sequence number
    and no flags.
    """
    if linktype == LINKTYPE_ETHERNET:
        payload, vlan = _strip_ethernet(record.data)
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        payload, vlan = record.data, None
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(record.data) < 16 or struct.unpack("!H", record.data[14:16])[0] != ETHERTYPE_IPV4:
            return None
        payload, vlan = record.data[16:], None
    else:
        return None
    if payload is None:
        return None
    return _decode_ipv4(record.timestamp, payload, vlan)


def _strip_ethernet(frame: bytes) -> tuple[bytes | None, int | None]:
    if len(frame) < 14:
        return None, None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    vlan: int | None = None
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(frame) < offset + 4:
            return None, None
        tag, ethertype = struct.unpack("!HH", frame[offset : offset + 4])
        if vlan is None:
            vlan = tag & 0x0FFF
        offset += 4
    if ethertype != ETHERTYPE_IPV4:
        return None, vlan
    return frame[offset:], vlan


def _decode_ipv4(timestamp: float, packet: bytes, vlan: int | None) -> Segment | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or len(packet) < header_length:
        return None
    total_length = struct.unpack("!H", packet[2:4])[0]
    fragment = struct.unpack("!H", packet[6:8])[0]
    if fragment & 0x1FFF:
        # Non-initial fragment: the transport header is in an earlier packet.
        return None
    if packet[9] not in (PROTOCOL_TCP, PROTOCOL_UDP):
        return None
    source = IPv4Address(packet[12:16])
    destination = IPv4Address(packet[16:20])
    end = min(total_length, len(packet)) if total_length >= header_length else len(packet)
    if packet[9] == PROTOCOL_UDP:
        return _decode_udp(timestamp, source, destination, packet[header_length:end], vlan)
    return _decode_tcp(timestamp, source, destination, packet[header_length:end], vlan)


def _decode_tcp(
    timestamp: float,
    source: IPv4Address,
    destination: IPv4Address,
    segment: bytes,
    vlan: int | None,
) -> Segment | None:
    if len(segment) < 20:
        return None
    source_port, destination_port, sequence = struct.unpack("!HHI", segment[:8])
    data_offset = (segment[12] >> 4) * 4
    if data_offset < 20 or len(segment) < data_offset:
        return None
    return Segment(
        timestamp=timestamp,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        sequence=sequence,
        flags=segment[13],
        payload=segment[data_offset:],
        vlan=vlan,
    )


def _decode_udp(
    timestamp: float,
    source: IPv4Address,
    destination: IPv4Address,
    datagram: bytes,
    vlan: int | None,
) -> Segment | None:
    if len(datagram) < 8:
        return None
    source_port, destination_port = struct.unpack("!HH", datagram[:4])
    return Segment(
        timestamp=timestamp,
        source=source,
        destination=destination,
        source_port=source_port,
        destination_port=destination_port,
        sequence=0,
        flags=0,
        payload=datagram[8:],
        vlan=vlan,
        transport=PROTOCOL_UDP,
    )
