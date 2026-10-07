"""Reader for pcapng capture files, the default output of Wireshark and dumpcap.

Follows draft-ietf-opsawg-pcapng. Only what an audit needs is decoded: section
headers for byte order, interface descriptions for link type and timestamp
resolution, and the blocks that carry packets. Simple packet blocks carry no
timestamp and dumpcap does not write them, so they are skipped rather than
given a time that would distort the capture window. Name resolution,
statistics and custom blocks are skipped as well.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from .pcapfile import PcapError, PcapReader, Record

SECTION_HEADER = 0x0A0D0D0A
INTERFACE_DESCRIPTION = 0x00000001
OBSOLETE_PACKET = 0x00000002
ENHANCED_PACKET = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D

OPTION_END = 0
OPTION_TSRESOL = 9
DEFAULT_TICKS_PER_SECOND = 1_000_000


@dataclass(frozen=True)
class _Interface:
    linktype: int
    ticks_per_second: int


class PcapngReader:
    """Iterate over the packets of a pcapng file, each with its interface link type."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = path.open("rb")
        self._endian = "<"
        self._interfaces: list[_Interface] = []

    def __iter__(self) -> Iterator[Record]:
        while True:
            head = self._handle.read(8)
            if not head:
                return
            if len(head) < 8:
                raise PcapError(f"{self.path}: truncated block header")
            if struct.unpack("<I", head[:4])[0] == SECTION_HEADER:
                self._start_section(head)
                continue
            kind, length = struct.unpack(self._endian + "II", head)
            body = self._read_body(length)
            if kind == INTERFACE_DESCRIPTION:
                self._interfaces.append(self._interface(body))
            elif kind == ENHANCED_PACKET:
                yield self._enhanced_packet(body)
            elif kind == OBSOLETE_PACKET:
                yield self._obsolete_packet(body)

    def _start_section(self, head: bytes) -> None:
        magic_bytes = self._handle.read(4)
        if len(magic_bytes) < 4:
            raise PcapError(f"{self.path}: truncated block header")
        if struct.unpack("<I", magic_bytes)[0] == BYTE_ORDER_MAGIC:
            self._endian = "<"
        elif struct.unpack(">I", magic_bytes)[0] == BYTE_ORDER_MAGIC:
            self._endian = ">"
        else:
            raise PcapError(f"{self.path}: bad byte-order magic in section header")
        length = struct.unpack(self._endian + "I", head[4:8])[0]
        # The magic is part of the body, already consumed.
        self._read_body(length, already_read=4)
        self._interfaces = []

    def _read_body(self, length: int, already_read: int = 0) -> bytes:
        if length < 12 or length % 4:
            raise PcapError(f"{self.path}: invalid block length {length}")
        remaining = length - 8 - already_read
        data = self._handle.read(remaining)
        if len(data) < remaining:
            raise PcapError(f"{self.path}: truncated block")
        return data[:-4]

    def _interface(self, body: bytes) -> _Interface:
        if len(body) < 8:
            raise PcapError(f"{self.path}: truncated interface description")
        linktype = struct.unpack(self._endian + "H", body[:2])[0]
        ticks = DEFAULT_TICKS_PER_SECOND
        offset = 8
        while offset + 4 <= len(body):
            code, size = struct.unpack(self._endian + "HH", body[offset : offset + 4])
            if code == OPTION_END:
                break
            value = body[offset + 4 : offset + 4 + size]
            if code == OPTION_TSRESOL and value:
                exponent = value[0] & 0x7F
                ticks = 2**exponent if value[0] & 0x80 else 10**exponent
            offset += 4 + size + (-size % 4)
        return _Interface(linktype=linktype, ticks_per_second=ticks)

    def _enhanced_packet(self, body: bytes) -> Record:
        if len(body) < 20:
            raise PcapError(f"{self.path}: truncated enhanced packet block")
        interface_id, high, low, captured, original = struct.unpack(
            self._endian + "IIIII", body[:20]
        )
        return self._record(interface_id, high, low, body[20 : 20 + captured], original)

    def _obsolete_packet(self, body: bytes) -> Record:
        if len(body) < 20:
            raise PcapError(f"{self.path}: truncated packet block")
        interface_id, _drops, high, low, captured, original = struct.unpack(
            self._endian + "HHIIII", body[:20]
        )
        return self._record(interface_id, high, low, body[20 : 20 + captured], original)

    def _record(self, interface_id: int, high: int, low: int, data: bytes, original: int) -> Record:
        if interface_id >= len(self._interfaces):
            raise PcapError(f"{self.path}: packet on undeclared interface {interface_id}")
        interface = self._interfaces[interface_id]
        ticks = (high << 32) | low
        seconds, fraction = divmod(ticks, interface.ticks_per_second)
        return Record(
            timestamp=seconds + fraction / interface.ticks_per_second,
            data=data,
            original_length=original,
            linktype=interface.linktype,
        )

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> PcapngReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def open_capture(path: Path) -> PcapReader | PcapngReader:
    """Open a pcap or pcapng file, chosen from its first four bytes."""
    with path.open("rb") as handle:
        magic = handle.read(4)
    if len(magic) == 4 and struct.unpack("<I", magic)[0] == SECTION_HEADER:
        return PcapngReader(path)
    return PcapReader(path)
