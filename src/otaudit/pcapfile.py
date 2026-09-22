"""Reader for classic libpcap capture files.

Deliberately not built on scapy or dpkt: the tool is meant to be read and
approved by the audited party before it runs, and a hundred lines of struct
unpacking are easier to approve than a packet manipulation framework.
pcapng is not supported; convert with `editcap -F pcap in.pcapng out.pcap`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

GLOBAL_HEADER = 24
RECORD_HEADER = 16

MAGIC_MICROSECONDS = 0xA1B2C3D4
MAGIC_NANOSECONDS = 0xA1B23C4D

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228


class PcapError(Exception):
    """Raised when a file cannot be parsed as a classic pcap capture."""


@dataclass(frozen=True)
class Record:
    timestamp: float
    data: bytes
    original_length: int

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.original_length


class PcapReader:
    """Iterate over the records of a pcap file.

    >>> with PcapReader(path) as reader:      # doctest: +SKIP
    ...     for record in reader:
    ...         ...
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = path.open("rb")
        try:
            self.endian, self.linktype, self.divisor = self._read_global_header()
        except Exception:
            self._handle.close()
            raise

    def _read_global_header(self) -> tuple[str, int, int]:
        header = self._handle.read(GLOBAL_HEADER)
        if len(header) < GLOBAL_HEADER:
            raise PcapError(f"{self.path}: file shorter than a pcap header")
        (raw_magic,) = struct.unpack("<I", header[:4])
        if raw_magic == MAGIC_MICROSECONDS:
            endian, divisor = "<", 1_000_000
        elif raw_magic == MAGIC_NANOSECONDS:
            endian, divisor = "<", 1_000_000_000
        elif struct.unpack(">I", header[:4])[0] == MAGIC_MICROSECONDS:
            endian, divisor = ">", 1_000_000
        elif struct.unpack(">I", header[:4])[0] == MAGIC_NANOSECONDS:
            endian, divisor = ">", 1_000_000_000
        else:
            raise PcapError(
                f"{self.path}: unknown magic {raw_magic:#010x}; "
                "pcapng files must be converted first"
            )
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        return endian, linktype, divisor

    def __iter__(self) -> Iterator[Record]:
        while True:
            header = self._handle.read(RECORD_HEADER)
            if not header:
                return
            if len(header) < RECORD_HEADER:
                raise PcapError(f"{self.path}: truncated record header")
            seconds, fraction, captured, original = struct.unpack(self.endian + "IIII", header)
            payload = self._handle.read(captured)
            if len(payload) < captured:
                raise PcapError(f"{self.path}: truncated record payload")
            yield Record(
                timestamp=seconds + fraction / self.divisor,
                data=payload,
                original_length=original,
            )

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def write_pcap(path: Path, records: list[Record], linktype: int = LINKTYPE_ETHERNET) -> None:
    """Write a classic pcap file. Used to build test fixtures and sample captures."""
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", MAGIC_MICROSECONDS, 2, 4, 0, 0, 262144, linktype))
        for record in records:
            seconds = int(record.timestamp)
            microseconds = round((record.timestamp - seconds) * 1_000_000)
            if microseconds == 1_000_000:
                seconds, microseconds = seconds + 1, 0
            handle.write(
                struct.pack(
                    "<IIII", seconds, microseconds, len(record.data), record.original_length
                )
            )
            handle.write(record.data)
