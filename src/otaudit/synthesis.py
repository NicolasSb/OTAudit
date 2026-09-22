"""Generation of synthetic captures.

Real captures from a production site cannot be published, and a tool with no
sample is a tool nobody tries. Everything here builds well-formed Ethernet/IPv4/TCP
frames carrying handmade Modbus and S7 payloads, with correct checksums, so the
result opens in Wireshark like any other capture.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path

from .pcapfile import LINKTYPE_ETHERNET, Record, write_pcap
from .protocols import modbus, s7


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac(address: IPv4Address) -> bytes:
    return b"\x02\x00" + int(address).to_bytes(4, "big")


def tcp_frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    payload: bytes,
    flags: int = 0x18,
) -> bytes:
    src, dst = IPv4Address(source), IPv4Address(destination)
    tcp = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        flags,
        8192,
        0,
        0,
    )
    pseudo = src.packed + dst.packed + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    total_length = 20 + len(tcp) + len(payload)
    ip = (
        struct.pack("!BBHHHBBH", 0x45, 0, total_length, 0x1234, 0x4000, 64, 6, 0)
        + src.packed
        + dst.packed
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return _mac(dst) + _mac(src) + b"\x08\x00" + ip + tcp + payload


def modbus_request(transaction: int, unit: int, function: int, body: bytes = b"") -> bytes:
    pdu = bytes([function]) + body
    return struct.pack("!HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


def modbus_response(transaction: int, unit: int, function: int, body: bytes = b"") -> bytes:
    return modbus_request(transaction, unit, function, body)


def modbus_exception(transaction: int, unit: int, function: int, code: int) -> bytes:
    return modbus_request(transaction, unit, function | 0x80, bytes([code]))


def modbus_identification(transaction: int, unit: int, objects: dict[int, str]) -> bytes:
    body = bytes([modbus.MEI_READ_DEVICE_ID, 0x01, 0x01, 0x00, 0x00, len(objects)])
    for object_id, value in objects.items():
        encoded = value.encode("latin-1")
        body += bytes([object_id, len(encoded)]) + encoded
    return modbus_request(transaction, unit, 43, body)


def s7_frame(rosctr: int, parameter: bytes, data: bytes = b"", error: bytes = b"") -> bytes:
    header = struct.pack("!BBHHHH", s7.S7_PROTOCOL_ID, rosctr, 0, 0x0400, len(parameter), len(data))
    payload = header + error + parameter + data
    cotp = bytes([0x02, s7.COTP_DATA, 0x80])
    return struct.pack("!BBH", 3, 0, 4 + len(cotp) + len(payload)) + cotp + payload


def s7_job(function: int) -> bytes:
    return s7_frame(0x01, bytes([function, 0x00]))


def s7_szl_response(szl_id: int, records: list[bytes], record_size: int) -> bytes:
    # Userdata responses carry the return code in the parameter block, and the
    # S7 header stays at ten bytes: no error class or error code, unlike ack_data.
    parameter = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
    body = struct.pack("!HHHH", szl_id, 0x0000, record_size, len(records)) + b"".join(records)
    data = struct.pack("!BBH", 0xFF, 0x09, len(body) + 4) + body
    return s7_frame(0x07, parameter, data)


def szl_module_record(article: str) -> bytes:
    return struct.pack("!H", 1) + article.encode("latin-1").ljust(20, b"\x00") + b"\x00" * 6


def szl_component_record(index: int, value: str) -> bytes:
    return struct.pack("!H", index) + value.encode("latin-1").ljust(32, b"\x00")


@dataclass
class CaptureBuilder:
    """Accumulate frames with per-direction sequence numbers."""

    start: float = 1_700_000_000.0
    records: list[Record] = field(default_factory=list)
    _sequences: dict[tuple[str, int, str, int], int] = field(default_factory=dict)

    def add(
        self,
        offset: float,
        source: str,
        destination: str,
        source_port: int,
        destination_port: int,
        payload: bytes,
    ) -> None:
        key = (source, source_port, destination, destination_port)
        sequence = self._sequences.get(key, 1000)
        frame = tcp_frame(source, destination, source_port, destination_port, sequence, payload)
        self._sequences[key] = sequence + len(payload)
        self.records.append(
            Record(timestamp=self.start + offset, data=frame, original_length=len(frame))
        )

    def write(self, path: Path) -> Path:
        write_pcap(path, self.records, LINKTYPE_ETHERNET)
        return path


def build_sample_capture(path: Path) -> Path:
    """Build the capture shipped in samples/, modelled on a small control network.

    A supervision host polls three Modbus slaves and writes to one of them. A
    S7-1200 answers an engineering station, which reads its identification and
    writes a variable. One slave answers with exceptions to a stale polling
    template, one host exposes telnet, and a second writer appears from outside
    the declared range.
    """
    builder = CaptureBuilder()
    scada = "10.42.7.10"
    engineering = "10.42.7.11"
    maintenance = "10.42.9.80"
    slaves = ["10.42.7.20", "10.42.7.21", "10.42.7.22"]
    plc = "10.42.7.30"

    offset = 0.0
    transaction = 1
    for cycle in range(40):
        for index, slave in enumerate(slaves):
            builder.add(
                offset,
                scada,
                slave,
                40000 + index,
                502,
                modbus_request(transaction, 1, 3, struct.pack("!HH", 0, 10)),
            )
            offset += 0.004
            if slave == slaves[2] and cycle % 2 == 0:
                builder.add(
                    offset,
                    slave,
                    scada,
                    502,
                    40000 + index,
                    modbus_exception(transaction, 1, 3, 2),
                )
            else:
                builder.add(
                    offset,
                    slave,
                    scada,
                    502,
                    40000 + index,
                    modbus_response(transaction, 1, 3, bytes([20]) + b"\x00" * 20),
                )
            transaction += 1
            offset += 0.246

    builder.add(
        offset,
        scada,
        slaves[0],
        40100,
        502,
        modbus_request(transaction, 1, 16, struct.pack("!HHB", 100, 1, 2) + b"\x01\x2c"),
    )
    offset += 0.005
    builder.add(
        offset,
        slaves[0],
        scada,
        502,
        40100,
        modbus_response(transaction, 1, 16, struct.pack("!HH", 100, 1)),
    )
    offset += 1.0

    transaction += 1
    builder.add(
        offset,
        maintenance,
        slaves[0],
        51000,
        502,
        modbus_request(transaction, 1, 6, struct.pack("!HH", 100, 0)),
    )
    offset += 0.006
    builder.add(
        offset,
        slaves[0],
        maintenance,
        502,
        51000,
        modbus_response(transaction, 1, 6, struct.pack("!HH", 100, 0)),
    )
    offset += 0.5

    transaction += 1
    builder.add(
        offset, scada, slaves[1], 40200, 502, modbus_request(transaction, 1, 43, b"\x0e\x01\x00")
    )
    offset += 0.008
    builder.add(
        offset,
        slaves[1],
        scada,
        502,
        40200,
        modbus_identification(
            transaction, 1, {0: "Schneider Electric", 1: "TM241CE40R", 2: "5.1.9.9"}
        ),
    )
    offset += 0.5

    builder.add(offset, engineering, plc, 52000, 102, s7_job(0xF0))
    offset += 0.01
    builder.add(
        offset, plc, engineering, 102, 52000, s7_frame(0x03, bytes([0xF0, 0x00]), error=b"\x00\x00")
    )
    offset += 0.2
    builder.add(
        offset,
        engineering,
        plc,
        52000,
        102,
        s7_frame(0x07, bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])),
    )
    offset += 0.02
    builder.add(
        offset,
        plc,
        engineering,
        102,
        52000,
        s7_szl_response(
            0x001C,
            [
                szl_component_record(1, "LINE2_CPU"),
                szl_component_record(7, "CPU 1214C DC/DC/DC"),
            ],
            34,
        ),
    )
    offset += 0.3
    builder.add(
        offset,
        plc,
        engineering,
        102,
        52000,
        s7_szl_response(0x0011, [szl_module_record("6ES7 214-1AG40-0XB0")], 28),
    )
    offset += 0.3
    builder.add(offset, engineering, plc, 52000, 102, s7_frame(0x01, bytes([0x05, 0x01])))
    offset += 0.02
    builder.add(
        offset, plc, engineering, 102, 52000, s7_frame(0x03, bytes([0x05, 0x01]), error=b"\x00\x00")
    )
    offset += 0.5

    builder.add(offset, maintenance, slaves[0], 51200, 23, b"\xff\xfb\x01")
    offset += 0.05
    builder.add(offset, slaves[0], maintenance, 23, 51200, b"\xff\xfd\x01login: ")

    return builder.write(path)
