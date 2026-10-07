"""Modbus/TCP framing and PDU decoding.

Reference: MODBUS Application Protocol Specification V1.1b3 and MODBUS
Messaging on TCP/IP Implementation Guide V1.0b.

Function 90 carries Schneider Electric's UMAS, used by Unity / EcoStruxure
Control Expert to program Modicon PLCs. It is not published; the codes below
are limited to those documented in Kaspersky ICS CERT, "The secrets of
Schneider Electric's UMAS protocol" (2022). In Schneider's vocabulary a
download sends a program to the PLC and an upload reads it back.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

PORT = 502
MBAP_LENGTH = 7
MAX_PDU = 253

FUNCTION_NAMES = {
    1: "read coils",
    2: "read discrete inputs",
    3: "read holding registers",
    4: "read input registers",
    5: "write single coil",
    6: "write single register",
    7: "read exception status",
    8: "diagnostics",
    11: "get comm event counter",
    12: "get comm event log",
    15: "write multiple coils",
    16: "write multiple registers",
    17: "report server id",
    20: "read file record",
    21: "write file record",
    22: "mask write register",
    23: "read/write multiple registers",
    24: "read fifo queue",
    43: "encapsulated interface transport",
    90: "umas",
}

WRITE_FUNCTIONS = frozenset({5, 6, 15, 16, 21, 22, 23})

COILS = "coils"
HOLDING_REGISTERS = "holding registers"

DIAGNOSTICS = 8
DIAGNOSTIC_NAMES = {
    0x00: "return query data",
    0x01: "restart communications",
    0x02: "return diagnostic register",
    0x04: "force listen only mode",
    0x0A: "clear counters and diagnostic register",
}
# Restart reboots the communication port; listen only mutes the device until restart.
CONTROL_DIAGNOSTICS = frozenset({0x01, 0x04})

UMAS = 90
UMAS_NAMES = {
    0x01: "get com info",
    0x02: "get plc info",
    0x04: "get plc status",
    0x06: "get memory card info",
    0x10: "take plc reservation",
    0x11: "release plc reservation",
    0x12: "keep plc reservation",
    0x20: "read memory block",
    0x21: "write memory block",
    0x30: "begin download",
    0x31: "download packet",
    0x32: "end download",
    0x33: "begin upload",
    0x34: "upload packet",
    0x35: "end upload",
    0x40: "start plc",
    0x41: "stop plc",
}
UMAS_WRITES = frozenset({0x21, 0x30, 0x31, 0x32})
UMAS_CONTROLS = frozenset({0x40, 0x41})
UMAS_ERROR = 0xFD

EXCEPTION_NAMES = {
    1: "illegal function",
    2: "illegal data address",
    3: "illegal data value",
    4: "server device failure",
    5: "acknowledge",
    6: "server device busy",
    8: "memory parity error",
    10: "gateway path unavailable",
    11: "gateway target device failed to respond",
}

MEI_READ_DEVICE_ID = 14
IDENTIFICATION_OBJECTS = {
    0x00: "vendor",
    0x01: "product",
    0x02: "revision",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "application_name",
}


@dataclass(frozen=True)
class Pdu:
    transaction: int
    unit_id: int
    function: int
    is_exception: bool = False
    exception_code: int | None = None
    identification: dict[str, str] = field(default_factory=dict)
    subfunction: int | None = None
    written: tuple[str, int, int] | None = None
    """Table, first address and count of a write request."""

    @property
    def function_name(self) -> str:
        name = FUNCTION_NAMES.get(self.function, f"function {self.function}")
        if self.subfunction is None:
            return name
        if self.function == DIAGNOSTICS:
            detail = DIAGNOSTIC_NAMES.get(self.subfunction, f"sub-function {self.subfunction}")
        else:
            detail = UMAS_NAMES.get(self.subfunction, f"function {self.subfunction:#04x}")
        return f"{name}: {detail}"

    @property
    def exception_name(self) -> str | None:
        if self.function == UMAS and self.is_exception:
            return "umas error"
        if self.exception_code is None:
            return None
        return EXCEPTION_NAMES.get(self.exception_code, f"exception {self.exception_code}")

    @property
    def is_write(self) -> bool:
        if self.function == UMAS:
            return self.subfunction in UMAS_WRITES
        return self.function in WRITE_FUNCTIONS

    @property
    def is_control(self) -> bool:
        if self.function == UMAS:
            return self.subfunction in UMAS_CONTROLS
        return self.function == DIAGNOSTICS and self.subfunction in CONTROL_DIAGNOSTICS


def split_frames(buffer: bytearray) -> list[bytes]:
    """Consume complete Modbus/TCP frames from the head of a stream buffer.

    Returns the frames removed from the buffer. Bytes that cannot start a valid
    MBAP header are discarded one at a time, so a capture that starts in the
    middle of a connection resynchronises instead of failing.
    """
    frames: list[bytes] = []
    while len(buffer) >= MBAP_LENGTH:
        protocol, length = struct.unpack("!HH", buffer[2:6])
        if protocol != 0 or not 2 <= length <= MAX_PDU + 1:
            del buffer[:1]
            continue
        total = 6 + length
        if len(buffer) < total:
            break
        frames.append(bytes(buffer[:total]))
        del buffer[:total]
    return frames


def parse(frame: bytes, request: bool = True) -> Pdu | None:
    """Decode one complete Modbus/TCP frame.

    The direction only matters for UMAS, where the byte after the session key is
    a function code in a request and a status in a response.
    """
    if len(frame) < MBAP_LENGTH + 1:
        return None
    transaction = struct.unpack("!H", frame[0:2])[0]
    unit_id = frame[6]
    function = frame[7]
    body = frame[8:]
    if function & 0x80:
        code = body[0] if body else None
        return Pdu(
            transaction=transaction,
            unit_id=unit_id,
            function=function & 0x7F,
            is_exception=True,
            exception_code=code,
        )
    identification: dict[str, str] = {}
    if function == 43 and len(body) >= 1 and body[0] == MEI_READ_DEVICE_ID:
        identification = _parse_identification(body)
    subfunction: int | None = None
    failed = False
    if function == DIAGNOSTICS and len(body) >= 2:
        subfunction = struct.unpack("!H", body[:2])[0]
    elif function == UMAS and len(body) >= 2:
        if request:
            subfunction = body[1]
        else:
            failed = body[1] == UMAS_ERROR
    return Pdu(
        transaction=transaction,
        unit_id=unit_id,
        function=function,
        is_exception=failed,
        identification=identification,
        subfunction=subfunction,
        written=_written(function, body) if request else None,
    )


def _written(function: int, body: bytes) -> tuple[str, int, int] | None:
    """Locate what a write request targets. Responses echo it and are not decoded."""
    if function in (5, 6, 22) and len(body) >= 2:
        table = COILS if function == 5 else HOLDING_REGISTERS
        return table, struct.unpack("!H", body[:2])[0], 1
    if function in (15, 16) and len(body) >= 4:
        first, count = struct.unpack("!HH", body[:4])
        return (COILS if function == 15 else HOLDING_REGISTERS), first, count
    if function == 23 and len(body) >= 8:
        first, count = struct.unpack("!HH", body[4:8])
        return HOLDING_REGISTERS, first, count
    return None


def _parse_identification(body: bytes) -> dict[str, str]:
    """Decode a Read Device Identification response (MEI type 14).

    Requests share the function code but carry no object list, so a short body
    simply yields nothing.
    """
    if len(body) < 6:
        return {}
    count = body[5]
    offset = 6
    objects: dict[str, str] = {}
    for _ in range(count):
        if offset + 2 > len(body):
            break
        object_id, length = body[offset], body[offset + 1]
        offset += 2
        value = body[offset : offset + length]
        offset += length
        if len(value) < length:
            break
        name = IDENTIFICATION_OBJECTS.get(object_id)
        if name:
            objects[name] = value.decode("latin-1").strip()
    return objects
