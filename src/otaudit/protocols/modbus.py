"""Modbus/TCP framing and PDU decoding.

Reference: MODBUS Application Protocol Specification V1.1b3 and MODBUS
Messaging on TCP/IP Implementation Guide V1.0b.
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
}

WRITE_FUNCTIONS = frozenset({5, 6, 15, 16, 21, 22, 23})

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

    @property
    def function_name(self) -> str:
        return FUNCTION_NAMES.get(self.function, f"function {self.function}")

    @property
    def exception_name(self) -> str | None:
        if self.exception_code is None:
            return None
        return EXCEPTION_NAMES.get(self.exception_code, f"exception {self.exception_code}")

    @property
    def is_write(self) -> bool:
        return self.function in WRITE_FUNCTIONS


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


def parse(frame: bytes) -> Pdu | None:
    """Decode one complete Modbus/TCP frame."""
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
    return Pdu(
        transaction=transaction,
        unit_id=unit_id,
        function=function,
        identification=identification,
    )


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
