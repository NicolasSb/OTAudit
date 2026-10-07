"""S7comm decoding over TPKT (RFC 1006) and COTP (ISO 8073).

The protocol is not published by Siemens; the field layout used here follows
the public Wireshark dissector and is limited to what an audit needs: which
service was requested, and what the CPU disclosed about itself when a SZL list
was read. Block upload and download payloads are identified but not decoded.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

PORT = 102
TPKT_HEADER = 4
TPKT_VERSION = 3
S7_PROTOCOL_ID = 0x32

COTP_CONNECT_REQUEST = 0xE0
COTP_CONNECT_CONFIRM = 0xD0
COTP_DATA = 0xF0

ROSCTR_NAMES = {
    0x01: "job",
    0x02: "ack",
    0x03: "ack_data",
    0x07: "userdata",
}

FUNCTION_NAMES = {
    0x00: "cpu services",
    0x04: "read variable",
    0x05: "write variable",
    0x1A: "request download",
    0x1B: "download block",
    0x1C: "download ended",
    0x1D: "start upload",
    0x1E: "upload",
    0x1F: "end upload",
    0x28: "plc control",
    0x29: "plc stop",
    0xF0: "setup communication",
}

WRITE_FUNCTIONS = frozenset({0x05, 0x1A, 0x1B, 0x1C})
CONTROL_FUNCTIONS = frozenset({0x28, 0x29})

SZL_MODULE_IDENTIFICATION = 0x0011
SZL_COMPONENT_IDENTIFICATION = 0x001C

COMPONENT_FIELDS = {
    1: "plc_name",
    2: "module_name",
    5: "serial_number",
    7: "module_type",
}


@dataclass(frozen=True)
class Message:
    rosctr: int
    function: int | None
    reference: int = 0
    identification: dict[str, str] = field(default_factory=dict)
    error_class: int | None = None
    error_code: int | None = None

    @property
    def rosctr_name(self) -> str:
        return ROSCTR_NAMES.get(self.rosctr, f"rosctr {self.rosctr}")

    @property
    def function_name(self) -> str | None:
        if self.function is None:
            return None
        return FUNCTION_NAMES.get(self.function, f"function {self.function:#04x}")

    @property
    def is_write(self) -> bool:
        return self.function in WRITE_FUNCTIONS

    @property
    def is_control(self) -> bool:
        return self.function in CONTROL_FUNCTIONS

    @property
    def failed(self) -> bool:
        return bool(self.error_class) or bool(self.error_code)


def split_frames(buffer: bytearray) -> list[bytes]:
    """Consume complete TPKT frames from the head of a stream buffer."""
    frames: list[bytes] = []
    while len(buffer) >= TPKT_HEADER:
        if buffer[0] != TPKT_VERSION:
            del buffer[:1]
            continue
        length = struct.unpack("!H", buffer[2:4])[0]
        if length < TPKT_HEADER + 2:
            del buffer[:1]
            continue
        if len(buffer) < length:
            break
        frames.append(bytes(buffer[:length]))
        del buffer[:length]
    return frames


def parse(frame: bytes) -> Message | None:
    """Decode one TPKT frame. Returns None for COTP frames carrying no S7 payload."""
    if len(frame) < TPKT_HEADER + 2:
        return None
    cotp_length = frame[TPKT_HEADER]
    cotp_type = frame[TPKT_HEADER + 1]
    if cotp_type != COTP_DATA:
        return None
    payload = frame[TPKT_HEADER + cotp_length + 1 :]
    if len(payload) < 10 or payload[0] != S7_PROTOCOL_ID:
        return None
    rosctr = payload[1]
    reference = struct.unpack("!H", payload[4:6])[0]
    parameter_length, data_length = struct.unpack("!HH", payload[6:10])
    offset = 10
    error_class: int | None = None
    error_code: int | None = None
    if rosctr in (0x02, 0x03):
        if len(payload) < 12:
            return None
        error_class, error_code = payload[10], payload[11]
        offset = 12
    parameter = payload[offset : offset + parameter_length]
    data = payload[offset + parameter_length : offset + parameter_length + data_length]
    if not parameter:
        return Message(
            rosctr=rosctr,
            function=None,
            reference=reference,
            error_class=error_class,
            error_code=error_code,
        )
    function = parameter[0]
    identification: dict[str, str] = {}
    if rosctr == 0x07:
        identification = _parse_userdata(parameter, data)
    return Message(
        rosctr=rosctr,
        function=function,
        reference=reference,
        identification=identification,
        error_class=error_class,
        error_code=error_code,
    )


def _parse_userdata(parameter: bytes, data: bytes) -> dict[str, str]:
    """Extract CPU identification from a Read SZL response.

    Only the two lists that carry identification are decoded: 0x0011 for the
    order number, 0x001C for the names configured by the integrator.
    """
    if len(parameter) < 8:
        return {}
    function_group = parameter[5] & 0x0F
    subfunction = parameter[6]
    if function_group != 0x04 or subfunction != 0x01:
        return {}
    if len(data) < 12 or data[0] != 0xFF:
        return {}
    szl_id, _index, record_size, record_count = struct.unpack("!HHHH", data[4:12])
    records = data[12:]
    fields: dict[str, str] = {}
    for position in range(record_count):
        start = position * record_size
        record = records[start : start + record_size]
        if len(record) < record_size or record_size < 3:
            break
        record_index = struct.unpack("!H", record[:2])[0]
        if szl_id == SZL_MODULE_IDENTIFICATION and record_index == 1:
            fields["article_number"] = _text(record[2:22])
        elif szl_id == SZL_COMPONENT_IDENTIFICATION:
            name = COMPONENT_FIELDS.get(record_index)
            if name:
                fields[name] = _text(record[2:])
    return {key: value for key, value in fields.items() if value}


def _text(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1").strip()
