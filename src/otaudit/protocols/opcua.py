"""OPC UA Binary decoding over UA TCP (IEC 62541-6).

Only the binary encoding over plain TCP is read: HTTPS and WebSocket transports
are not. What an audit needs from it is narrow: the security policy each secure
channel was opened with, the service behind each request when the channel does
not encrypt it, how users authenticated, and which endpoints a server offers when
a client asks. Chunks the channel encrypts are counted, never decoded.

Field layouts follow part 6 of the specification; numeric identifiers are the
binary encoding ids from the published NodeIds.csv.
"""

from __future__ import annotations

import base64
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

PORT = 4840
HEADER = 8
MAX_CHUNK = 1 << 24
MAX_ARRAY = 10_000

MESSAGE_TYPES = frozenset({b"HEL", b"ACK", b"ERR", b"RHE", b"OPN", b"CLO", b"MSG"})
CHUNK_TYPES = frozenset(b"FCA")

KIND_NAMES = {
    "HEL": "hello",
    "ACK": "acknowledge",
    "ERR": "error",
    "RHE": "reverse hello",
    "OPN": "open secure channel",
    "CLO": "close secure channel",
}

# Binary encoding ids of service requests. Each response id is the request id + 3.
SERVICES = {
    422: "find servers",
    428: "get endpoints",
    437: "register server",
    446: "open secure channel",
    452: "close secure channel",
    461: "create session",
    467: "activate session",
    473: "close session",
    479: "cancel",
    488: "add nodes",
    494: "add references",
    500: "delete nodes",
    506: "delete references",
    527: "browse",
    533: "browse next",
    554: "translate browse paths",
    560: "register nodes",
    566: "unregister nodes",
    615: "query first",
    621: "query next",
    631: "read",
    664: "history read",
    673: "write",
    700: "history update",
    712: "call",
    751: "create monitored items",
    763: "modify monitored items",
    769: "set monitoring mode",
    775: "set triggering",
    781: "delete monitored items",
    787: "create subscription",
    793: "modify subscription",
    799: "set publishing mode",
    826: "publish",
    832: "republish",
    841: "transfer subscriptions",
    847: "delete subscriptions",
}
SERVICE_FAULT = 397
RESPONSES = {identifier + 3: name for identifier, name in SERVICES.items()}
RESPONSES[SERVICE_FAULT] = "service fault"

FIND_SERVERS = 422
GET_ENDPOINTS = 428
ACTIVATE_SESSION = 467
WRITE = 673
GET_ENDPOINTS_RESPONSE = GET_ENDPOINTS + 3

DISCOVERY_SERVICES = frozenset({FIND_SERVERS, GET_ENDPOINTS, 446, 452})
# A method call is a command to the server's program, so it counts with the writes.
WRITE_SERVICES = frozenset({488, 494, 500, 506, WRITE, 700, 712})

DEPRECATED_POLICIES = frozenset({"Basic128Rsa15", "Basic256"})

SECURITY_MODES = {0: "Invalid", 1: "None", 2: "Sign", 3: "SignAndEncrypt"}
TOKEN_TYPES = {0: "anonymous", 1: "username", 2: "certificate", 3: "issued"}
# Binary encoding ids of user identity tokens. A null token means anonymous.
TOKEN_ENCODINGS = {
    0: "anonymous",
    321: "anonymous",
    324: "username",
    327: "certificate",
    940: "issued",
}

STATUS_NAMES = {
    0x800A0000: "BadTimeout",
    0x800B0000: "BadServiceUnsupported",
    0x80130000: "BadSecurityChecksFailed",
    0x801A0000: "BadCertificateUntrusted",
    0x801F0000: "BadUserAccessDenied",
    0x80200000: "BadIdentityTokenInvalid",
    0x80210000: "BadIdentityTokenRejected",
    0x80250000: "BadSessionIdInvalid",
    0x80340000: "BadNodeIdUnknown",
    0x803A0000: "BadNotReadable",
    0x803B0000: "BadNotWritable",
    0x80560000: "BadTooManySessions",
}

NodeId = tuple[int, int | str]
T = TypeVar("T")


@dataclass(frozen=True, order=True)
class Endpoint:
    url: str
    mode: str
    policy: str
    tokens: tuple[str, ...] = ()


@dataclass
class Message:
    kind: str
    chunk: str
    request_id: int | None = None
    """From the sequence header; meaningless when the channel encrypts it."""
    service: int | None = None
    """Request or response encoding id, set only when the body was readable."""
    security_policy: str | None = None
    status: int | None = None
    identity_token: str | None = None
    user_name: str | None = None
    cleartext_password: bool = False
    written: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    identification: dict[str, str] = field(default_factory=dict)

    @property
    def service_name(self) -> str:
        if self.kind != "MSG":
            return KIND_NAMES.get(self.kind, self.kind)
        if self.service is None:
            return "undecoded message"
        return SERVICES.get(self.service) or RESPONSES[self.service]

    @property
    def decoded(self) -> bool:
        return self.service is not None

    @property
    def is_write(self) -> bool:
        return self.service in WRITE_SERVICES

    @property
    def is_discovery(self) -> bool:
        return self.kind != "MSG" or self.service in DISCOVERY_SERVICES

    @property
    def failed(self) -> bool:
        return self.status is not None and bool(self.status & 0x80000000)

    @property
    def status_name(self) -> str:
        if self.status is None:
            return "no status"
        return STATUS_NAMES.get(self.status, f"status {self.status:#010x}")


def is_hello(payload: bytes) -> bool:
    """Say whether a TCP payload opens a UA TCP connection, whatever the port."""
    if len(payload) < HEADER or payload[:4] != b"HELF":
        return False
    length: int = struct.unpack("<I", payload[4:8])[0]
    return HEADER < length <= MAX_CHUNK


def split_frames(buffer: bytearray) -> list[bytes]:
    """Consume complete UA TCP chunks from the head of a stream buffer."""
    frames: list[bytes] = []
    while len(buffer) >= HEADER:
        if bytes(buffer[:3]) not in MESSAGE_TYPES or buffer[3] not in CHUNK_TYPES:
            del buffer[:1]
            continue
        length = struct.unpack("<I", buffer[4:8])[0]
        if length < HEADER or length > MAX_CHUNK:
            del buffer[:1]
            continue
        if len(buffer) < length:
            break
        frames.append(bytes(buffer[:length]))
        del buffer[:length]
    return frames


def policy_name(uri: str | None) -> str:
    """Short name of a security policy URI: "None", "Basic256Sha256"..."""
    if not uri:
        return "unknown"
    return uri.rsplit("#", 1)[-1]


def format_node_id(node: NodeId) -> str:
    namespace, identifier = node
    text = f"i={identifier}" if isinstance(identifier, int) else identifier
    return f"ns={namespace};{text}" if namespace else text


def parse(frame: bytes) -> Message | None:
    """Decode one chunk. Whatever was read before the data ran out is kept."""
    if len(frame) < HEADER or frame[:3] not in MESSAGE_TYPES:
        return None
    message = Message(kind=frame[:3].decode("ascii"), chunk=chr(frame[3]))
    reader = _Reader(frame, HEADER)
    try:
        if message.kind == "ERR":
            message.status = reader.uint32()
        elif message.kind == "OPN":
            reader.uint32()
            message.security_policy = policy_name(reader.string())
            reader.bytestring()
            reader.bytestring()
            # Under any other policy the sequence header and body are encrypted.
            if message.security_policy == "None":
                _body(reader, message)
        elif message.kind in ("MSG", "CLO"):
            reader.uint32()
            reader.uint32()
            _body(reader, message)
    except _Truncated:
        pass
    return message


def _body(reader: _Reader, message: Message) -> None:
    reader.uint32()
    message.request_id = reader.uint32()
    namespace, identifier = reader.node_id()
    if namespace or not isinstance(identifier, int):
        return
    if identifier not in SERVICES and identifier not in RESPONSES:
        return
    message.service = identifier
    if identifier in RESPONSES:
        message.status = reader.response_header()
        if identifier == GET_ENDPOINTS_RESPONSE:
            _endpoints(reader, message)
    elif identifier == ACTIVATE_SESSION:
        _activate_session(reader, message)
    elif identifier == WRITE:
        reader.request_header()
        message.written = reader.array(lambda: _write_value(reader))


def _write_value(reader: _Reader) -> str:
    node = reader.node_id()
    reader.uint32()
    reader.string()
    reader.data_value()
    return format_node_id(node)


def _activate_session(reader: _Reader, message: Message) -> None:
    reader.request_header()
    reader.string()
    reader.bytestring()
    reader.array(lambda: (reader.bytestring(), reader.bytestring()))
    reader.array(reader.string)
    (namespace, identifier), body = reader.extension_object()
    token = None
    if not namespace and isinstance(identifier, int):
        token = TOKEN_ENCODINGS.get(identifier)
    message.identity_token = token or "unknown"
    if token != "username":
        return
    token_reader = _Reader(body)
    token_reader.string()
    message.user_name = token_reader.string() or ""
    # Only whether a password went out unencrypted is kept, never the password.
    password = token_reader.bytestring()
    algorithm = token_reader.string()
    message.cleartext_password = bool(password) and not algorithm


def _endpoints(reader: _Reader, message: Message) -> None:
    def endpoint() -> Endpoint:
        url = reader.string() or ""
        application = {
            "application_uri": reader.string(),
            "product_uri": reader.string(),
            "application_name": reader.localized_text(),
        }
        reader.uint32()
        reader.string()
        reader.string()
        reader.array(reader.string)
        if not message.identification:
            message.identification = {key: value for key, value in application.items() if value}
        reader.bytestring()
        mode = SECURITY_MODES.get(reader.uint32(), "Invalid")
        policy = policy_name(reader.string())
        tokens = reader.array(user_token)
        reader.string()
        reader.byte()
        return Endpoint(url=url, mode=mode, policy=policy, tokens=tuple(dict.fromkeys(tokens)))

    def user_token() -> str:
        reader.string()
        token_type = reader.uint32()
        reader.string()
        reader.string()
        reader.string()
        return TOKEN_TYPES.get(token_type, f"token type {token_type}")

    message.endpoints = reader.array(endpoint)


class _Truncated(Exception):
    """The chunk ended before the structure being read."""


class _Reader:
    """Little-endian reader for the OPC UA binary encoding."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.offset = offset

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise _Truncated
        chunk = self.data[self.offset : self.offset + count]
        self.offset += count
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def uint16(self) -> int:
        value: int = struct.unpack("<H", self.take(2))[0]
        return value

    def uint32(self) -> int:
        value: int = struct.unpack("<I", self.take(4))[0]
        return value

    def int32(self) -> int:
        value: int = struct.unpack("<i", self.take(4))[0]
        return value

    def bytestring(self) -> bytes | None:
        length = self.int32()
        return None if length < 0 else self.take(length)

    def string(self) -> str | None:
        raw = self.bytestring()
        return None if raw is None else raw.decode("utf-8", "replace")

    def array(self, read: Callable[[], T]) -> list[T]:
        count = self.int32()
        if count > MAX_ARRAY:
            raise _Truncated
        return [read() for _ in range(max(count, 0))]

    def node_id(self) -> NodeId:
        encoding = self.byte()
        form = encoding & 0x0F
        node: NodeId
        if form == 0x00:
            node = (0, self.byte())
        elif form == 0x01:
            namespace = self.byte()
            node = (namespace, self.uint16())
        elif form == 0x02:
            namespace = self.uint16()
            node = (namespace, self.uint32())
        elif form == 0x03:
            namespace = self.uint16()
            node = (namespace, f"s={self.string() or ''}")
        elif form == 0x04:
            namespace = self.uint16()
            data1, data2, data3 = struct.unpack("<IHH", self.take(8))
            tail = self.take(8).hex()
            node = (namespace, f"g={data1:08x}-{data2:04x}-{data3:04x}-{tail[:4]}-{tail[4:]}")
        elif form == 0x05:
            namespace = self.uint16()
            node = (namespace, f"b={base64.b64encode(self.bytestring() or b'').decode()}")
        else:
            raise _Truncated
        # Flags of an expanded node id; never set on a plain one.
        if encoding & 0x80:
            self.string()
        if encoding & 0x40:
            self.uint32()
        return node

    def extension_object(self) -> tuple[NodeId, bytes]:
        type_id = self.node_id()
        encoding = self.byte()
        body = self.bytestring() if encoding in (0x01, 0x02) else None
        return type_id, body or b""

    def localized_text(self) -> str | None:
        mask = self.byte()
        if mask & 0x01:
            self.string()
        return self.string() if mask & 0x02 else None

    def diagnostic_info(self) -> None:
        mask = self.byte()
        for bit in (0x01, 0x02, 0x04, 0x08):
            if mask & bit:
                self.int32()
        if mask & 0x10:
            self.string()
        if mask & 0x20:
            self.uint32()
        if mask & 0x40:
            self.diagnostic_info()

    def request_header(self) -> None:
        self.node_id()
        self.take(16)
        self.string()
        self.uint32()
        self.extension_object()

    def response_header(self) -> int:
        self.take(12)
        status = self.uint32()
        self.diagnostic_info()
        self.array(self.string)
        self.extension_object()
        return status

    def data_value(self) -> None:
        mask = self.byte()
        if mask & 0x01:
            self.variant()
        if mask & 0x02:
            self.uint32()
        for bit, size in ((0x04, 8), (0x10, 2), (0x08, 8), (0x20, 2)):
            if mask & bit:
                self.take(size)

    def variant(self) -> None:
        mask = self.byte()
        kind = mask & 0x3F
        if not mask & 0x80:
            self._scalar(kind)
            return
        self.array(lambda: self._scalar(kind))
        if mask & 0x40:
            self.array(self.int32)

    def _scalar(self, kind: int) -> None:
        size = _SCALAR_SIZES.get(kind)
        if size is not None:
            self.take(size)
        elif kind in (12, 15, 16):
            self.bytestring()
        elif kind in (17, 18):
            self.node_id()
        elif kind == 20:
            self.uint16()
            self.string()
        elif kind == 21:
            self.localized_text()
        elif kind == 22:
            self.extension_object()
        elif kind == 23:
            self.data_value()
        elif kind == 24:
            self.variant()
        elif kind == 25:
            self.diagnostic_info()
        else:
            raise _Truncated


# Fixed sizes of variant scalars by built-in type id; 0 is the null variant.
_SCALAR_SIZES = {
    0: 0, 1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 4, 8: 8, 9: 8, 10: 4, 11: 8, 13: 8, 14: 16, 19: 4
}  # fmt: skip
