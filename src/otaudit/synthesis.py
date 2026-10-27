"""Generation of synthetic captures.

Real captures from a production site cannot be published, and a tool with no
sample is a tool nobody tries. Everything here builds well-formed Ethernet/IPv4/TCP
frames carrying handmade Modbus, S7 and OPC UA payloads, with correct checksums, so the
result opens in Wireshark like any other capture.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path

from .pcapfile import LINKTYPE_ETHERNET, Record, write_pcap
from .protocols import modbus, opcua, s7


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


POLICY_PREFIX = "http://opcfoundation.org/UA/SecurityPolicy#"
SECURITY_MODE_IDS = {name: value for value, name in opcua.SECURITY_MODES.items()}
TOKEN_TYPE_IDS = {name: value for value, name in opcua.TOKEN_TYPES.items()}
TOKEN_ENCODING_IDS = {"anonymous": 321, "username": 324, "certificate": 327}


def ua_string(value: str | bytes | None) -> bytes:
    if value is None:
        return struct.pack("<i", -1)
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return struct.pack("<i", len(raw)) + raw


def ua_numeric_node(identifier: int, namespace: int = 0) -> bytes:
    return struct.pack("<BBH", 0x01, namespace, identifier)


def ua_string_node(name: str, namespace: int) -> bytes:
    return struct.pack("<BH", 0x03, namespace) + ua_string(name)


def ua_request_header(handle: int = 1) -> bytes:
    # Null authentication token, no audit entry, no additional header.
    return b"\x00\x00" + struct.pack("<QIIiIBBB", 0, handle, 0, -1, 10000, 0, 0, 0)


def ua_response_header(status: int = 0, handle: int = 1) -> bytes:
    return struct.pack("<QIIBiBBB", 0, handle, status, 0, -1, 0, 0, 0)


def opcua_chunk(kind: bytes, body: bytes, chunk: bytes = b"F") -> bytes:
    return kind + chunk + struct.pack("<I", opcua.HEADER + len(body)) + body


def opcua_hello(url: str) -> bytes:
    return opcua_chunk(b"HEL", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + ua_string(url))


def opcua_acknowledge() -> bytes:
    return opcua_chunk(b"ACK", struct.pack("<IIIII", 0, 65536, 65536, 0, 0))


def opcua_open(policy: str, request_id: int, response: bool = False) -> bytes:
    """An OpenSecureChannel chunk; under any policy but None its body is opaque bytes."""
    channel = 7 if response else 0
    header = struct.pack("<I", channel) + ua_string(POLICY_PREFIX + policy)
    if policy != "None":
        certificate = b"\x30\x82" + bytes(range(64))
        return opcua_chunk(
            b"OPN", header + ua_string(certificate) + ua_string(bytes(20)) + bytes(128)
        )
    header += ua_string(None) + ua_string(None) + struct.pack("<II", request_id, request_id)
    if response:
        body = ua_numeric_node(449) + ua_response_header()
        body += struct.pack("<IIIQI", 0, channel, 1, 0, 3600000) + ua_string(None)
    else:
        body = ua_numeric_node(446) + ua_request_header()
        body += struct.pack("<III", 0, 0, 1) + ua_string(None) + struct.pack("<I", 3600000)
    return opcua_chunk(b"OPN", header + body)


def opcua_message(service: int, body: bytes, request_id: int, chunk: bytes = b"F") -> bytes:
    header = struct.pack("<IIII", 7, 1, request_id, request_id)
    return opcua_chunk(b"MSG", header + ua_numeric_node(service) + body, chunk)


def opcua_encrypted(request_id: int, size: int = 96) -> bytes:
    """A chunk of a SignAndEncrypt channel: only the channel and token ids are readable."""
    noise = bytes((request_id * 37 + index * 11) & 0xFF for index in range(size))
    return opcua_chunk(b"MSG", struct.pack("<II", 7, 1) + noise)


def ua_application(name: str, uri: str, product: str, kind: int = 0) -> bytes:
    """An ApplicationDescription; kind 0 is a server, 1 a client."""
    encoded = ua_string(uri) + ua_string(product) + b"\x02" + ua_string(name)
    return encoded + struct.pack("<I", kind) + ua_string(None) + ua_string(None) + b"\xff" * 4


def ua_endpoint(
    url: str,
    mode: str,
    policy: str,
    tokens: list[str],
    application: tuple[str, str, str] = ("", "", ""),
) -> bytes:
    """An EndpointDescription; application is (name, application uri, product uri)."""
    encoded = ua_string(url) + ua_application(*application) + ua_string(None)
    encoded += struct.pack("<I", SECURITY_MODE_IDS[mode])
    encoded += ua_string(POLICY_PREFIX + policy) + struct.pack("<i", len(tokens))
    for token in tokens:
        encoded += ua_string(token) + struct.pack("<I", TOKEN_TYPE_IDS[token])
        encoded += ua_string(None) * 3
    return encoded + ua_string(None) + b"\x00"


def ua_get_endpoints_request(url: str) -> bytes:
    return ua_request_header() + ua_string(url) + struct.pack("<ii", 0, 0)


def ua_create_session_request(url: str, session: str) -> bytes:
    client = ua_application("Supervision", "urn:scada:client", "urn:vendor:scada", kind=1)
    body = ua_request_header() + client + ua_string(None) + ua_string(url) + ua_string(session)
    return body + ua_string(bytes(32)) + ua_string(None) + struct.pack("<dI", 600000.0, 0)


def ua_create_session_response() -> bytes:
    body = (
        ua_response_header()
        + struct.pack("<BBH", 0x01, 1, 1001)
        + struct.pack("<BBH", 0x01, 1, 1002)
    )
    body += struct.pack("<d", 600000.0) + ua_string(bytes(32)) + ua_string(None)
    return (
        body + struct.pack("<ii", 0, 0) + ua_string(None) + ua_string(None) + struct.pack("<I", 0)
    )


def ua_status_results(count: int, status: int = 0) -> bytes:
    """The results and diagnostic arrays that end activate session and write responses."""
    return struct.pack("<i", count) + struct.pack("<I", status) * count + struct.pack("<i", 0)


def ua_read_response(values: list[float]) -> bytes:
    body = ua_response_header() + struct.pack("<i", len(values))
    for value in values:
        body += b"\x01\x0b" + struct.pack("<d", value)
    return body + struct.pack("<i", 0)


def ua_get_endpoints_response(endpoints: list[bytes], status: int = 0) -> bytes:
    return ua_response_header(status) + struct.pack("<i", len(endpoints)) + b"".join(endpoints)


def ua_activate_session(
    token: str, user: str = "", password: bytes = b"", algorithm: str | None = None
) -> bytes:
    body = ua_request_header() + ua_string(None) + ua_string(None)
    body += struct.pack("<ii", 0, 0)
    if token == "username":
        content = ua_string("username") + ua_string(user) + ua_string(password)
        content += ua_string(algorithm)
    else:
        content = ua_string("anonymous")
    body += ua_numeric_node(TOKEN_ENCODING_IDS[token]) + b"\x01" + ua_string(content)
    return body + ua_string(None) + ua_string(None)


def ua_write_request(nodes: list[tuple[int, str]], value: float = 0.0) -> bytes:
    body = ua_request_header() + struct.pack("<i", len(nodes))
    for namespace, name in nodes:
        body += ua_string_node(name, namespace) + struct.pack("<I", 13) + ua_string(None)
        body += b"\x01" + b"\x0b" + struct.pack("<d", value)
    return body


def ua_read_request(nodes: list[tuple[int, str]]) -> bytes:
    body = ua_request_header() + struct.pack("<dIi", 0.0, 0, len(nodes))
    for namespace, name in nodes:
        body += ua_string_node(name, namespace) + struct.pack("<I", 13) + ua_string(None)
        body += struct.pack("<H", 0) + ua_string(None)
    return body


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
    offset += 0.5

    _add_opcua_sessions(builder, offset, scada, engineering, "10.42.7.40")
    return builder.write(path)


def _add_opcua_sessions(
    builder: CaptureBuilder, offset: float, scada: str, engineering: str, server: str
) -> None:
    """Supervision on a None channel with a clear password; engineering fully encrypted."""
    url = f"opc.tcp://{server}:4840"
    application = ("Line 3 gateway", "urn:line3:gateway", "urn:vendor:uagateway")
    exchanges = [
        (opcua_hello(url), opcua_acknowledge()),
        (opcua_open("None", 1), opcua_open("None", 1, response=True)),
        (
            opcua_message(opcua.GET_ENDPOINTS, ua_get_endpoints_request(url), 2),
            opcua_message(
                opcua.GET_ENDPOINTS_RESPONSE,
                ua_get_endpoints_response(
                    [
                        ua_endpoint(url, "None", "None", ["anonymous", "username"], application),
                        ua_endpoint(url, "Sign", "Basic128Rsa15", ["username"], application),
                        ua_endpoint(
                            url, "SignAndEncrypt", "Basic256Sha256", ["username", "certificate"]
                        ),
                    ]
                ),
                2,
            ),
        ),
        (
            opcua_message(461, ua_create_session_request(url, "Supervision"), 3),
            opcua_message(464, ua_create_session_response(), 3),
        ),
        (
            opcua_message(
                opcua.ACTIVATE_SESSION,
                ua_activate_session("username", "supervision", b"Line3-2019"),
                4,
            ),
            opcua_message(
                470, ua_response_header() + ua_string(bytes(32)) + ua_status_results(0), 4
            ),
        ),
    ]
    polled = [(2, "Line3.Level"), (2, "Line3.Flow")]
    request_id = 5
    for cycle in range(5):
        exchanges.append(
            (
                opcua_message(631, ua_read_request(polled), request_id),
                opcua_message(634, ua_read_response([2.5 + cycle, 11.0]), request_id),
            )
        )
        request_id += 1
    written = ua_write_request([(2, "Line3.Setpoint")], 42.0)
    exchanges.append(
        (
            opcua_message(opcua.WRITE, written, request_id),
            opcua_message(676, ua_response_header() + ua_status_results(1), request_id),
        )
    )
    for request, response in exchanges:
        builder.add(offset, scada, server, 40300, 4840, request)
        offset += 0.01
        builder.add(offset, server, scada, 4840, 40300, response)
        offset += 0.5

    secured = [
        (opcua_hello(url), opcua_acknowledge()),
        (opcua_open("Basic256Sha256", 1), opcua_open("Basic256Sha256", 1, response=True)),
    ]
    secured.extend((opcua_encrypted(index), opcua_encrypted(index + 100)) for index in range(4))
    for request, response in secured:
        builder.add(offset, engineering, server, 52100, 4840, request)
        offset += 0.01
        builder.add(offset, server, engineering, 4840, 52100, response)
        offset += 0.5
