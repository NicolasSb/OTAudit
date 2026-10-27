import struct

from otaudit.protocols import opcua
from otaudit.synthesis import (
    opcua_encrypted,
    opcua_hello,
    opcua_message,
    opcua_open,
    ua_activate_session,
    ua_endpoint,
    ua_get_endpoints_response,
    ua_request_header,
    ua_response_header,
    ua_write_request,
)

# MSG chunk on channel 7, token 1, sequence 5, request 5, carrying a ReadRequest (631).
READ_REQUEST = bytes.fromhex(
    "4d5347461c00000007000000010000000500000005000000010077 02".replace(" ", "")
)
# ERR chunk with BadSecurityChecksFailed and no reason.
ERROR = bytes.fromhex("455252461000000000001380ffffffff")


def test_hello_is_recognised_whatever_the_port():
    url = b"opc.tcp://plc:4840"
    hello = bytes.fromhex("48454c4632000000" + "00000000" + "00000100" * 2 + "00000000" * 2)
    hello += struct.pack("<i", len(url)) + url

    assert opcua.is_hello(hello)
    assert not opcua.is_hello(b"HELF\x04\x00\x00\x00")
    assert not opcua.is_hello(b"GET / HTTP/1.1\r\n")
    message = opcua.parse(hello)
    assert message is not None
    assert message.service_name == "hello"


def test_read_request_service_and_request_id_are_decoded():
    message = opcua.parse(READ_REQUEST)

    assert message is not None
    assert message.kind == "MSG"
    assert message.chunk == "F"
    assert message.service_name == "read"
    assert message.request_id == 5
    assert message.decoded
    assert not message.is_write
    assert not message.is_discovery


def test_error_chunk_carries_a_failed_status():
    message = opcua.parse(ERROR)

    assert message is not None
    assert message.failed
    assert message.status_name == "BadSecurityChecksFailed"


def test_open_secure_channel_under_none_is_read_through():
    message = opcua.parse(opcua_open("None", 1))

    assert message is not None
    assert message.security_policy == "None"
    assert message.request_id == 1
    assert message.service_name == "open secure channel"
    assert message.is_discovery


def test_open_secure_channel_under_a_policy_keeps_the_policy_only():
    message = opcua.parse(opcua_open("Basic256Sha256", 1))

    assert message is not None
    assert message.security_policy == "Basic256Sha256"
    assert message.request_id is None
    assert not message.decoded


def test_encrypted_chunk_is_not_decoded():
    message = opcua.parse(opcua_encrypted(3))

    assert message is not None
    assert not message.decoded
    assert message.service_name == "undecoded message"


def test_write_request_lists_the_nodes_written():
    body = ua_write_request([(2, "Line3.Setpoint"), (3, "Pump.Start")], 1.5)
    message = opcua.parse(opcua_message(opcua.WRITE, body, 9))

    assert message is not None
    assert message.is_write
    assert message.written == ["ns=2;s=Line3.Setpoint", "ns=3;s=Pump.Start"]


def test_method_call_counts_as_a_write():
    message = opcua.parse(opcua_message(712, ua_request_header(), 4))

    assert message is not None
    assert message.service_name == "call"
    assert message.is_write


def test_username_token_without_encryption_is_flagged_without_keeping_the_password():
    body = ua_activate_session("username", "operator", b"hunter2")
    message = opcua.parse(opcua_message(opcua.ACTIVATE_SESSION, body, 4))

    assert message is not None
    assert message.identity_token == "username"
    assert message.user_name == "operator"
    assert message.cleartext_password
    assert "hunter2" not in repr(message)


def test_encrypted_username_token_is_not_flagged():
    body = ua_activate_session(
        "username",
        "operator",
        b"\x8a" * 256,
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep",
    )
    message = opcua.parse(opcua_message(opcua.ACTIVATE_SESSION, body, 4))

    assert message is not None
    assert not message.cleartext_password


def test_anonymous_token_is_recognised():
    message = opcua.parse(
        opcua_message(opcua.ACTIVATE_SESSION, ua_activate_session("anonymous"), 4)
    )

    assert message is not None
    assert message.identity_token == "anonymous"
    assert message.user_name is None


def test_get_endpoints_response_lists_endpoints_and_identification():
    url = "opc.tcp://10.0.0.9:4840"
    body = ua_get_endpoints_response(
        [
            ua_endpoint(url, "None", "None", ["anonymous"], ("Press 4", "urn:press4", "urn:acme")),
            ua_endpoint(url, "SignAndEncrypt", "Basic256Sha256", ["username", "certificate"]),
        ]
    )
    message = opcua.parse(opcua_message(opcua.GET_ENDPOINTS_RESPONSE, body, 2))

    assert message is not None
    assert not message.failed
    assert message.endpoints == [
        opcua.Endpoint(url, "None", "None", ("anonymous",)),
        opcua.Endpoint(url, "SignAndEncrypt", "Basic256Sha256", ("username", "certificate")),
    ]
    assert message.identification == {
        "application_name": "Press 4",
        "application_uri": "urn:press4",
        "product_uri": "urn:acme",
    }


def test_service_fault_and_bad_results_are_failures():
    fault = opcua.parse(opcua_message(opcua.SERVICE_FAULT, ua_response_header(0x801F0000), 4))
    unknown = opcua.parse(opcua_message(634, ua_response_header(0x80AB0000), 5))
    good = opcua.parse(opcua_message(634, ua_response_header(), 6))

    assert fault is not None and fault.failed
    assert fault.service_name == "service fault"
    assert fault.status_name == "BadUserAccessDenied"
    assert unknown is not None and unknown.status_name == "status 0x80ab0000"
    assert good is not None and not good.failed


def test_truncated_body_keeps_what_was_read():
    frame = opcua_message(opcua.ACTIVATE_SESSION, ua_activate_session("username", "op", b"x"), 4)
    cut = frame[:40]
    cut = cut[:4] + struct.pack("<I", len(cut)) + cut[8:]
    message = opcua.parse(cut)

    assert message is not None
    assert message.service_name == "activate session"
    assert message.identity_token is None


def test_node_id_encodings_are_formatted():
    guid = struct.pack("<BH", 0x04, 1) + bytes.fromhex("7856341234127856") + bytes(range(8))
    cases = [
        (b"\x00\x2a", "i=42"),
        (struct.pack("<BBH", 0x01, 2, 1000), "ns=2;i=1000"),
        (struct.pack("<BHI", 0x02, 4, 100000), "ns=4;i=100000"),
        (guid, "ns=1;g=12345678-1234-5678-0001-020304050607"),
        (struct.pack("<BHi", 0x05, 3, 2) + b"\x01\x02", "ns=3;b=AQI="),
        (struct.pack("<BBH", 0x81, 0, 5) + struct.pack("<i", -1), "i=5"),
    ]
    for encoded, expected in cases:
        assert opcua.format_node_id(opcua._Reader(encoded).node_id()) == expected


def test_variants_of_every_shape_are_skipped():
    reader = opcua._Reader
    values = [
        b"\x01\x01",  # boolean
        b"\x0c" + struct.pack("<i", 2) + b"ok",  # string
        b"\x8b" + struct.pack("<i", 2) + bytes(16),  # array of doubles
        b"\xc6" + struct.pack("<i", 1) + bytes(4) + struct.pack("<ii", 1, 1),  # with dimensions
        b"\x14" + struct.pack("<H", 1) + struct.pack("<i", -1),  # qualified name
        b"\x15\x00",  # empty localized text
        b"\x16\x00\x00\x00",  # empty extension object
        b"\x17\x02" + bytes(4),  # data value with a status code only
        b"\x18\x00",  # nested null variant
        b"\x19\x21" + bytes(8),  # diagnostic info
        b"\x11\x00\x05",  # node id
    ]
    for value in values:
        cursor = reader(value)
        cursor.variant()
        assert cursor.offset == len(value), value


def test_unknown_variant_type_stops_the_decoding():
    body = ua_request_header() + struct.pack("<i", 1) + struct.pack("<BBH", 1, 0, 5)
    body += struct.pack("<I", 13) + struct.pack("<i", -1) + b"\x01\x3f"
    message = opcua.parse(opcua_message(opcua.WRITE, body, 2))

    assert message is not None
    assert message.is_write
    assert message.written == []


def test_split_frames_handles_partial_chunks_and_garbage():
    first = opcua_hello("opc.tcp://a:4840")
    second = READ_REQUEST
    buffer = bytearray(b"\x00\x99" + first + second[:10])

    assert opcua.split_frames(buffer) == [first]

    buffer += second[10:]
    assert opcua.split_frames(buffer) == [second]
    assert not buffer


def test_split_frames_rejects_impossible_lengths():
    buffer = bytearray(b"MSGF\x04\x00\x00\x00" + b"MSGF\xff\xff\xff\x7f")

    assert opcua.split_frames(buffer) == []
    assert len(buffer) < 8


def test_short_and_foreign_frames_are_rejected():
    assert opcua.parse(b"MSGF") is None
    assert opcua.parse(b"XYZF\x08\x00\x00\x00") is None


def test_policy_names_are_shortened():
    assert opcua.policy_name("http://opcfoundation.org/UA/SecurityPolicy#Basic256") == "Basic256"
    assert opcua.policy_name(None) == "unknown"
