"""Frames are written as literal bytes rather than produced by the builders,
so that a change in the builders cannot make a broken decoder look correct."""

from otaudit.protocols import modbus

READ_HOLDING_REQUEST = bytes.fromhex("0001000000060103006B0003")
READ_HOLDING_RESPONSE = bytes.fromhex("000100000009010306022B00000064")
EXCEPTION_RESPONSE = bytes.fromhex("000200000003018302")


def test_parse_request():
    pdu = modbus.parse(READ_HOLDING_REQUEST)

    assert pdu is not None
    assert pdu.transaction == 1
    assert pdu.unit_id == 1
    assert pdu.function == 3
    assert pdu.function_name == "read holding registers"
    assert not pdu.is_write
    assert not pdu.is_exception


def test_parse_exception_response():
    pdu = modbus.parse(EXCEPTION_RESPONSE)

    assert pdu is not None
    assert pdu.is_exception
    assert pdu.function == 3
    assert pdu.exception_code == 2
    assert pdu.exception_name == "illegal data address"


def test_write_function_is_recognised():
    frame = bytes.fromhex("000400000006011000640001")
    pdu = modbus.parse(frame)

    assert pdu is not None
    assert pdu.is_write
    assert pdu.function_name == "write multiple registers"


def test_unknown_function_and_exception_fall_back_to_a_label():
    frame = bytes.fromhex("0005000000030163")
    pdu = modbus.parse(frame)
    assert pdu is not None
    assert pdu.function_name == "function 99"

    unknown_exception = bytes.fromhex("000600000003018307")
    pdu = modbus.parse(unknown_exception)
    assert pdu is not None
    assert pdu.exception_name == "exception 7"


def test_parse_identification_response():
    objects = b"\x00\x06Vendor\x01\x04Item\x02\x033.1"
    body = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03]) + objects
    frame = bytes.fromhex("000700000000") + b"\x01" + body
    frame = frame[:4] + len(body + b"\x01").to_bytes(2, "big") + frame[6:]

    pdu = modbus.parse(frame)

    assert pdu is not None
    assert pdu.identification == {"vendor": "Vendor", "product": "Item", "revision": "3.1"}


def test_identification_request_yields_no_objects():
    frame = bytes.fromhex("000800000005012B0E0100")
    pdu = modbus.parse(frame)

    assert pdu is not None
    assert pdu.identification == {}


def test_split_frames_handles_partial_and_multiple_frames():
    buffer = bytearray(READ_HOLDING_REQUEST + READ_HOLDING_RESPONSE[:5])
    frames = modbus.split_frames(buffer)

    assert frames == [READ_HOLDING_REQUEST]
    assert len(buffer) == 5

    buffer += READ_HOLDING_RESPONSE[5:]
    assert modbus.split_frames(buffer) == [READ_HOLDING_RESPONSE]
    assert not buffer


def test_split_frames_resynchronises_on_garbage():
    buffer = bytearray(b"\xde\xad\xbe\xef" + READ_HOLDING_REQUEST)
    frames = modbus.split_frames(buffer)

    assert frames == [READ_HOLDING_REQUEST]


def test_parse_rejects_short_frame():
    assert modbus.parse(b"\x00\x01\x00\x00") is None
