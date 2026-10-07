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


def test_diagnostics_restart_is_a_control_function():
    pdu = modbus.parse(bytes.fromhex("000500000006010800010000"))

    assert pdu is not None
    assert pdu.subfunction == 0x0001
    assert pdu.function_name == "diagnostics: restart communications"
    assert pdu.is_control
    assert not pdu.is_write


def test_diagnostics_force_listen_only_is_a_control_function():
    pdu = modbus.parse(bytes.fromhex("000600000006010800040000"))

    assert pdu is not None
    assert pdu.function_name == "diagnostics: force listen only mode"
    assert pdu.is_control


def test_diagnostics_echo_is_not_a_control_function():
    pdu = modbus.parse(bytes.fromhex("000700000006010800001234"))

    assert pdu is not None
    assert pdu.function_name == "diagnostics: return query data"
    assert not pdu.is_control


def test_umas_stop_and_start_are_control_functions():
    # Function 0x5A, session key 0x01, UMAS code.
    stop = modbus.parse(bytes.fromhex("000800000004005a0141"))
    start = modbus.parse(bytes.fromhex("000900000004005a0140"))

    assert stop is not None and start is not None
    assert stop.subfunction == 0x41
    assert stop.function_name == "umas: stop plc"
    assert start.function_name == "umas: start plc"
    assert stop.is_control and start.is_control
    assert not stop.is_write


def test_umas_memory_write_and_program_download_are_writes():
    write = modbus.parse(bytes.fromhex("000a00000005005a012100"))
    download = modbus.parse(bytes.fromhex("000b00000005005a013000"))

    assert write is not None and download is not None
    assert write.function_name == "umas: write memory block"
    assert download.function_name == "umas: begin download"
    assert write.is_write and download.is_write
    assert not download.is_control


def test_umas_read_is_neither_write_nor_control():
    pdu = modbus.parse(bytes.fromhex("000c00000005005a012000"))

    assert pdu is not None
    assert pdu.function_name == "umas: read memory block"
    assert not pdu.is_write
    assert not pdu.is_control


def test_unknown_umas_code_falls_back_to_a_label():
    pdu = modbus.parse(bytes.fromhex("000d00000004005a0158"))

    assert pdu is not None
    assert pdu.function_name == "umas: function 0x58"


def test_umas_response_status_is_read_as_success_or_error():
    # In a response the byte after the session key is a status, not a code.
    failed = modbus.parse(bytes.fromhex("000800000004005a01fd"), request=False)
    succeeded = modbus.parse(bytes.fromhex("000800000004005a01fe"), request=False)

    assert failed is not None and succeeded is not None
    assert failed.is_exception
    assert failed.exception_name == "umas error"
    assert not succeeded.is_exception
    assert succeeded.subfunction is None


def test_truncated_umas_request_has_no_subfunction():
    pdu = modbus.parse(bytes.fromhex("000e00000003005a01"))

    assert pdu is not None
    assert pdu.subfunction is None
    assert pdu.function_name == "umas"
