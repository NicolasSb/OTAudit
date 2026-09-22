from otaudit.protocols import s7
from otaudit.synthesis import s7_frame, s7_szl_response, szl_component_record, szl_module_record

CONNECT_REQUEST = bytes.fromhex("0300001611e00000000100c1020100c2020102c0010a")


def test_connect_request_carries_no_s7_payload():
    assert s7.parse(CONNECT_REQUEST) is None


def test_parse_read_variable_job():
    frame = s7_frame(0x01, bytes([0x04, 0x01]))
    message = s7.parse(frame)

    assert message is not None
    assert message.rosctr == 0x01
    assert message.rosctr_name == "job"
    assert message.function_name == "read variable"
    assert not message.is_write


def test_write_and_control_functions_are_flagged():
    write = s7.parse(s7_frame(0x01, bytes([0x05, 0x01])))
    stop = s7.parse(s7_frame(0x01, bytes([0x29, 0x00])))

    assert write is not None and write.is_write
    assert stop is not None and stop.is_control
    assert stop.function_name == "plc stop"


def test_error_fields_are_read_from_ack_data():
    frame = s7_frame(0x03, bytes([0x04, 0x01]), error=b"\x81\x04")
    message = s7.parse(frame)

    assert message is not None
    assert message.error_class == 0x81
    assert message.error_code == 0x04
    assert message.failed


def test_szl_component_identification_is_decoded():
    frame = s7_szl_response(
        0x001C,
        [szl_component_record(1, "LINE2_CPU"), szl_component_record(7, "CPU 1214C DC/DC/DC")],
        34,
    )
    message = s7.parse(frame)

    assert message is not None
    assert message.identification == {
        "plc_name": "LINE2_CPU",
        "module_type": "CPU 1214C DC/DC/DC",
    }


def test_szl_module_identification_is_decoded():
    frame = s7_szl_response(0x0011, [szl_module_record("6ES7 214-1AG40-0XB0")], 28)
    message = s7.parse(frame)

    assert message is not None
    assert message.identification == {"article_number": "6ES7 214-1AG40-0XB0"}


def test_other_szl_lists_are_ignored():
    frame = s7_szl_response(0x0132, [szl_component_record(1, "whatever")], 34)
    message = s7.parse(frame)

    assert message is not None
    assert message.identification == {}


def test_split_frames_handles_partial_frames_and_garbage():
    first = s7_frame(0x01, bytes([0x04, 0x01]))
    second = s7_frame(0x01, bytes([0x05, 0x01]))
    buffer = bytearray(b"\x99\x99" + first + second[:6])

    assert s7.split_frames(buffer) == [first]

    buffer += second[6:]
    assert s7.split_frames(buffer) == [second]
    assert not buffer


def test_unknown_function_falls_back_to_a_label():
    message = s7.parse(s7_frame(0x01, bytes([0x77, 0x00])))

    assert message is not None
    assert message.function_name == "function 0x77"


def test_short_and_malformed_frames_are_rejected():
    assert s7.parse(b"\x03\x00\x00") is None
    assert s7.parse(s7_frame(0x01, b"")) is not None
