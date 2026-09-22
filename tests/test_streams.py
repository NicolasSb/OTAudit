from otaudit.streams import DirectionalStream


def test_contiguous_segments_are_appended():
    stream = DirectionalStream()
    stream.push(100, b"abc")
    stream.push(103, b"de")

    assert bytes(stream.buffer) == b"abcde"
    assert stream.gaps == 0


def test_duplicate_segment_is_ignored():
    stream = DirectionalStream()
    stream.push(100, b"abc")
    stream.push(100, b"abc")

    assert bytes(stream.buffer) == b"abc"


def test_overlapping_retransmission_keeps_new_bytes_only():
    stream = DirectionalStream()
    stream.push(100, b"abc")
    stream.push(102, b"cde")

    assert bytes(stream.buffer) == b"abcde"


def test_gap_resynchronises_and_is_counted():
    stream = DirectionalStream()
    stream.push(100, b"abc")
    stream.push(200, b"xyz")

    assert bytes(stream.buffer) == b"xyz"
    assert stream.gaps == 1


def test_sequence_number_wraparound():
    stream = DirectionalStream()
    start = 0xFFFFFFFE
    stream.push(start, b"ab")
    stream.push(0, b"cd")

    assert bytes(stream.buffer) == b"abcd"
    assert stream.gaps == 0


def test_take_consumes_from_the_head():
    stream = DirectionalStream()
    stream.push(1, b"abcdef")

    assert stream.take(2) == b"ab"
    assert len(stream) == 4


def test_empty_payload_is_ignored():
    stream = DirectionalStream()
    stream.push(1, b"")

    assert stream.expected is None
