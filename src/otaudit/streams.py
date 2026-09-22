"""Per-direction byte stream rebuilding.

Control traffic is small and rarely reordered, but retransmissions are common
on a saturated industrial network and a mirrored port drops packets under load.
The reassembler handles duplicates and overlaps, and resynchronises on a gap
rather than pretending the bytes are contiguous.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DirectionalStream:
    """Ordered bytes of one direction of one TCP connection."""

    expected: int | None = None
    buffer: bytearray = field(default_factory=bytearray)
    gaps: int = 0

    def push(self, sequence: int, payload: bytes) -> None:
        if not payload:
            return
        if self.expected is None:
            self.expected = sequence
        if sequence == self.expected:
            self.buffer += payload
            self.expected = _wrap(sequence + len(payload))
            return
        overlap = _distance(sequence, self.expected)
        if 0 < overlap <= len(payload):
            # Retransmission that starts before what we already have.
            self.buffer += payload[overlap:]
            self.expected = _wrap(sequence + len(payload))
            return
        if overlap >= len(payload):
            # Pure duplicate.
            return
        # Missing bytes: drop what is buffered rather than splice a false frame.
        self.gaps += 1
        self.buffer.clear()
        self.buffer += payload
        self.expected = _wrap(sequence + len(payload))

    def take(self, count: int) -> bytes:
        taken = bytes(self.buffer[:count])
        del self.buffer[:count]
        return taken

    def __len__(self) -> int:
        return len(self.buffer)


def _wrap(value: int) -> int:
    return value & 0xFFFFFFFF


def _distance(earlier: int, later: int) -> int:
    """Signed distance later - earlier over the 32-bit sequence space."""
    delta = (later - earlier) & 0xFFFFFFFF
    return delta - 0x100000000 if delta > 0x7FFFFFFF else delta
