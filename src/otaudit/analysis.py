"""Turn a capture into an inventory of devices and conversations."""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from itertools import pairwise
from pathlib import Path

from . import net
from .models import Capture, Conversation, Device, Protocol, Scope
from .pcapfile import PcapReader
from .protocols import modbus, s7
from .streams import DirectionalStream

INDUSTRIAL_PORTS = {modbus.PORT: Protocol.MODBUS, s7.PORT: Protocol.S7COMM}

LEGACY_SERVICES = {
    21: "ftp",
    23: "telnet",
    69: "tftp",
    80: "http",
    111: "rpcbind",
    161: "snmp",
    445: "smb",
    2000: "cisco-sccp",
    3389: "rdp",
    5900: "vnc",
    20000: "dnp3",
    44818: "ethernet/ip",
    47808: "bacnet",
}

# Listed services that run over UDP. TFTP is kept apart because its server answers
# from a fresh port, so the reply never carries port 69.
LEGACY_UDP_SERVICES = frozenset({111, 161, 20000, 44818, 47808})
TFTP_PORT = 69

FlowKey = tuple[IPv4Address, IPv4Address, int, Protocol]


@dataclass
class _Flow:
    protocol: Protocol
    requests: int = 0
    responses: int = 0
    writes: int = 0
    controls: int = 0
    unit_ids: set[int] = field(default_factory=set)
    functions: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    exceptions: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    request_times: list[float] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class _DeviceState:
    roles: set[str] = field(default_factory=set)
    protocols: set[Protocol] = field(default_factory=set)
    unit_ids: set[int] = field(default_factory=set)
    identification: dict[str, str] = field(default_factory=dict)
    other_ports: set[int] = field(default_factory=set)


class Analyser:
    """Accumulate state across a capture, then emit the model objects."""

    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self._flows: dict[FlowKey, _Flow] = {}
        self._devices: dict[IPv4Address, _DeviceState] = defaultdict(_DeviceState)
        self._streams: dict[tuple[IPv4Address, int, IPv4Address, int], DirectionalStream] = {}
        self._tftp_requests: set[tuple[IPv4Address, int, IPv4Address]] = set()
        self.packets = 0
        self.industrial_frames = 0
        self.truncated = 0
        self.first_seen: float | None = None
        self.last_seen: float | None = None

    def feed(self, segment: net.Segment) -> None:
        self._note_time(segment.timestamp)
        if segment.transport == net.PROTOCOL_UDP:
            self._note_udp_service(segment)
            return
        self.packets += 1
        protocol = INDUSTRIAL_PORTS.get(segment.destination_port) or INDUSTRIAL_PORTS.get(
            segment.source_port
        )
        if protocol is None:
            self._note_other_service(segment)
            return
        is_request = segment.destination_port in INDUSTRIAL_PORTS
        client = segment.source if is_request else segment.destination
        server = segment.destination if is_request else segment.source
        port = segment.destination_port if is_request else segment.source_port
        self._devices[client].roles.add("client")
        self._devices[server].roles.add("server")
        self._devices[server].protocols.add(protocol)
        if not segment.payload:
            return
        for frame in self._frames(segment, protocol):
            self.industrial_frames += 1
            key: FlowKey = (client, server, port, protocol)
            flow = self._flows.setdefault(key, _Flow(protocol=protocol))
            if flow.first_seen == 0.0:
                flow.first_seen = segment.timestamp
            flow.last_seen = segment.timestamp
            if protocol is Protocol.MODBUS:
                self._handle_modbus(frame, flow, server, is_request, segment.timestamp)
            else:
                self._handle_s7(frame, flow, server, is_request, segment.timestamp)

    def _frames(self, segment: net.Segment, protocol: Protocol) -> list[bytes]:
        key = (segment.source, segment.source_port, segment.destination, segment.destination_port)
        stream = self._streams.setdefault(key, DirectionalStream())
        stream.push(segment.sequence, segment.payload)
        splitter = modbus.split_frames if protocol is Protocol.MODBUS else s7.split_frames
        return splitter(stream.buffer)

    def _handle_modbus(
        self,
        frame: bytes,
        flow: _Flow,
        server: IPv4Address,
        is_request: bool,
        timestamp: float,
    ) -> None:
        pdu = modbus.parse(frame)
        if pdu is None:
            return
        flow.unit_ids.add(pdu.unit_id)
        self._devices[server].unit_ids.add(pdu.unit_id)
        if is_request:
            flow.requests += 1
            flow.request_times.append(timestamp)
            flow.functions[pdu.function_name] += 1
            if pdu.is_write:
                flow.writes += 1
            return
        flow.responses += 1
        if pdu.is_exception and pdu.exception_name:
            flow.exceptions[pdu.exception_name] += 1
        if pdu.identification:
            self._devices[server].identification.update(pdu.identification)

    def _handle_s7(
        self,
        frame: bytes,
        flow: _Flow,
        server: IPv4Address,
        is_request: bool,
        timestamp: float,
    ) -> None:
        message = s7.parse(frame)
        if message is None or message.function_name is None:
            return
        if is_request:
            flow.requests += 1
            flow.request_times.append(timestamp)
            flow.functions[message.function_name] += 1
            if message.is_write:
                flow.writes += 1
            if message.is_control:
                flow.controls += 1
            return
        flow.responses += 1
        if message.failed:
            flow.exceptions[f"error {message.error_class:#04x}{message.error_code:02x}"] += 1
        if message.identification:
            self._devices[server].identification.update(message.identification)

    def _note_other_service(self, segment: net.Segment) -> None:
        # Only the server side proves a service exists: a SYN to a closed port, or one
        # answered by a reset, says something about the client, not the host. The lower
        # port test keeps a client whose ephemeral port happens to be listed from being
        # taken for the server.
        service_port = segment.source_port
        if service_port not in LEGACY_SERVICES or service_port >= segment.destination_port:
            return
        if segment.flags & net.RST:
            return
        accepted = segment.flags & (net.SYN | net.ACK) == net.SYN | net.ACK
        if not segment.payload and not accepted:
            return
        self._devices[segment.source].other_ports.add(service_port)

    def _note_udp_service(self, segment: net.Segment) -> None:
        if segment.destination_port == TFTP_PORT:
            self._tftp_requests.add((segment.source, segment.source_port, segment.destination))
            return
        if (segment.destination, segment.destination_port, segment.source) in self._tftp_requests:
            self._devices[segment.source].other_ports.add(TFTP_PORT)
            return
        # As over TCP, only a datagram sent from the service port proves the service.
        # Equal ports are allowed: BACnet devices talk from 47808 to 47808.
        service_port = segment.source_port
        if service_port in LEGACY_UDP_SERVICES and service_port <= segment.destination_port:
            self._devices[segment.source].other_ports.add(service_port)

    def _note_time(self, timestamp: float) -> None:
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp

    @property
    def stream_gaps(self) -> int:
        return sum(stream.gaps for stream in self._streams.values())

    def devices(self) -> list[Device]:
        devices = []
        for address, state in self._devices.items():
            if not state.protocols and not state.roles:
                continue
            devices.append(
                Device(
                    address=address,
                    roles=sorted(state.roles),
                    protocols=sorted(state.protocols, key=lambda item: item.value),
                    unit_ids=sorted(state.unit_ids),
                    identification=dict(sorted(state.identification.items())),
                    in_scope=self.scope.covers(address),
                    excluded=self.scope.excluded(address),
                    other_ports=sorted(state.other_ports),
                )
            )
        return sorted(devices, key=lambda device: device.address)

    def conversations(self) -> list[Conversation]:
        conversations = []
        for (client, server, port, protocol), flow in self._flows.items():
            mean, jitter = _interval_statistics(flow.request_times)
            conversations.append(
                Conversation(
                    client=client,
                    server=server,
                    port=port,
                    protocol=protocol,
                    requests=flow.requests,
                    responses=flow.responses,
                    writes=flow.writes,
                    controls=flow.controls,
                    unit_ids=sorted(flow.unit_ids),
                    functions=dict(sorted(flow.functions.items())),
                    exceptions=dict(sorted(flow.exceptions.items())),
                    first_seen=_moment(flow.first_seen),
                    last_seen=_moment(flow.last_seen),
                    mean_interval_ms=mean,
                    jitter_ms=jitter,
                )
            )
        return sorted(conversations, key=lambda item: (item.server, item.client, item.port))

    def capture(self, path: Path) -> Capture:
        started = _moment(self.first_seen) if self.first_seen is not None else None
        ended = _moment(self.last_seen) if self.last_seen is not None else None
        within = True
        if started is not None and ended is not None:
            within = self.scope.window.contains(started) and self.scope.window.contains(ended)
        return Capture(
            path=str(path),
            started_at=started,
            ended_at=ended,
            packets=self.packets,
            industrial_frames=self.industrial_frames,
            truncated_records=self.truncated,
            stream_gaps=self.stream_gaps,
            within_window=within,
        )


def analyse(path: Path, scope: Scope) -> tuple[Capture, list[Device], list[Conversation]]:
    analyser = Analyser(scope)
    with PcapReader(path) as reader:
        for record in reader:
            if record.truncated:
                analyser.truncated += 1
            segment = net.decode(record, reader.linktype)
            if segment is not None:
                analyser.feed(segment)
    return analyser.capture(path), analyser.devices(), analyser.conversations()


def _interval_statistics(times: list[float]) -> tuple[float | None, float | None]:
    if len(times) < 3:
        return None, None
    ordered = sorted(times)
    intervals = [(later - earlier) * 1000 for earlier, later in pairwise(ordered)]
    return round(statistics.fmean(intervals), 3), round(statistics.pstdev(intervals), 3)


def _moment(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=UTC)
