"""Rules turning observations into findings.

Each rule states what was observed, never what is assumed. A capture shows
traffic, so a finding says "no authentication was observed on this exchange",
not "the device has no authentication". The distinction matters when the report
is handed to an operator who has to answer it.

References point to IEC 62443-4-2 component requirements and to the ANSSI
guide "La cybersécurité des systèmes industriels - Méthode de classification et
mesures principales" (2014). Both are starting points for the discussion with
the integrator, not verdicts.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from ipaddress import IPv4Address

from .analysis import LEGACY_SERVICES, merge_ranges
from .models import (
    SEVERITY_ORDER,
    Capture,
    Conversation,
    Device,
    Finding,
    Protocol,
    Severity,
    format_ranges,
)

EXCEPTION_RATIO_THRESHOLD = 0.05
EXCEPTION_MINIMUM_RESPONSES = 20
JITTER_RATIO_THRESHOLD = 1.0
JITTER_MINIMUM_REQUESTS = 100
SILENT_MINIMUM_REQUESTS = 10
# Clients address a native Modbus/TCP device with 0 or 255; only 1-247 name serial slaves.
SERIAL_UNIT_IDS = range(1, 248)
HIGH_RISK_SERVICES = {21, 23, 69, 5900}

Rule = Callable[[Capture, list[Device], list[Conversation]], list[Finding]]


def evaluate(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(capture, devices, conversations))
    return sorted(findings, key=lambda item: (SEVERITY_ORDER[item.severity], item.identifier))


def _cleartext_control(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    if not conversations:
        return []
    protocols = sorted({item.protocol.value for item in conversations})
    servers = sorted({str(item.server) for item in conversations})
    return [
        Finding(
            identifier="OT-001",
            title="Control traffic carried without authentication or integrity protection",
            severity=Severity.MEDIUM,
            assets=servers,
            evidence=[
                f"{protocol} observed in clear text on the mirrored segment"
                for protocol in protocols
            ],
            iec_62443=["CR 3.1", "CR 4.1"],
            anssi=["Mesure 15 (cloisonnement)", "Mesure 19 (protocoles)"],
            recommendation=(
                "Neither Modbus/TCP nor S7comm carries authentication. Compensate at the network "
                "layer: dedicated VLAN, filtering between the control segment and everything else, "
                "and no route from office IT to port 502 or 102."
            ),
        )
    ]


def _write_operations(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    writing = [item for item in conversations if item.writes]
    if not writing:
        return []
    evidence = [
        f"{item.client} -> {item.server}:{item.port} - {item.writes} write requests"
        + (f" ({'; '.join(item.written_ranges)})" if item.written_ranges else "")
        for item in writing
    ]
    return [
        Finding(
            identifier="OT-002",
            title="Write operations observed on the control network",
            severity=Severity.MEDIUM,
            assets=sorted({str(item.server) for item in writing}),
            evidence=evidence,
            iec_62443=["CR 1.2", "CR 2.1"],
            anssi=["Mesure 12 (gestion des droits)"],
            recommendation=(
                "Confirm with the operator that each writing host is a legitimate controller. "
                "Any host able to reach port 502 or 102 can issue the same requests, so the "
                "control list is whatever the firewall allows, not what the application intends."
            ),
        )
    ]


def _multiple_masters(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    writers: dict[IPv4Address, set[IPv4Address]] = defaultdict(set)
    for item in conversations:
        if item.writes:
            writers[item.server].add(item.client)
    contested = {server: clients for server, clients in writers.items() if len(clients) > 1}
    if not contested:
        return []
    evidence = []
    for server, clients in sorted(contested.items()):
        evidence.append(f"{server} written by {', '.join(str(c) for c in sorted(clients))}")
        evidence.extend(_shared_registers(server, sorted(clients), conversations))
    return [
        Finding(
            identifier="OT-003",
            title="Several hosts write to the same device",
            severity=Severity.HIGH,
            assets=sorted(str(server) for server in contested),
            evidence=evidence,
            iec_62443=["CR 2.1"],
            anssi=["Mesure 12 (gestion des droits)"],
            recommendation=(
                "Identify each writer and the reason it exists. A second master is usually a "
                "maintenance laptop or a supervision station left connected after commissioning; "
                "concurrent writes to the same registers also cause process incidents that are "
                "hard to attribute."
            ),
        )
    ]


def _shared_registers(
    server: IPv4Address, clients: list[IPv4Address], conversations: list[Conversation]
) -> list[str]:
    """Say which registers several writers have in common, when the ranges are known."""
    written: dict[IPv4Address, dict[str, set[tuple[int, int]]]] = {
        client: defaultdict(set) for client in clients
    }
    for item in conversations:
        if item.server == server and item.client in written:
            for target, ranges in item.written.items():
                written[item.client][target].update(ranges)
    lines = []
    for index, first in enumerate(clients):
        for second in clients[index + 1 :]:
            for target in sorted(written[first].keys() & written[second].keys()):
                shared = _intersection(written[first][target], written[second][target])
                if shared:
                    lines.append(
                        f"{first} and {second} both write {target} {format_ranges(shared)}"
                    )
    if not lines and all(written[client] for client in clients):
        lines.append(f"{server}: no register is written by more than one host")
    return lines


def _intersection(left: set[tuple[int, int]], right: set[tuple[int, int]]) -> list[tuple[int, int]]:
    shared = {
        (max(a_first, b_first), min(a_last, b_last))
        for a_first, a_last in left
        for b_first, b_last in right
        if max(a_first, b_first) <= min(a_last, b_last)
    }
    return merge_ranges(shared)


def _plc_control(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    controlling = [item for item in conversations if item.controls]
    if not controlling:
        return []
    ports = ", ".join(str(port) for port in sorted({item.port for item in controlling}))
    protocols = {item.protocol for item in controlling}
    protections = []
    if Protocol.S7COMM in protocols:
        protections.append("the S7 CPU protection level")
    if Protocol.MODBUS in protocols:
        protections.append("the Modicon application password")
    return [
        Finding(
            identifier="OT-004",
            title="CPU control services invoked during the capture",
            severity=Severity.HIGH,
            assets=sorted({str(item.server) for item in controlling}),
            evidence=[
                f"{item.client} -> {item.server}:{item.port} - {item.controls} control requests"
                for item in controlling
            ],
            iec_62443=["CR 2.1", "CR 7.1"],
            anssi=["Mesure 12 (gestion des droits)", "Mesure 17 (journalisation)"],
            recommendation=(
                "Start, stop and restart requests reach the device with no authentication. "
                f"Restrict port {ports} to the engineering station, enable "
                f"{' and '.join(protections)}, and log the source of every such request."
            ),
        )
    ]


def _undeclared_assets(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    findings: list[Finding] = []
    outside = [
        device for device in devices if device.roles and not device.in_scope and not device.excluded
    ]
    if outside:
        findings.append(
            Finding(
                identifier="OT-005",
                title="Industrial hosts seen outside the declared target ranges",
                severity=Severity.MEDIUM,
                assets=[str(device.address) for device in outside],
                evidence=[
                    f"{device.address} ({', '.join(device.roles)}) not covered by scope targets"
                    for device in outside
                ],
                iec_62443=["CR 1.2"],
                anssi=["Mesure 1 (cartographie)"],
                recommendation=(
                    "The asset inventory used to write the scope does not match the traffic. "
                    "Reconcile before drawing any conclusion from the rest of this report: an "
                    "audit that missed a device also missed its exposure."
                ),
            )
        )
    breached = [device for device in devices if device.excluded]
    if breached:
        findings.append(
            Finding(
                identifier="OT-006",
                title="Traffic captured from an excluded host",
                severity=Severity.HIGH,
                assets=[str(device.address) for device in breached],
                evidence=[
                    f"{device.address} was listed under scope exclusions" for device in breached
                ],
                iec_62443=[],
                anssi=[],
                recommendation=(
                    "The capture covers a host the authorisation excluded. Report this to the "
                    "engagement sponsor, and delete the corresponding frames from the evidence "
                    "before the report leaves your hands."
                ),
            )
        )
    return findings


def _protocol_exceptions(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    noisy = [
        item
        for item in conversations
        if item.responses >= EXCEPTION_MINIMUM_RESPONSES
        and item.exception_ratio >= EXCEPTION_RATIO_THRESHOLD
    ]
    if not noisy:
        return []
    evidence = []
    for item in noisy:
        detail = ", ".join(f"{name} x{count}" for name, count in item.exceptions.items())
        evidence.append(
            f"{item.client} -> {item.server}:{item.port} - "
            f"{item.exception_ratio:.0%} of responses are exceptions ({detail})"
        )
    return [
        Finding(
            identifier="OT-007",
            title="Recurrent protocol exceptions",
            severity=Severity.LOW,
            assets=sorted({str(item.server) for item in noisy}),
            evidence=evidence,
            iec_62443=["CR 7.2"],
            anssi=["Mesure 17 (journalisation)"],
            recommendation=(
                "Persistent exceptions usually mean a supervision template polling addresses that "
                "no longer exist. Harmless in itself, it consumes cycles on the device and hides "
                "genuine faults in the logs."
            ),
        )
    ]


def _legacy_services(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    exposed = [device for device in devices if device.other_ports]
    if not exposed:
        return []
    severity = Severity.MEDIUM
    evidence = []
    for device in exposed:
        names = ", ".join(
            f"{LEGACY_SERVICES.get(port, port)}/{port}" for port in device.other_ports
        )
        evidence.append(f"{device.address}: {names}")
        if any(port in HIGH_RISK_SERVICES for port in device.other_ports):
            severity = Severity.HIGH
    return [
        Finding(
            identifier="OT-008",
            title="Legacy management services reachable on the control segment",
            severity=severity,
            assets=[str(device.address) for device in exposed],
            evidence=evidence,
            iec_62443=["CR 1.1", "CR 4.1", "CR 7.6"],
            anssi=["Mesure 14 (durcissement)", "Mesure 19 (protocoles)"],
            recommendation=(
                "Disable the services that are not required for operation. Where an HMI or a "
                "gateway genuinely needs them, restrict the source addresses and stop using the "
                "ones that carry credentials in clear."
            ),
        )
    ]


def _identification_disclosure(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    disclosed = [device for device in devices if device.identification]
    if not disclosed:
        return []
    evidence = [
        f"{device.address}: "
        + ", ".join(f"{key}={value}" for key, value in device.identification.items())
        for device in disclosed
    ]
    return [
        Finding(
            identifier="OT-009",
            title="Devices disclose model and firmware to any peer",
            severity=Severity.LOW,
            assets=[str(device.address) for device in disclosed],
            evidence=evidence,
            iec_62443=["CR 1.2"],
            anssi=["Mesure 1 (cartographie)", "Mesure 20 (veille vulnérabilités)"],
            recommendation=(
                "Identification cannot be turned off on these protocols, and it is useful to you "
                "as much as to an attacker. Use it: match each order number and firmware version "
                "against the CISA ICS advisories and the vendor bulletins, and record the result "
                "in the asset inventory."
            ),
        )
    ]


def _polling_stability(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    unstable = [
        item
        for item in conversations
        if item.requests >= JITTER_MINIMUM_REQUESTS
        and item.mean_interval_ms
        and item.jitter_ms
        and item.jitter_ms / item.mean_interval_ms >= JITTER_RATIO_THRESHOLD
    ]
    if not unstable:
        return []
    evidence = [
        f"{item.client} -> {item.server}:{item.port} - mean {item.mean_interval_ms:.0f} ms, "
        f"deviation {item.jitter_ms:.0f} ms over {item.requests} requests"
        for item in unstable
    ]
    return [
        Finding(
            identifier="OT-010",
            title="Unstable polling intervals",
            severity=Severity.INFO,
            assets=sorted({str(item.server) for item in unstable}),
            evidence=evidence,
            iec_62443=["CR 7.2"],
            anssi=["Mesure 17 (journalisation)"],
            recommendation=(
                "Deviation as large as the interval itself points to a loaded device, a saturated "
                "link or a mirrored port dropping frames. Establish which before reading anything "
                "into the timing figures elsewhere in this report."
            ),
        )
    ]


def _capture_window(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    if capture.within_window or capture.started_at is None or capture.ended_at is None:
        return []
    return [
        Finding(
            identifier="OT-011",
            title="Capture falls outside the authorised window",
            severity=Severity.MEDIUM,
            assets=[],
            evidence=[
                f"capture runs from {capture.started_at.isoformat()} to "
                f"{capture.ended_at.isoformat()}"
            ],
            iec_62443=[],
            anssi=[],
            recommendation=(
                "Either the capture was taken outside the agreed window, or the scope file is "
                "wrong. Settle it with the sponsor before issuing the report; evidence collected "
                "outside an authorisation is not evidence you can use."
            ),
        )
    ]


def _modbus_gateways(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    gateways = [
        device
        for device in devices
        if len([unit for unit in device.unit_ids if unit in SERIAL_UNIT_IDS]) > 1
    ]
    if not gateways:
        return []
    return [
        Finding(
            identifier="OT-012",
            title="Modbus gateway fronting a serial bus outside the capture",
            severity=Severity.MEDIUM,
            assets=[str(device.address) for device in gateways],
            evidence=[
                f"{device.address} is addressed with unit IDs "
                + ", ".join(str(unit) for unit in device.unit_ids)
                for device in gateways
            ],
            iec_62443=["CR 1.2"],
            anssi=["Mesure 1 (cartographie)"],
            recommendation=(
                "Each unit ID is a device on a serial bus the capture cannot see: inventory them "
                "from the gateway configuration. Any host that reaches the gateway on port 502 "
                "can read and write every one of them, so filter its sources as for a PLC."
            ),
        )
    ]


def _silent_exchanges(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    silent = [
        item
        for item in conversations
        if item.requests >= SILENT_MINIMUM_REQUESTS and item.responses == 0
    ]
    if not silent:
        return []
    evidence = []
    if not any(item.responses for item in conversations):
        evidence.append(
            "no exchange in the capture carries a response: the mirror is probably one-way"
        )
    evidence.extend(
        f"{item.client} -> {item.server}:{item.port} - {item.requests} requests, no response"
        for item in silent
    )
    return [
        Finding(
            identifier="OT-013",
            title="Requests observed without any response",
            severity=Severity.INFO,
            assets=sorted({str(item.server) for item in silent}),
            evidence=evidence,
            iec_62443=[],
            anssi=[],
            recommendation=(
                "Either the mirror carries one direction only, or the device does not answer. "
                "Check the SPAN configuration before writing anything about these devices: a "
                "one-way capture hides every response, identification and exception."
            ),
        )
    ]


RULES: tuple[Rule, ...] = (
    _cleartext_control,
    _write_operations,
    _multiple_masters,
    _plc_control,
    _undeclared_assets,
    _protocol_exceptions,
    _legacy_services,
    _identification_disclosure,
    _polling_stability,
    _capture_window,
    _modbus_gateways,
    _silent_exchanges,
)
