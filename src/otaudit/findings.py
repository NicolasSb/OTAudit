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

from .analysis import LEGACY_SERVICES
from .models import (
    SEVERITY_ORDER,
    Capture,
    Conversation,
    Device,
    Finding,
    Severity,
)

EXCEPTION_RATIO_THRESHOLD = 0.05
EXCEPTION_MINIMUM_RESPONSES = 20
JITTER_RATIO_THRESHOLD = 1.0
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
    evidence = [
        f"{server} written by {', '.join(str(client) for client in sorted(clients))}"
        for server, clients in sorted(contested.items())
    ]
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


def _plc_control(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    controlling = [item for item in conversations if item.controls]
    if not controlling:
        return []
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
                "Start and stop requests reach the CPU with no authentication. Restrict port 102 "
                "to the engineering station, enable the CPU protection level, and log the source "
                "of every such request."
            ),
        )
    ]


def _undeclared_assets(
    capture: Capture, devices: list[Device], conversations: list[Conversation]
) -> list[Finding]:
    findings: list[Finding] = []
    outside = [device for device in devices if not device.in_scope and not device.excluded]
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
        if item.mean_interval_ms
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
)
