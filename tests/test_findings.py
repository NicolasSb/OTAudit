from datetime import UTC, datetime
from ipaddress import IPv4Address

from otaudit.analysis import analyse
from otaudit.findings import evaluate
from otaudit.models import (
    SEVERITY_ORDER,
    Capture,
    Conversation,
    Device,
    Protocol,
    Severity,
)

MOMENT = datetime(2023, 11, 14, 22, 0, tzinfo=UTC)


def empty_capture(**overrides):
    defaults = {"path": "x.pcap", "started_at": MOMENT, "ended_at": MOMENT, "within_window": True}
    return Capture(**{**defaults, **overrides})


def make_conversation(client, server, **overrides):
    defaults = {
        "client": IPv4Address(client),
        "server": IPv4Address(server),
        "port": 502,
        "protocol": Protocol.MODBUS,
        "first_seen": MOMENT,
        "last_seen": MOMENT,
    }
    return Conversation(**{**defaults, **overrides})


def identifiers(findings):
    return [finding.identifier for finding in findings]


def test_sample_capture_raises_the_expected_findings(sample_capture, sample_scope):
    capture, devices, conversations = analyse(sample_capture, sample_scope)
    findings = evaluate(capture, devices, conversations)

    assert identifiers(findings) >= ["OT-003", "OT-008"]
    assert {"OT-001", "OT-002", "OT-005", "OT-009"} <= set(identifiers(findings))


def test_findings_are_sorted_by_severity(sample_capture, sample_scope):
    capture, devices, conversations = analyse(sample_capture, sample_scope)
    findings = evaluate(capture, devices, conversations)
    ranks = [SEVERITY_ORDER[finding.severity] for finding in findings]

    assert ranks == sorted(ranks)


def test_no_traffic_raises_nothing():
    assert evaluate(empty_capture(), [], []) == []


def test_multiple_writers_are_reported_once_per_server():
    conversations = [
        make_conversation("10.0.0.1", "10.0.0.9", writes=3),
        make_conversation("10.0.0.2", "10.0.0.9", writes=1),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    contested = next(item for item in findings if item.identifier == "OT-003")

    assert contested.severity is Severity.HIGH
    assert contested.assets == ["10.0.0.9"]
    assert "10.0.0.1, 10.0.0.2" in contested.evidence[0]


def test_control_functions_raise_a_high_finding():
    conversations = [make_conversation("10.0.0.1", "10.0.0.9", port=102, controls=2)]
    findings = evaluate(empty_capture(), [], conversations)

    assert "OT-004" in identifiers(findings)


def test_excluded_host_in_capture_is_a_high_finding():
    devices = [Device(address=IPv4Address("10.42.7.13"), in_scope=False, excluded=True)]
    findings = evaluate(empty_capture(), devices, [])
    breach = next(item for item in findings if item.identifier == "OT-006")

    assert breach.severity is Severity.HIGH
    assert "OT-005" not in identifiers(findings)


def test_exception_rule_needs_enough_responses():
    below = [make_conversation("10.0.0.1", "10.0.0.9", responses=10, exceptions={"busy": 10})]
    above = [make_conversation("10.0.0.1", "10.0.0.9", responses=100, exceptions={"busy": 20})]

    assert "OT-007" not in identifiers(evaluate(empty_capture(), [], below))
    assert "OT-007" in identifiers(evaluate(empty_capture(), [], above))


def test_high_risk_service_raises_the_severity():
    telnet = [Device(address=IPv4Address("10.0.0.9"), other_ports=[23])]
    http = [Device(address=IPv4Address("10.0.0.9"), other_ports=[80])]

    high = next(
        item for item in evaluate(empty_capture(), telnet, []) if item.identifier == "OT-008"
    )
    medium = next(
        item for item in evaluate(empty_capture(), http, []) if item.identifier == "OT-008"
    )

    assert high.severity is Severity.HIGH
    assert medium.severity is Severity.MEDIUM


def test_unstable_polling_is_informational():
    conversations = [
        make_conversation("10.0.0.1", "10.0.0.9", requests=150, mean_interval_ms=100, jitter_ms=250)
    ]
    finding = next(
        item for item in evaluate(empty_capture(), [], conversations) if item.identifier == "OT-010"
    )

    assert finding.severity is Severity.INFO


def test_capture_outside_window_is_reported():
    findings = evaluate(empty_capture(within_window=False), [], [])

    assert identifiers(findings) == ["OT-011"]


def test_every_finding_carries_a_recommendation(sample_capture, sample_scope):
    capture, devices, conversations = analyse(sample_capture, sample_scope)

    for finding in evaluate(capture, devices, conversations):
        assert finding.recommendation.strip()
        assert finding.evidence


def test_non_industrial_host_outside_targets_is_not_an_undeclared_asset():
    switch = [
        Device(address=IPv4Address("10.42.9.1"), in_scope=False, other_ports=[23]),
    ]
    findings = evaluate(empty_capture(), switch, [])

    assert "OT-005" not in identifiers(findings)
    assert "OT-008" in identifiers(findings)


def test_modbus_control_recommendation_names_the_modbus_port():
    conversations = [make_conversation("10.42.7.11", "10.42.7.21", controls=1)]
    findings = evaluate(empty_capture(), [], conversations)
    control = next(item for item in findings if item.identifier == "OT-004")

    assert "502" in control.recommendation
    assert "102" not in control.recommendation


def test_overlapping_writers_name_the_shared_registers():
    conversations = [
        make_conversation(
            "10.42.7.10", "10.42.7.20", writes=1, written={"unit 1 holding registers": [(100, 104)]}
        ),
        make_conversation(
            "10.42.9.80", "10.42.7.20", writes=1, written={"unit 1 holding registers": [(103, 110)]}
        ),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    contested = next(item for item in findings if item.identifier == "OT-003")

    assert "10.42.7.10 and 10.42.9.80 both write unit 1 holding registers 103-104" in (
        contested.evidence
    )


def test_writers_on_separate_registers_are_told_apart():
    conversations = [
        make_conversation(
            "10.42.7.10", "10.42.7.20", writes=1, written={"unit 1 holding registers": [(100, 104)]}
        ),
        make_conversation(
            "10.42.9.80", "10.42.7.20", writes=1, written={"unit 1 holding registers": [(200, 200)]}
        ),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    contested = next(item for item in findings if item.identifier == "OT-003")

    assert "10.42.7.20: no register is written by more than one host" in contested.evidence


def test_write_evidence_lists_the_written_ranges():
    conversations = [
        make_conversation(
            "10.42.7.10", "10.42.7.20", writes=2, written={"unit 1 coils": [(16, 17)]}
        ),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    writing = next(item for item in findings if item.identifier == "OT-002")

    assert writing.evidence == [
        "10.42.7.10 -> 10.42.7.20:502 - 2 write requests (unit 1 coils 16-17)"
    ]


def test_jitter_over_too_few_requests_is_not_reported():
    conversations = [
        make_conversation("10.0.0.1", "10.0.0.9", requests=50, mean_interval_ms=100, jitter_ms=250)
    ]

    assert "OT-010" not in identifiers(evaluate(empty_capture(), [], conversations))


def test_several_unit_ids_behind_one_address_reveal_a_gateway():
    devices = [
        Device(address=IPv4Address("10.42.7.25"), roles=["server"], unit_ids=[1, 2, 7]),
        Device(address=IPv4Address("10.42.7.20"), roles=["server"], unit_ids=[1]),
    ]
    findings = evaluate(empty_capture(), devices, [])
    gateway = next(item for item in findings if item.identifier == "OT-012")

    assert gateway.severity is Severity.MEDIUM
    assert gateway.assets == ["10.42.7.25"]
    assert gateway.evidence == ["10.42.7.25 is addressed with unit IDs 1, 2, 7"]


def test_unit_ids_0_and_255_do_not_make_a_gateway():
    # Both are what clients send to a native Modbus/TCP device; UMAS uses 0.
    devices = [
        Device(address=IPv4Address("10.42.7.21"), roles=["server"], unit_ids=[0, 1, 255]),
    ]

    assert "OT-012" not in identifiers(evaluate(empty_capture(), devices, []))


def test_exchange_without_any_response_is_reported():
    conversations = [
        make_conversation("10.42.7.10", "10.42.7.20", requests=40, responses=0, unanswered=40),
        make_conversation("10.42.7.10", "10.42.7.21", requests=40, responses=40),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    silent = next(item for item in findings if item.identifier == "OT-013")

    assert silent.severity is Severity.INFO
    assert silent.assets == ["10.42.7.20"]
    assert silent.evidence == ["10.42.7.10 -> 10.42.7.20:502 - 40 requests, no response"]


def test_one_way_capture_is_called_out():
    conversations = [
        make_conversation("10.42.7.10", "10.42.7.20", requests=40, responses=0, unanswered=40),
        make_conversation("10.42.7.10", "10.42.7.21", requests=12, responses=0, unanswered=12),
    ]
    findings = evaluate(empty_capture(), [], conversations)
    silent = next(item for item in findings if item.identifier == "OT-013")

    assert silent.evidence[0] == (
        "no exchange in the capture carries a response: the mirror is probably one-way"
    )


def test_a_few_unanswered_requests_are_not_reported():
    conversations = [
        make_conversation("10.42.7.10", "10.42.7.20", requests=5, responses=0, unanswered=5),
    ]

    assert "OT-013" not in identifiers(evaluate(empty_capture(), [], conversations))
