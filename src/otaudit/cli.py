"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .analysis import analyse
from .ebios import to_ebios
from .findings import evaluate
from .models import SEVERITY_ORDER, Finding, Report, Severity
from .pcapfile import PcapError
from .report import render
from .scope import ScopeError, load_scope

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FINDINGS = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="otaudit",
        description="Passive audit of Modbus/TCP and S7comm traffic captures.",
    )
    parser.add_argument("--version", action="version", version=f"otaudit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check-scope", help="validate an engagement scope file")
    check.add_argument("scope", type=Path)

    analyse_parser = subparsers.add_parser("analyse", help="analyse a capture against a scope")
    analyse_parser.add_argument("pcap", type=Path)
    analyse_parser.add_argument("--scope", type=Path, required=True)
    analyse_parser.add_argument("--report", type=Path, help="write the Markdown report here")
    analyse_parser.add_argument("--json", type=Path, help="write the raw inventory here")
    analyse_parser.add_argument("--ebios", type=Path, help="write the EBIOS RM scaffold here")
    analyse_parser.add_argument(
        "--fail-on",
        choices=[severity.value for severity in Severity],
        help="exit with status 3 if a finding reaches this severity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "check-scope":
            return _check_scope(arguments.scope)
        return _analyse(arguments)
    except (ScopeError, PcapError) as error:
        print(f"otaudit: {error}", file=sys.stderr)
        return EXIT_USAGE


def _check_scope(path: Path) -> int:
    scope = load_scope(path)
    targets = ", ".join(str(network) for network in scope.targets)
    print(f"scope valid: {scope.engagement} ({scope.reference})")
    print(f"  authorised by {scope.authorized_by}")
    print(f"  window        {scope.window.start.isoformat()} .. {scope.window.end.isoformat()}")
    print(f"  targets       {targets}")
    if scope.exclusions:
        print(f"  exclusions    {', '.join(str(n) for n in scope.exclusions)}")
    return EXIT_OK


def _analyse(arguments: argparse.Namespace) -> int:
    scope = load_scope(arguments.scope)
    if not arguments.pcap.exists():
        raise PcapError(f"{arguments.pcap}: no such file")
    capture, devices, conversations = analyse(arguments.pcap, scope)
    findings = evaluate(capture, devices, conversations)
    report = Report(
        scope=scope,
        capture=capture,
        devices=devices,
        conversations=conversations,
        findings=findings,
        generated_at=datetime.now(tz=UTC),
    )

    rendered = render(report)
    if arguments.report:
        arguments.report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    if arguments.json:
        arguments.json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if arguments.ebios:
        arguments.ebios.write_text(
            json.dumps(to_ebios(report), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    if arguments.report:
        summary = ", ".join(f"{s.value}: {_count(findings, s)}" for s in Severity)
        print(f"{len(devices)} devices, {len(findings)} findings ({summary})", file=sys.stderr)
    if arguments.fail_on and _reaches(findings, Severity(arguments.fail_on)):
        return EXIT_FINDINGS
    return EXIT_OK


def _count(findings: list[Finding], severity: Severity) -> int:
    return sum(1 for finding in findings if finding.severity is severity)


def _reaches(findings: list[Finding], threshold: Severity) -> bool:
    limit = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] <= limit for finding in findings)


if __name__ == "__main__":
    raise SystemExit(main())
