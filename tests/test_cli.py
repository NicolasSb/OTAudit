import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from otaudit.analysis import analyse
from otaudit.cli import main
from otaudit.ebios import to_ebios
from otaudit.findings import evaluate
from otaudit.models import Capture, Report
from otaudit.report import render

SCOPE = str(Path(__file__).resolve().parent.parent / "samples" / "scope.yaml")


def build_report(capture_path, scope):
    capture, devices, conversations = analyse(capture_path, scope)
    return Report(
        scope=scope,
        capture=capture,
        devices=devices,
        conversations=conversations,
        findings=evaluate(capture, devices, conversations),
        generated_at=datetime(2026, 4, 13, 6, 0, tzinfo=UTC),
    )


def test_rendered_report_contains_the_engagement_and_findings(sample_capture, sample_scope):
    text = render(build_report(sample_capture, sample_scope))

    assert "BC-2026-014" in text
    assert "10.42.7.30" in text
    assert "OT-003" in text
    assert "6ES7 214-1AG40-0XB0" in text


def test_rendered_report_states_its_limits(sample_capture, sample_scope):
    text = render(build_report(sample_capture, sample_scope))

    assert "No frame was emitted" in text
    assert "not evidence of absence" in text


def test_report_with_no_traffic_renders(sample_scope):
    report = Report(
        scope=sample_scope,
        capture=Capture(path="empty.pcap"),
        generated_at=datetime(2026, 4, 13, 6, 0, tzinfo=UTC),
    )
    text = render(report)

    assert "No device was observed." in text
    assert "No finding was raised" in text


def test_ebios_export_leaves_the_analysis_to_the_analyst(sample_capture, sample_scope):
    export = to_ebios(build_report(sample_capture, sample_scope))

    assert export["atelier"] == 4
    assert export["reference"] == "BC-2026-014"
    for mode in export["modes_operatoires"]:
        assert mode["gravite"] is None
        assert mode["vraisemblance"] is None


def test_check_scope_command(capsys):
    assert main(["check-scope", SCOPE]) == 0
    assert "scope valid" in capsys.readouterr().out


def test_check_scope_rejects_a_bad_file(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("engagement: only\n", encoding="utf-8")

    assert main(["check-scope", str(bad)]) == 2
    assert "authorized_by" in capsys.readouterr().err


def test_analyse_writes_every_requested_artefact(sample_capture, tmp_path):
    report_path = tmp_path / "report.md"
    json_path = tmp_path / "inventory.json"
    ebios_path = tmp_path / "ebios.json"

    code = main(
        [
            "analyse",
            str(sample_capture),
            "--scope",
            SCOPE,
            "--report",
            str(report_path),
            "--json",
            str(json_path),
            "--ebios",
            str(ebios_path),
        ]
    )

    assert code == 0
    assert "OT-001" in report_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["devices"]
    assert json.loads(ebios_path.read_text(encoding="utf-8"))["modes_operatoires"]


def test_analyse_prints_to_stdout_without_report_option(sample_capture, capsys):
    assert main(["analyse", str(sample_capture), "--scope", SCOPE]) == 0
    assert "Passive audit of industrial traffic" in capsys.readouterr().out


def test_fail_on_threshold(sample_capture, tmp_path):
    arguments = [
        "analyse",
        str(sample_capture),
        "--scope",
        SCOPE,
        "--report",
        str(tmp_path / "r.md"),
    ]

    assert main([*arguments, "--fail-on", "high"]) == 3
    assert main([*arguments]) == 0


def test_missing_capture_is_reported(capsys):
    assert main(["analyse", "does-not-exist.pcap", "--scope", SCOPE]) == 2
    assert "no such file" in capsys.readouterr().err


def test_command_is_required():
    with pytest.raises(SystemExit):
        main([])
