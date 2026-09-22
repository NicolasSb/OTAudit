from ipaddress import IPv4Address

import pytest

from otaudit.scope import ScopeError, load_scope

VALID = """
engagement: "Audit"
authorized_by: "J. Martin"
reference: "BC-2026-014"
window:
  start: "2023-11-14T20:00:00+00:00"
  end: "2023-11-15T02:00:00+00:00"
targets:
  - 10.42.7.0/26
exclusions:
  - 10.42.7.13/32
"""


def write(tmp_path, text, name="scope.yaml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_a_valid_scope(tmp_path):
    scope = load_scope(write(tmp_path, VALID))

    assert scope.reference == "BC-2026-014"
    assert scope.covers(IPv4Address("10.42.7.20"))
    assert not scope.covers(IPv4Address("10.42.9.80"))


def test_exclusions_override_targets(tmp_path):
    scope = load_scope(write(tmp_path, VALID))

    assert not scope.covers(IPv4Address("10.42.7.13"))
    assert scope.excluded(IPv4Address("10.42.7.13"))
    assert not scope.excluded(IPv4Address("10.42.7.20"))


def test_missing_file(tmp_path):
    with pytest.raises(ScopeError, match="no such file"):
        load_scope(tmp_path / "absent.yaml")


def test_invalid_yaml(tmp_path):
    with pytest.raises(ScopeError, match="invalid YAML"):
        load_scope(write(tmp_path, "engagement: [unclosed"))


def test_top_level_must_be_a_mapping(tmp_path):
    with pytest.raises(ScopeError, match="mapping"):
        load_scope(write(tmp_path, "- one\n- two\n"))


def test_missing_authorisation_is_refused(tmp_path):
    text = VALID.replace('authorized_by: "J. Martin"\n', "")
    with pytest.raises(ScopeError, match="authorized_by"):
        load_scope(write(tmp_path, text))


def test_empty_target_list_is_refused(tmp_path):
    text = VALID.replace("  - 10.42.7.0/26\n", "")
    with pytest.raises(ScopeError, match="targets"):
        load_scope(write(tmp_path, text))


def test_reversed_window_is_refused(tmp_path):
    text = VALID.replace("2023-11-15T02:00:00+00:00", "2023-11-14T18:00:00+00:00")
    with pytest.raises(ScopeError, match=r"window\.end must be after"):
        load_scope(write(tmp_path, text))


def test_window_containment(tmp_path):
    from datetime import UTC, datetime

    scope = load_scope(write(tmp_path, VALID))

    assert scope.window.contains(datetime(2023, 11, 14, 23, 0, tzinfo=UTC))
    assert not scope.window.contains(datetime(2023, 11, 15, 3, 0, tzinfo=UTC))
