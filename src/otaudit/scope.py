"""Loading of the engagement scope file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .models import Scope


class ScopeError(Exception):
    """Raised when the scope file is missing, unreadable or invalid."""


def load_scope(path: Path) -> Scope:
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ScopeError(f"{path}: no such file") from error
    except yaml.YAMLError as error:
        raise ScopeError(f"{path}: invalid YAML ({error})") from error
    if not isinstance(raw, dict):
        raise ScopeError(f"{path}: expected a mapping at the top level")
    try:
        return Scope.model_validate(raw)
    except ValidationError as error:
        raise ScopeError(f"{path}: {_summarise(error)}") from error


def _summarise(error: ValidationError) -> str:
    lines = []
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        lines.append(f"{location}: {item['msg']}")
    return "; ".join(lines)
