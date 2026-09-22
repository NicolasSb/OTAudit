"""Rendering of the audit report.

The template ships as a file inside the package so it can be replaced without
touching the code: report wording belongs to whoever signs the report.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from .models import Report

TEMPLATE_DIRECTORY = Path(__file__).parent / "templates"
DEFAULT_TEMPLATE = "report.md.j2"


def render(report: Report, template_name: str = DEFAULT_TEMPLATE) -> str:
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIRECTORY),
        autoescape=select_autoescape(enabled_extensions=("html",), default=False),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    environment.filters["duration"] = _duration
    return environment.get_template(template_name).render(report=report)


def _duration(report: Report) -> str:
    capture = report.capture
    if capture.started_at is None or capture.ended_at is None:
        return "unknown"
    seconds = int((capture.ended_at - capture.started_at).total_seconds())
    minutes, remainder = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    if minutes:
        return f"{minutes} min {remainder:02d} s"
    return f"{remainder} s"
