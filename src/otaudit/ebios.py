"""Export of findings as a starting point for EBIOS RM workshop 4.

This is a scaffold, not a risk analysis. Each finding becomes one operational
mode with the assets it touches; severity, likelihood and the link to a feared
event stay empty because they depend on the process, which a capture cannot
tell you. The point is to avoid retyping the inventory into a spreadsheet.
"""

from __future__ import annotations

from typing import Any

from .models import Report


def to_ebios(report: Report) -> dict[str, Any]:
    return {
        "etude": report.scope.engagement,
        "reference": report.scope.reference,
        "atelier": 4,
        "source": "otaudit passive capture analysis",
        "modes_operatoires": [
            {
                "identifiant": finding.identifier,
                "libelle": finding.title,
                "biens_supports": finding.assets,
                "constats": finding.evidence,
                "referentiels": {
                    "iec_62443_4_2": finding.iec_62443,
                    "anssi": finding.anssi,
                },
                "gravite": None,
                "vraisemblance": None,
                "evenement_redoute": None,
                "mesures_existantes": [],
            }
            for finding in report.findings
        ],
    }
