"""Findings ingestion — format-agnostic entry point.

`load_findings` auto-detects Semgrep-native JSON vs SARIF and dispatches to the
right parser, so the rest of ThreatLens only ever sees normalized `Finding`s.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from ..models import Finding
from .sarif import load_sarif_file, parse_sarif
from .semgrep import load_semgrep_file, parse_semgrep


def detect_format(data: dict) -> str:
    """Return 'sarif' or 'semgrep' based on document shape."""
    if isinstance(data, dict) and "runs" in data:
        return "sarif"
    return "semgrep"


def load_findings(path: Union[str, Path], fmt: str = "auto") -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if fmt == "auto":
        fmt = detect_format(data)
    if fmt == "sarif":
        return parse_sarif(data)
    return parse_semgrep(data)


__all__ = [
    "load_findings",
    "detect_format",
    "load_semgrep_file",
    "parse_semgrep",
    "load_sarif_file",
    "parse_sarif",
]
