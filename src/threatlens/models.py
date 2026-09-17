"""Typed data model for findings and triage output.

Everything the LLM returns is parsed back through these Pydantic models, so
model output is validated data — never trusted structure — before use.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEV_ORDER[self.value]

    @classmethod
    def coerce(cls, value: object, default: "Severity") -> "Severity":
        try:
            return cls(str(value).upper())
        except (ValueError, AttributeError):
            return default


class Finding(BaseModel):
    """A single normalized finding from any scanner."""

    id: str
    rule_id: str
    message: str = ""
    severity: Severity = Severity.LOW
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    file_path: str = "unknown"
    start_line: int = 0
    end_line: int = 0
    code_snippet: Optional[str] = None
    source_tool: str = "semgrep"
    fingerprint: str = ""


class TriagedFinding(BaseModel):
    """A finding enriched with triage judgement (heuristic or LLM)."""

    finding: Finding
    vulnerability_class: str = "Other"
    adjusted_severity: Severity = Severity.LOW
    is_likely_false_positive: bool = False
    confidence: float = 0.5
    exploitability: str = ""
    remediation: str = ""
    rationale: str = ""
    triaged_by: str = "heuristic"  # "heuristic" | "llm"

    @property
    def sort_key(self) -> tuple[int, int, float]:
        # actionable first, then by severity, then by confidence
        return (
            0 if self.is_likely_false_positive else 1,
            self.adjusted_severity.rank,
            self.confidence,
        )


class TriageStats(BaseModel):
    raw_count: int = 0
    deduped_count: int = 0
    actionable_count: int = 0
    false_positive_count: int = 0
    class_counts: dict[str, int] = Field(default_factory=dict)


class TriageResult(BaseModel):
    findings: list[TriagedFinding] = Field(default_factory=list)
    stats: TriageStats = Field(default_factory=TriageStats)
