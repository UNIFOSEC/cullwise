"""Parse Semgrep JSON output into normalized Finding objects.

Semgrep is invoked out-of-band (`semgrep --json`); Cullwise reasons over its
output rather than re-implementing scanning. Keeping ingest a thin, typed
adapter is what lets us add Trivy/Grype later behind the same Finding model.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Union

from ..models import Finding, Severity

# Semgrep severities map onto our shared scale.
_SEV_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _fingerprint(rule_id: str, path: str, snippet: str | None) -> str:
    h = hashlib.sha1()
    h.update(rule_id.encode("utf-8", "ignore"))
    h.update(b"|")
    h.update(path.encode("utf-8", "ignore"))
    h.update(b"|")
    h.update((snippet or "").strip().encode("utf-8", "ignore"))
    return h.hexdigest()[:16]


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def parse_semgrep(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []) or []:
        rule_id = str(result.get("check_id", "unknown"))
        path = str(result.get("path", "unknown"))
        extra = result.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        snippet = extra.get("lines")

        severity = _SEV_MAP.get(str(extra.get("severity", "")).upper(), Severity.LOW)
        fingerprint = _fingerprint(rule_id, path, snippet)

        findings.append(
            Finding(
                id=fingerprint,
                rule_id=rule_id,
                message=str(extra.get("message", "")).strip(),
                severity=severity,
                cwe=_as_list(meta.get("cwe")),
                owasp=_as_list(meta.get("owasp")),
                file_path=path,
                start_line=int((result.get("start", {}) or {}).get("line", 0) or 0),
                end_line=int((result.get("end", {}) or {}).get("line", 0) or 0),
                code_snippet=snippet,
                source_tool="semgrep",
                fingerprint=fingerprint,
            )
        )
    return findings


def load_semgrep_file(path: Union[str, Path]) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_semgrep(data)
