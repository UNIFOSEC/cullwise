"""Parse SARIF 2.1.0 into normalized Finding objects.

SARIF (OASIS standard) is what CodeQL, Trivy, Bandit, Checkov, and Semgrep all
speak. Ingesting SARIF makes ThreatLens scanner-agnostic — one adapter covers
the whole ecosystem instead of a per-tool parser.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Union

from ..models import Finding, Severity

# SARIF result.level -> our scale (fallback when no security-severity present).
_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.I)


def _sev_from_security_severity(value: object) -> Severity | None:
    """GitHub-style numeric 'security-severity' (0-10) -> Severity."""
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _cwes_from(*sources: object) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for src in sources:
        if not src:
            continue
        items = src if isinstance(src, list) else [src]
        for item in items:
            match = _CWE_RE.search(str(item))
            if match:
                cwe = f"CWE-{int(match.group(1))}"  # int() strips leading zeros (cwe-089 -> CWE-89)
                if cwe not in seen:
                    seen.add(cwe)
                    out.append(cwe)
    return out


def _fingerprint(rule_id: str, path: str, snippet: str | None, start: int) -> str:
    h = hashlib.sha1()
    for part in (rule_id, path, str(start), (snippet or "").strip()):
        h.update(part.encode("utf-8", "ignore"))
        h.update(b"|")
    return h.hexdigest()[:16]


def _index_rules(container: dict) -> tuple[dict, list]:
    by_id: dict = {}
    by_index: list = []
    for rule in container.get("rules", []) or []:
        by_index.append(rule)
        if rule.get("id"):
            by_id[rule["id"]] = rule
    return by_id, by_index


def parse_sarif(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []) or []:
        tool = run.get("tool", {}) or {}
        driver = tool.get("driver", {}) or {}
        tool_name = driver.get("name", "sarif")
        rules_by_id, rules_by_index = _index_rules(driver)
        for ext in tool.get("extensions", []) or []:
            ext_by_id, _ = _index_rules(ext)
            rules_by_id.update(ext_by_id)

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId")
            rule = rules_by_id.get(rule_id)
            if rule is None:
                idx = res.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(rules_by_index):
                    rule = rules_by_index[idx]
                    rule_id = rule_id or rule.get("id")
            rule = rule or {}
            rule_props = rule.get("properties", {}) or {}
            res_props = res.get("properties", {}) or {}

            severity = _sev_from_security_severity(
                rule_props.get("security-severity") or res_props.get("security-severity")
            )
            if severity is None:
                level = (
                    res.get("level")
                    or (rule.get("defaultConfiguration", {}) or {}).get("level")
                    or "warning"
                )
                severity = _LEVEL_MAP.get(str(level).lower(), Severity.MEDIUM)

            path, start, end, snippet = "unknown", 0, 0, None
            locations = res.get("locations", []) or []
            if locations:
                phys = locations[0].get("physicalLocation", {}) or {}
                path = (phys.get("artifactLocation", {}) or {}).get("uri", "unknown")
                region = phys.get("region", {}) or {}
                start = int(region.get("startLine", 0) or 0)
                end = int(region.get("endLine", start) or start)
                snippet = (region.get("snippet", {}) or {}).get("text")

            cwe = _cwes_from(
                rule_props.get("cwe"), rule_props.get("tags"), res_props.get("cwe")
            )
            message = ((res.get("message", {}) or {}).get("text") or "").strip()
            rule_id = rule_id or "unknown"

            # Prefer a scanner-provided fingerprint; otherwise derive one.
            fingerprint = None
            partial = res.get("partialFingerprints") or res.get("fingerprints")
            if isinstance(partial, dict) and partial:
                fingerprint = str(sorted(partial.items())[0][1])[:32]
            if not fingerprint:
                fingerprint = _fingerprint(rule_id, path, snippet, start)

            findings.append(
                Finding(
                    id=fingerprint,
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    cwe=cwe,
                    owasp=[],
                    file_path=path,
                    start_line=start,
                    end_line=end,
                    code_snippet=snippet,
                    source_tool=tool_name,
                    fingerprint=fingerprint,
                )
            )
    return findings


def load_sarif_file(path: Union[str, Path]) -> list[Finding]:
    return parse_sarif(json.loads(Path(path).read_text(encoding="utf-8")))
