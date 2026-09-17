"""Emit triage results as SARIF 2.1.0.

This lets ThreatLens output be uploaded to GitHub Code Scanning (via
github/codeql-action/upload-sarif), so triaged, de-noised findings appear in the
repo's Security tab. Likely false-positives are emitted as SARIF *suppressions*,
so they show up dismissed rather than as noise.
"""

from __future__ import annotations

import json

from .. import __version__
from ..models import Severity, TriageResult

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}
# GitHub reads this string to render its own severity chip.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def build_sarif(result: TriageResult) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for t in result.findings:
        f = t.finding
        rid = f.rule_id or "unknown"

        if rid not in rules:
            tags = ["security", f"threatlens/class/{t.vulnerability_class}"] + list(f.cwe)
            rules[rid] = {
                "id": rid,
                "name": t.vulnerability_class.replace(" ", ""),
                "shortDescription": {"text": t.vulnerability_class},
                "fullDescription": {"text": t.remediation or t.vulnerability_class},
                "helpUri": "https://github.com/UNIFOSEC/threatlens",
                "properties": {
                    "tags": tags,
                    "security-severity": _SECURITY_SEVERITY[t.adjusted_severity],
                },
            }

        result_obj = {
            "ruleId": rid,
            "level": _LEVEL[t.adjusted_severity],
            "message": {"text": f"{t.vulnerability_class}: {t.remediation}".strip(": ").strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {
                            "startLine": max(f.start_line, 1),
                            "endLine": max(f.end_line or f.start_line, 1),
                        },
                    }
                }
            ],
            "partialFingerprints": {"threatlensFingerprint": f.fingerprint or f.id},
            "properties": {
                "vulnerabilityClass": t.vulnerability_class,
                "confidence": round(t.confidence, 3),
                "triagedBy": t.triaged_by,
                "reportedSeverity": f.severity.value,
                "adjustedSeverity": t.adjusted_severity.value,
            },
        }
        if t.is_likely_false_positive:
            result_obj["suppressions"] = [
                {
                    "kind": "external",
                    "justification": t.rationale or "Likely false-positive (ThreatLens triage).",
                }
            ]
        results.append(result_obj)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatLens",
                        "informationUri": "https://github.com/UNIFOSEC/threatlens",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(result: TriageResult) -> str:
    return json.dumps(build_sarif(result), indent=2)
