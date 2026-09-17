"""Triage core: de-duplicate, cluster into vulnerability classes, prioritize.

The engine is deterministic and offline by default. If `use_llm=True` and the
optional `anthropic` dependency + API key are present, LLM judgement is layered
on top (severity adjustment, false-positive calls, tailored remediation). The
heuristic result is always the fallback, so ThreatLens never *requires* the LLM.
"""

from __future__ import annotations

import re

from ..models import Finding, Severity, TriagedFinding, TriageResult, TriageStats

# --- vulnerability-class mapping ------------------------------------------------
# Map CWE ids to human-readable classes. Clustering by class (not by individual
# finding) is what lets a team eliminate a whole category at once.
_CWE_CLASS = {
    "89": "SQL Injection",
    "79": "Cross-Site Scripting (XSS)",
    "798": "Hardcoded Credentials",
    "259": "Hardcoded Credentials",
    "321": "Hardcoded Credentials",
    "327": "Weak Cryptography",
    "326": "Weak Cryptography",
    "916": "Weak Cryptography",
    "22": "Path Traversal",
    "78": "OS Command Injection",
    "77": "OS Command Injection",
    "502": "Insecure Deserialization",
    "918": "Server-Side Request Forgery (SSRF)",
    "611": "XML External Entity (XXE)",
    "94": "Code Injection",
    "312": "Sensitive Data Exposure",
    "306": "Missing Authentication",
    "352": "Cross-Site Request Forgery (CSRF)",
}

# Keyword fallback when no CWE is present.
_KEYWORD_CLASS = [
    (re.compile(r"\bsql\b|sqli|injection.*query", re.I), "SQL Injection"),
    (re.compile(r"\bxss\b|cross[- ]site scripting", re.I), "Cross-Site Scripting (XSS)"),
    (re.compile(r"hardcoded|secret|api[_-]?key|password", re.I), "Hardcoded Credentials"),
    (re.compile(r"\bmd5\b|\bsha1\b|weak (hash|cipher|crypto)|\bdes\b|\brc4\b", re.I), "Weak Cryptography"),
    (re.compile(r"path traversal|\.\./", re.I), "Path Traversal"),
    (re.compile(r"command injection|os\.system|subprocess.*shell", re.I), "OS Command Injection"),
    (re.compile(r"deserializ|pickle|yaml\.load", re.I), "Insecure Deserialization"),
    (re.compile(r"\bssrf\b|request forgery", re.I), "Server-Side Request Forgery (SSRF)"),
]

# Short, class-level remediation guidance for the offline path.
_CLASS_REMEDIATION = {
    "SQL Injection": "Use parameterized queries / prepared statements; never build SQL by string concatenation.",
    "Cross-Site Scripting (XSS)": "Contextually output-encode untrusted data and use an auto-escaping template engine; add a strict CSP.",
    "Hardcoded Credentials": "Remove the secret from source, rotate it, and load from a secrets manager / environment at runtime.",
    "Weak Cryptography": "Replace with a vetted algorithm (SHA-256+/AES-GCM) via a maintained crypto library; drop MD5/SHA1/DES/RC4.",
    "Path Traversal": "Canonicalize and validate paths against an allow-list base directory; reject '..' segments.",
    "OS Command Injection": "Avoid the shell; pass arguments as a list to the exec API and validate against an allow-list.",
    "Insecure Deserialization": "Do not deserialize untrusted data; use safe loaders (yaml.safe_load) or signed, schema-validated formats.",
    "Server-Side Request Forgery (SSRF)": "Validate outbound URLs against an allow-list; block internal ranges and cloud metadata endpoints.",
    "Other": "Review the finding against the relevant secure-coding standard and apply the least-privilege fix.",
}

# Findings under these paths are more likely to be false positives / lower risk.
_LIKELY_FP_PATH = re.compile(r"(^|/)(tests?|test|__tests__|fixtures?|examples?|mocks?)(/|$)", re.I)


def classify(finding: Finding) -> str:
    for cwe in finding.cwe:
        digits = re.sub(r"\D", "", cwe)
        if digits in _CWE_CLASS:
            return _CWE_CLASS[digits]
    haystack = f"{finding.rule_id} {finding.message} {finding.code_snippet or ''}"
    for pattern, label in _KEYWORD_CLASS:
        if pattern.search(haystack):
            return label
    return "Other"


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a fingerprint (same rule + path + snippet)."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint or f.id, f)
    return list(seen.values())


def _heuristic_triage(finding: Finding) -> TriagedFinding:
    vuln_class = classify(finding)
    in_test = bool(_LIKELY_FP_PATH.search(finding.file_path))
    adjusted = finding.severity
    if in_test and adjusted.rank > Severity.LOW.rank:
        adjusted = Severity.LOW
    return TriagedFinding(
        finding=finding,
        vulnerability_class=vuln_class,
        adjusted_severity=adjusted,
        is_likely_false_positive=in_test,
        confidence=0.55 if in_test else 0.6,
        exploitability="Non-production path; verify before prioritizing." if in_test else "",
        remediation=_CLASS_REMEDIATION.get(vuln_class, _CLASS_REMEDIATION["Other"]),
        rationale=(
            "Located under a test/example path — likely lower real-world risk."
            if in_test
            else "Heuristic classification by CWE/rule; confirm with a reviewer."
        ),
        triaged_by="heuristic",
    )


def _build_stats(findings: list[Finding], triaged: list[TriagedFinding]) -> TriageStats:
    class_counts: dict[str, int] = {}
    fp = 0
    for t in triaged:
        class_counts[t.vulnerability_class] = class_counts.get(t.vulnerability_class, 0) + 1
        if t.is_likely_false_positive:
            fp += 1
    return TriageStats(
        raw_count=len(findings),
        deduped_count=len(triaged),
        actionable_count=len(triaged) - fp,
        false_positive_count=fp,
        class_counts=dict(sorted(class_counts.items(), key=lambda kv: -kv[1])),
    )


def triage(findings: list[Finding], *, use_llm: bool = False) -> TriageResult:
    unique = dedupe(findings)
    triaged = [_heuristic_triage(f) for f in unique]

    if use_llm:
        try:
            from .llm import enrich_with_llm  # local import keeps anthropic optional

            triaged = enrich_with_llm(triaged)
        except Exception as exc:  # noqa: BLE001 - fall back, never fail the run
            print(f"[threatlens] LLM triage unavailable, using heuristics: {exc}")

    triaged.sort(key=lambda t: t.sort_key, reverse=True)
    return TriageResult(findings=triaged, stats=_build_stats(findings, triaged))
