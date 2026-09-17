from pathlib import Path

from cullwise.ingest import load_semgrep_file
from cullwise.models import Finding, Severity
from cullwise.triage import classify, dedupe, triage

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "semgrep-sample.json"


def _finding(rule_id="r", cwe=None, path="app/x.py", snippet="code", sev=Severity.HIGH):
    return Finding(
        id="1", rule_id=rule_id, message="", severity=sev,
        cwe=cwe or [], file_path=path, code_snippet=snippet, fingerprint=rule_id + path + snippet,
    )


def test_classify_by_cwe():
    assert classify(_finding(cwe=["CWE-89"])) == "SQL Injection"
    assert classify(_finding(cwe=["CWE-798"])) == "Hardcoded Credentials"
    assert classify(_finding(cwe=["CWE-327"])) == "Weak Cryptography"


def test_classify_keyword_fallback():
    f = _finding(rule_id="detect-md5-usage", cwe=[], snippet="hashlib.md5(x)")
    assert classify(f) == "Weak Cryptography"


def test_dedupe_collapses_identical():
    findings = load_semgrep_file(SAMPLE)
    assert len(dedupe(findings)) == 5  # 6 raw, one duplicate removed


def test_triage_end_to_end_offline():
    findings = load_semgrep_file(SAMPLE)
    result = triage(findings, use_llm=False)
    assert result.stats.raw_count == 6
    assert result.stats.deduped_count == 5
    # The test-fixture SQL finding should be flagged as likely false-positive.
    assert result.stats.false_positive_count >= 1
    assert result.stats.actionable_count == result.stats.deduped_count - result.stats.false_positive_count


def test_actionable_findings_sort_before_false_positives():
    findings = load_semgrep_file(SAMPLE)
    result = triage(findings, use_llm=False)
    fp_flags = [t.is_likely_false_positive for t in result.findings]
    # once we hit the first false-positive, no actionable finding follows
    if True in fp_flags:
        first_fp = fp_flags.index(True)
        assert all(fp_flags[first_fp:])
