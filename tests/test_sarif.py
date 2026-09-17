from pathlib import Path

from threatlens.ingest import detect_format, load_findings, parse_sarif
from threatlens.models import Severity
from threatlens.report import build_sarif
from threatlens.triage import triage

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
SARIF = EXAMPLES / "sarif-sample.sarif"
SEMGREP = EXAMPLES / "semgrep-sample.json"


# --- ingest -------------------------------------------------------------------
def test_detect_format_auto():
    findings_sarif = load_findings(SARIF)  # auto
    findings_semgrep = load_findings(SEMGREP)  # auto
    assert len(findings_sarif) == 2
    assert len(findings_semgrep) == 6
    assert findings_sarif[0].source_tool == "CodeQL"


def test_sarif_security_severity_mapping():
    findings = load_findings(SARIF)
    sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
    weak = [f for f in findings if "weak" in f.rule_id][0]
    assert sqli.severity is Severity.HIGH  # security-severity 8.8
    assert weak.severity is Severity.MEDIUM  # security-severity 5.0


def test_sarif_cwe_extracted_and_normalized():
    findings = load_findings(SARIF)
    sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
    # cwe-089 in the tag must normalize to CWE-89 (leading zero stripped)
    assert "CWE-89" in sqli.cwe


def test_sarif_prefers_scanner_fingerprint():
    findings = load_findings(SARIF)
    sqli = [f for f in findings if f.rule_id == "py/sql-injection"][0]
    assert sqli.fingerprint == "a1b2c3d4e5"


def test_sarif_findings_classify_correctly():
    result = triage(load_findings(SARIF), use_llm=False)
    classes = {t.vulnerability_class for t in result.findings}
    assert "SQL Injection" in classes
    assert "Weak Cryptography" in classes


# --- output -------------------------------------------------------------------
def test_build_sarif_shape():
    result = triage(load_findings(SEMGREP), use_llm=False)
    doc = build_sarif(result)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ThreatLens"
    assert len(run["results"]) == len(result.findings)
    # every result carries a security-severity on its rule
    for rule in run["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_build_sarif_suppresses_false_positives():
    result = triage(load_findings(SEMGREP), use_llm=False)
    doc = build_sarif(result)
    suppressed = [r for r in doc["runs"][0]["results"] if r.get("suppressions")]
    assert len(suppressed) >= 1  # the test-fixture SQL finding


def test_sarif_roundtrip():
    # ThreatLens output SARIF can be re-ingested by ThreatLens.
    result = triage(load_findings(SEMGREP), use_llm=False)
    doc = build_sarif(result)
    reparsed = parse_sarif(doc)
    assert len(reparsed) == len(result.findings)
    assert detect_format(doc) == "sarif"
