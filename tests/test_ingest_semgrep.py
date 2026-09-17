from pathlib import Path

from cullwise.ingest import load_semgrep_file, parse_semgrep
from cullwise.models import Severity

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "semgrep-sample.json"


def test_loads_sample_findings():
    findings = load_semgrep_file(SAMPLE)
    assert len(findings) == 6  # includes one duplicate on purpose


def test_severity_mapping():
    findings = load_semgrep_file(SAMPLE)
    by_rule = [f for f in findings if "insecure-hash" in f.rule_id]
    assert by_rule and by_rule[0].severity is Severity.MEDIUM  # WARNING -> MEDIUM


def test_cwe_extracted():
    findings = load_semgrep_file(SAMPLE)
    sql = [f for f in findings if "formatted-sql-query" in f.rule_id][0]
    assert any("89" in c for c in sql.cwe)


def test_duplicates_share_fingerprint():
    findings = load_semgrep_file(SAMPLE)
    fps = [f.fingerprint for f in findings if f.file_path == "app/db.py"]
    assert len(fps) == 2 and fps[0] == fps[1]


def test_empty_results():
    assert parse_semgrep({"results": []}) == []
