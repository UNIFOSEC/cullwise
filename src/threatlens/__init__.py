"""ThreatLens — AI-assisted AppSec triage for CI/CD.

Phase 1: ingest scanner findings (Semgrep), de-duplicate, cluster into
vulnerability *classes*, and produce a prioritized, remediation-first report.
LLM triage is optional and layered on top of a deterministic heuristic core.
"""

__version__ = "0.1.0"
