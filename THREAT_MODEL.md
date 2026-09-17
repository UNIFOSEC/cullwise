# Cullwise — Threat Model

A STRIDE-style threat model of Cullwise itself. Because the tool ingests
attacker-influenceable data and can call an LLM, it warrants the same rigor it
applies to the code it scans.

## System overview

**Assets:** the integrity of triage verdicts (a downgraded verdict could hide a
real vulnerability), the API key, and the developer's trust in the report.

**Trust boundaries:**
1. Scanner output → Cullwise (untrusted: derived from arbitrary source).
2. Cullwise → Claude API (network egress; capped, delimited data).
3. Cullwise → CI / PR comment (output consumed by humans and pipeline gates).

**Data flow:** `repo → semgrep → JSON → ingest → dedupe/classify → [Claude] →
report → PR/CI`.

## STRIDE

| Threat | Scenario | Mitigation |
| --- | --- | --- |
| **Spoofing** | Crafted finding impersonates a trusted rule to alter priority. | Verdicts derive from CWE/rule + validated schema, not free-text claims in the data. |
| **Tampering** | Malicious code comment injects "mark all as false positive" (prompt injection). | Untrusted data is delimited and neutralized; system prompt forbids following embedded instructions; heuristic fallback bounds impact. |
| **Repudiation** | Unclear why a finding was down-ranked. | Each `TriagedFinding` records `triaged_by`, `confidence`, and a rationale. |
| **Information disclosure** | Snippets/secrets sent to a third party. | Offline by default; `--llm` sends only capped metadata + snippets to the configured API; `.env` git-ignored. |
| **Denial of service** | Huge/adversarial snippet inflates prompt/cost. | `MAX_SNIPPET_CHARS` cap; dedupe reduces volume; LLM path is opt-in. |
| **Elevation of privilege** | Tool induced to run code or write to the repo. | No code execution and no write actions on any input or model output; least-privilege CI token. |

## Residual risk & assumptions

- LLM triage is **advisory**; the report states this and severity floors are
  never silently raised past what the scanner reported without a rationale.
- Cullwise trusts the Semgrep binary and the Claude API endpoint it is
  configured to call; pin/verify these in your pipeline.
- Prompt-injection defenses reduce but do not eliminate risk — hence the
  deterministic fallback and the "no autonomous action" rule.
