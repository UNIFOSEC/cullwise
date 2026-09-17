# 🛡️ ThreatLens

**AI-assisted application-security triage for CI/CD.** ThreatLens turns raw
scanner noise into a prioritized, remediation-first report — de-duplicating
findings and clustering them into **vulnerability classes** so teams fix
categories, not one-off bugs.

> Phase 1 (this repo): Semgrep ingestion → heuristic + optional LLM triage →
> Markdown report. Threat-modeling and PR-diff review land in later phases
> (see [Roadmap](#roadmap)).

**🔴 Live dashboard:** https://unifosec.github.io/threatlens/ — rebuilt on every
push by [`.github/workflows/pages.yml`](.github/workflows/pages.yml).

---

## Live dashboard (GitHub Pages)

On every push to `main`, CI runs Semgrep against a demo target, triages the
findings with ThreatLens, and publishes the HTML report to GitHub Pages — an
always-current security dashboard at a public URL.

**One-time setup** (after the repo is on GitHub):

1. Push this repo to `github.com/UNIFOSEC/threatlens`.
2. In the repo: **Settings → Pages → Build and deployment → Source = GitHub Actions**.
3. Push any commit (or run the **Deploy dashboard** workflow manually from the
   Actions tab). The dashboard appears at `https://unifosec.github.io/threatlens/`.

Build it locally the same way CI does:

```bash
threatlens triage examples/semgrep-sample.json --out site/index.html
# then open site/index.html
```

---

## Why

Security teams drown in scanner output: hundreds of findings, heavy duplication,
and a long tail of false positives. The manual triage that follows is the real
cost — and it's the work least suited to a human. ThreatLens automates the
first pass:

- **De-duplicates** findings that share a rule + location + snippet.
- **Clusters into vulnerability classes** (SQL Injection, Hardcoded Credentials,
  Weak Crypto, XSS, …) — the unit you actually remediate.
- **Prioritizes**, down-weighting likely false positives (e.g. matches in test
  fixtures) so real risk floats to the top.
- **Optionally uses Claude** to adjust severity, judge exploitability, flag false
  positives, and write tailored remediation — layered *on top of* a
  deterministic core that never requires the LLM.

## Quick start

```bash
pip install -e ".[dev]"

# Offline, deterministic triage (no API key needed):
threatlens triage examples/semgrep-sample.json --out report.md

# LLM-assisted triage (needs ANTHROPIC_API_KEY):
export ANTHROPIC_API_KEY=sk-...
threatlens triage examples/semgrep-sample.json --llm --out report.md
```

Generate your own input with Semgrep:

```bash
semgrep --config=auto --json -o findings.json .
threatlens triage findings.json --out report.md --fail-on-findings
```

`--fail-on-findings` exits non-zero when actionable findings remain, so it can
**gate a CI pipeline**.

## Example output

```
12 raw findings → 8 unique → 6 actionable (2 likely false-positive / low-risk).

Vulnerability classes
| Class                    | Count |
| ------------------------ | ----: |
| SQL Injection            |     3 |
| Hardcoded Credentials    |     2 |
| Weak Cryptography        |     1 |
```

## How it works

```
Semgrep JSON ──▶ ingest ──▶ Finding[]
                              │
                     dedupe + classify (deterministic)
                              │
                    ┌─────────┴──────────┐
                    │  optional: Claude  │  ← severity, FP calls, remediation
                    └─────────┬──────────┘
                              ▼
                    TriageResult ──▶ Markdown report
```

- `ingest/` — thin, typed scanner adapters (Semgrep today; Trivy/Grype next).
- `triage/engine.py` — dedupe, CWE/keyword class clustering, prioritization.
- `triage/llm.py` + `prompts.py` — optional Claude enrichment.
- `report/markdown.py` — PR-ready report.
- `models.py` — the shared, validated `Finding` / `TriagedFinding` schema.

## Securing the tool itself

ThreatLens feeds **untrusted, attacker-influenceable content** (code snippets and
messages from the scanned repo) into an LLM, so it is itself a target for
**prompt injection**. The defenses are described in
[`SECURITY.md`](SECURITY.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md), and in
short:

1. All scanner-derived text is wrapped in explicit **untrusted-data delimiters**,
   with break-out attempts neutralized (`security.py`).
2. The system prompt treats delimited content as **data, never instructions**.
3. LLM output is **validated back through Pydantic** and used only to produce a
   report — ThreatLens takes **no autonomous action** on model output.
4. The CI token is **least-privilege**; the tool needs no write scope.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

CI runs the suite on Python 3.10–3.12 and **dogfoods** ThreatLens against its own
sample findings on every push.

## Roadmap

- **Phase 1 — AI vuln-triage** ✅ (this repo)
- **Phase 2 — AI secure code review** on PR diffs (OWASP-class patterns, cited).
- **Phase 3 — AI threat modeling** (STRIDE table from an architecture description).
- **Phase 4 — GitHub Action** posting one consolidated PR comment.

## License

MIT © 2026 Jose Ernest — see [LICENSE](LICENSE).
