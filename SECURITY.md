# Security Policy

## Reporting a vulnerability

Please report security issues privately to **unifosec@gmail.com** rather than
opening a public issue. You'll get an acknowledgement within 72 hours.

## Security posture of Cullwise

Cullwise processes untrusted input (scanner output derived from arbitrary
source repositories) and optionally sends it to an LLM. Its own security is a
first-class design concern — see [`THREAT_MODEL.md`](THREAT_MODEL.md) for the
full analysis. Key controls:

- **Prompt-injection containment.** Scanner-derived text (code snippets,
  messages) is treated as untrusted data: delimited, break-out-neutralized, and
  size-capped (`src/cullwise/security.py`), and the system prompt instructs the
  model to never follow instructions found in that data.
- **Output is data, not authority.** Every LLM response is parsed and validated
  through Pydantic models. Malformed output is discarded; the deterministic
  heuristic result is the fallback.
- **No autonomous action.** Cullwise only ever emits a report. It does not
  modify code, merge, comment, or call external systems based on model output.
- **Least privilege.** No secrets are required for the core path. LLM triage
  reads a single API key from the environment; the recommended CI token is
  read-only.
- **No data exfiltration by default.** Without `--llm`, nothing leaves the
  machine. With `--llm`, only the finding metadata and capped snippets are sent
  to the configured Claude API.

## Supported versions

Phase 1 is pre-1.0; security fixes are applied to `main`.
