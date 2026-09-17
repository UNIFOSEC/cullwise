"""Optional LLM enrichment via the Anthropic Claude API.

Isolated so the rest of Cullwise never imports `anthropic` unless LLM triage
is explicitly requested. Model output is parsed defensively and merged onto the
heuristic result; anything malformed is ignored rather than trusted.
"""

from __future__ import annotations

import json
import os
import re

from ..models import Severity, TriagedFinding
from .prompts import SYSTEM_PROMPT, build_user_prompt

# Current Claude model id (see project notes on model ids).
DEFAULT_MODEL = os.environ.get("CULLWISE_MODEL", "claude-sonnet-5")


def _extract_json_array(text: str) -> list[dict]:
    """Pull a JSON array out of the model response, tolerating stray prose."""
    text = text.strip()
    if not text.startswith("["):
        match = re.search(r"\[.*\]", text, re.S)
        text = match.group(0) if match else "[]"
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _call_claude(system: str, user: str, model: str) -> str:
    import anthropic  # imported lazily; part of the optional [llm] extra

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    resp = client.messages.create(
        model=model,
        max_tokens=2000,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    parts = [block.text for block in resp.content if getattr(block, "type", None) == "text"]
    return "".join(parts)


def enrich_with_llm(triaged: list[TriagedFinding], *, model: str = DEFAULT_MODEL) -> list[TriagedFinding]:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY not set")

    user_prompt = build_user_prompt(triaged)
    raw = _call_claude(SYSTEM_PROMPT, user_prompt, model)
    verdicts = {v.get("id"): v for v in _extract_json_array(raw) if isinstance(v, dict)}

    for t in triaged:
        v = verdicts.get(t.finding.id)
        if not v:
            continue
        t.vulnerability_class = str(v.get("vulnerability_class") or t.vulnerability_class)
        t.adjusted_severity = Severity.coerce(v.get("adjusted_severity"), t.adjusted_severity)
        t.is_likely_false_positive = bool(v.get("is_likely_false_positive", t.is_likely_false_positive))
        try:
            t.confidence = max(0.0, min(1.0, float(v.get("confidence", t.confidence))))
        except (TypeError, ValueError):
            pass
        t.exploitability = str(v.get("exploitability") or t.exploitability)
        t.remediation = str(v.get("remediation") or t.remediation)
        t.rationale = "LLM-assisted triage."
        t.triaged_by = "llm"
    return triaged
