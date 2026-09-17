"""Render a TriageResult as a self-contained, styled HTML dashboard.

Security note: findings originate from an untrusted repository, so every piece
of finding-derived text is HTML-escaped before templating. Otherwise a crafted
rule message or code snippet could inject markup/script into the report itself
(a stored-XSS-style issue in our own output). The page has no external assets.
"""

from __future__ import annotations

from html import escape

from ..models import Severity, TriageResult

# Severity -> (accent color, readable label bg)
_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def _e(value: object) -> str:
    return escape(str(value if value is not None else ""))


def _stat_tile(value: int, label: str, color: str) -> str:
    return (
        f'<div class="tile">'
        f'<div class="tile-value" style="color:{color}">{value}</div>'
        f'<div class="tile-label">{_e(label)}</div>'
        f"</div>"
    )


def _class_rows(result: TriageResult) -> str:
    counts = result.stats.class_counts
    if not counts:
        return '<p class="muted">No vulnerability classes detected.</p>'
    top = max(counts.values()) or 1
    rows = []
    for cls, count in counts.items():
        pct = int(round(100 * count / top))
        rows.append(
            f'<div class="class-row">'
            f'<div class="class-name">{_e(cls)}</div>'
            f'<div class="class-bar"><span style="width:{pct}%"></span></div>'
            f'<div class="class-count">{count}</div>'
            f"</div>"
        )
    return "\n".join(rows)


def _finding_card(t) -> str:
    f = t.finding
    color = _SEV_COLOR.get(t.adjusted_severity, "#6b7280")
    fp = " fp" if t.is_likely_false_positive else ""
    fp_tag = '<span class="fp-tag">likely false-positive</span>' if t.is_likely_false_positive else ""
    cwe = f'<div class="kv"><span>CWE</span><code>{_e(", ".join(f.cwe))}</code></div>' if f.cwe else ""
    exploit = (
        f'<div class="kv"><span>Exploitability</span><div>{_e(t.exploitability)}</div></div>'
        if t.exploitability
        else ""
    )
    return f"""
    <article class="card{fp}" style="--accent:{color}">
      <header class="card-head">
        <span class="badge" style="background:{color}">{_e(t.adjusted_severity.value)}</span>
        <h3>{_e(t.vulnerability_class)}</h3>
        {fp_tag}
      </header>
      <div class="kv"><span>Location</span><code>{_e(f.file_path)}:{_e(f.start_line)}</code></div>
      <div class="kv"><span>Rule</span><code>{_e(f.rule_id)}</code></div>
      {cwe}
      <div class="kv"><span>Severity</span><div>{_e(f.severity.value)} &rarr; <b>{_e(t.adjusted_severity.value)}</b>
        <span class="muted">(confidence {t.confidence:.0%}, via {_e(t.triaged_by)})</span></div></div>
      {exploit}
      <div class="kv remediation"><span>Remediation</span><div>{_e(t.remediation)}</div></div>
      {f'<div class="kv"><span>Why</span><div class="muted">{_e(t.rationale)}</div></div>' if t.rationale else ""}
    </article>"""


def render_html(result: TriageResult, *, title: str = "ThreatLens Triage Report") -> str:
    s = result.stats
    tiles = "".join(
        [
            _stat_tile(s.raw_count, "Raw findings", "#e2e8f0"),
            _stat_tile(s.deduped_count, "Unique", "#38bdf8"),
            _stat_tile(s.actionable_count, "Actionable", "#f97316"),
            _stat_tile(s.false_positive_count, "Likely false-positive", "#64748b"),
        ]
    )
    cards = "\n".join(_finding_card(t) for t in result.findings)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{
    --bg:#0b1120; --panel:#111a2e; --panel2:#0f1830; --text:#e6edf7;
    --muted:#94a3b8; --border:#1e293b; --accent:#38bdf8;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg:#f1f5f9; --panel:#ffffff; --panel2:#f8fafc; --text:#0f172a;
      --muted:#64748b; --border:#e2e8f0; --accent:#0284c7;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--text);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }}
  .wrap {{ max-width:960px; margin:0 auto; padding:32px 20px 64px; }}
  header.top {{ display:flex; align-items:center; gap:14px; margin-bottom:6px; }}
  header.top .logo {{ width:40px; height:40px; flex:0 0 auto; }}
  header.top h1 {{ font-size:22px; margin:0; letter-spacing:-.02em; }}
  .subtitle {{ color:var(--muted); margin:2px 0 24px; }}
  .summary {{ font-size:16px; margin:0 0 20px; }}
  .summary b {{ color:var(--accent); }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:0 0 28px; }}
  .tile {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center; }}
  .tile-value {{ font-size:30px; font-weight:700; line-height:1; }}
  .tile-label {{ color:var(--muted); font-size:12px; margin-top:6px; text-transform:uppercase; letter-spacing:.04em; }}
  h2.section {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:28px 0 12px; }}
  .classes {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 18px; }}
  .class-row {{ display:grid; grid-template-columns:200px 1fr 40px; align-items:center; gap:12px; padding:7px 0; }}
  .class-name {{ font-weight:600; font-size:14px; }}
  .class-bar {{ background:var(--panel2); border-radius:999px; height:9px; overflow:hidden; }}
  .class-bar span {{ display:block; height:100%; background:linear-gradient(90deg,var(--accent),#818cf8); border-radius:999px; }}
  .class-count {{ text-align:right; color:var(--muted); font-variant-numeric:tabular-nums; }}
  .card {{
    background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--accent);
    border-radius:12px; padding:16px 18px; margin:12px 0;
  }}
  .card.fp {{ opacity:.68; }}
  .card-head {{ display:flex; align-items:center; gap:10px; margin-bottom:12px; }}
  .card-head h3 {{ margin:0; font-size:16px; }}
  .badge {{ color:#fff; font-size:11px; font-weight:700; letter-spacing:.05em; padding:3px 9px; border-radius:999px; }}
  .fp-tag {{ margin-left:auto; font-size:11px; color:var(--muted); border:1px dashed var(--border); padding:2px 8px; border-radius:999px; }}
  .kv {{ display:grid; grid-template-columns:120px 1fr; gap:10px; padding:4px 0; font-size:14px; }}
  .kv > span:first-child {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.03em; padding-top:2px; }}
  .kv.remediation div {{ font-weight:500; }}
  code {{ font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace; font-size:13px;
    background:var(--panel2); padding:1px 6px; border-radius:6px; word-break:break-all; }}
  .muted {{ color:var(--muted); }}
  footer {{ margin-top:32px; color:var(--muted); font-size:13px; border-top:1px solid var(--border); padding-top:16px; }}
  @media (max-width:640px) {{
    .tiles {{ grid-template-columns:repeat(2,1fr); }}
    .class-row {{ grid-template-columns:130px 1fr 32px; }}
    .kv {{ grid-template-columns:1fr; gap:2px; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
    <header class="top">
      <svg class="logo" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="var(--accent)" opacity="0.18"/>
        <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="var(--accent)" stroke-width="1.5"/>
        <path d="m8.5 12 2.3 2.3L15.7 9.4" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <h1>ThreatLens Triage Report</h1>
    </header>
    <p class="subtitle">AI-assisted application-security triage &middot; findings clustered by vulnerability class</p>

    <p class="summary"><b>{s.raw_count}</b> raw findings &rarr; <b>{s.deduped_count}</b> unique &rarr;
      <b>{s.actionable_count}</b> actionable ({s.false_positive_count} likely false-positive / low-risk).</p>

    <div class="tiles">{tiles}</div>

    <h2 class="section">Vulnerability classes</h2>
    <div class="classes">{_class_rows(result)}</div>

    <h2 class="section">Findings (prioritized)</h2>
    {cards}

    <footer>Generated by ThreatLens &middot; triage is advisory &mdash; confirm before acting.</footer>
  </div>
</body>
</html>"""
