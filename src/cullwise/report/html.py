"""Render a TriageResult as a self-contained, interactive HTML dashboard.

Interactivity (filter by severity/class, search, sort, collapse) is plain inline
JavaScript with no external assets, so the report stays a single portable file.

Security notes:
  * Every piece of finding-derived text is HTML-escaped before templating, so a
    crafted rule message or snippet can't inject markup/script into the report
    (a stored-XSS-style issue in our own output).
  * A strict Content-Security-Policy blocks all network egress and external
    resources; only our own inline style/script run.
"""

from __future__ import annotations

from html import escape

from ..models import Severity, TriageResult

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
        f'<div class="tile"><div class="tile-value" style="color:{color}">{value}</div>'
        f'<div class="tile-label">{_e(label)}</div></div>'
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
            f'<div class="class-row"><div class="class-name">{_e(cls)}</div>'
            f'<div class="class-bar"><span style="width:{pct}%"></span></div>'
            f'<div class="class-count">{count}</div></div>'
        )
    return "\n".join(rows)


def _controls(result: TriageResult, sevs_present: list[Severity]) -> str:
    chips = "".join(
        f'<label class="chip"><input type="checkbox" data-sev="{s.value}" checked>'
        f'<span class="dot" style="background:{_SEV_COLOR[s]}"></span>{s.value}</label>'
        for s in sevs_present
    )
    opts = '<option value="__all__">All classes</option>' + "".join(
        f'<option value="{_e(cls)}">{_e(cls)} ({n})</option>'
        for cls, n in result.stats.class_counts.items()
    )
    return f"""<div class="controls">
    <input id="q" type="search" placeholder="Search file, rule, or message&hellip;" autocomplete="off" spellcheck="false">
    <div class="chips">{chips}</div>
    <select id="classFilter" aria-label="Filter by vulnerability class">{opts}</select>
    <label class="chip"><input type="checkbox" id="hideFp"> Hide false-positives</label>
    <select id="sortBy" aria-label="Sort findings">
      <option value="severity">Sort: severity</option>
      <option value="confidence">Sort: confidence</option>
      <option value="file">Sort: file</option>
    </select>
    <span class="btns">
      <button id="expandAll" type="button">Expand</button>
      <button id="collapseAll" type="button">Collapse</button>
      <button id="printBtn" type="button">Print / PDF</button>
    </span>
    <span class="vis"><b id="visCount">0</b> shown</span>
  </div>"""


def _finding_card(t) -> str:
    f = t.finding
    color = _SEV_COLOR.get(t.adjusted_severity, "#6b7280")
    fp = "1" if t.is_likely_false_positive else "0"
    fp_tag = '<span class="fp-tag">likely false-positive</span>' if t.is_likely_false_positive else ""
    search_text = _e(" ".join([f.file_path, f.rule_id, f.message, t.vulnerability_class]).lower())
    cwe = f'<div class="kv"><span>CWE</span><code>{_e(", ".join(f.cwe))}</code></div>' if f.cwe else ""
    exploit = (
        f'<div class="kv"><span>Exploitability</span><div>{_e(t.exploitability)}</div></div>'
        if t.exploitability
        else ""
    )
    why = f'<div class="kv"><span>Why</span><div class="muted">{_e(t.rationale)}</div></div>' if t.rationale else ""
    return f"""
    <details class="card{' fp' if fp == '1' else ''}" open
      data-severity="{_e(t.adjusted_severity.value)}" data-rank="{t.adjusted_severity.rank}"
      data-class="{_e(t.vulnerability_class)}" data-fp="{fp}"
      data-confidence="{t.confidence:.4f}" data-file="{_e(f.file_path)}" data-text="{search_text}"
      style="--accent:{color}">
      <summary class="card-head">
        <span class="badge" style="background:{color}">{_e(t.adjusted_severity.value)}</span>
        <span class="card-title">{_e(t.vulnerability_class)}</span>
        {fp_tag}
      </summary>
      <div class="card-body">
        <div class="kv"><span>Location</span><code>{_e(f.file_path)}:{_e(f.start_line)}</code></div>
        <div class="kv"><span>Rule</span><code>{_e(f.rule_id)}</code></div>
        {cwe}
        <div class="kv"><span>Severity</span><div>{_e(f.severity.value)} &rarr; <b>{_e(t.adjusted_severity.value)}</b>
          <span class="muted">(confidence {t.confidence:.0%}, via {_e(t.triaged_by)})</span></div></div>
        {exploit}
        <div class="kv remediation"><span>Remediation</span><div>{_e(t.remediation)}</div></div>
        {why}
      </div>
    </details>"""


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>__TITLE__</title>
<style>
  :root { --bg:#0b1120; --panel:#111a2e; --panel2:#0f1830; --text:#e6edf7; --muted:#94a3b8; --border:#1e293b; --accent:#38bdf8; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f1f5f9; --panel:#fff; --panel2:#f8fafc; --text:#0f172a; --muted:#64748b; --border:#e2e8f0; --accent:#0284c7; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .wrap { max-width:980px; margin:0 auto; padding:32px 20px 64px; }
  header.top { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:6px; }
  header.top .top-left { display:flex; align-items:center; gap:14px; }
  header.top .logo { width:40px; height:40px; flex:0 0 auto; }
  header.top h1 { font-size:22px; margin:0; letter-spacing:-.02em; }
  .back-link { font-size:13px; font-weight:600; color:var(--accent); text-decoration:none;
    border:1px solid var(--border); background:var(--panel); padding:7px 12px; border-radius:9px; white-space:nowrap; }
  .back-link:hover { border-color:var(--accent); }
  .subtitle { color:var(--muted); margin:2px 0 24px; }
  .summary { font-size:16px; margin:0 0 20px; }
  .summary b { color:var(--accent); }
  .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:0 0 24px; }
  .tile { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center; }
  .tile-value { font-size:30px; font-weight:700; line-height:1; }
  .tile-label { color:var(--muted); font-size:12px; margin-top:6px; text-transform:uppercase; letter-spacing:.04em; }
  h2.section { font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:26px 0 12px; }
  .classes { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 18px; }
  .class-row { display:grid; grid-template-columns:200px 1fr 40px; align-items:center; gap:12px; padding:7px 0; }
  .class-name { font-weight:600; font-size:14px; }
  .class-bar { background:var(--panel2); border-radius:999px; height:9px; overflow:hidden; }
  .class-bar span { display:block; height:100%; background:linear-gradient(90deg,var(--accent),#818cf8); border-radius:999px; }
  .class-count { text-align:right; color:var(--muted); font-variant-numeric:tabular-nums; }
  .controls { display:flex; flex-wrap:wrap; align-items:center; gap:10px; background:var(--panel); border:1px solid var(--border);
    border-radius:12px; padding:12px 14px; margin-bottom:16px; position:sticky; top:8px; z-index:5; }
  .controls input[type=search] { flex:1 1 220px; min-width:180px; background:var(--panel2); color:var(--text);
    border:1px solid var(--border); border-radius:8px; padding:7px 11px; font-size:14px; }
  .controls select { background:var(--panel2); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:7px 9px; font-size:13px; }
  .chips { display:flex; flex-wrap:wrap; gap:6px; }
  .chip { display:inline-flex; align-items:center; gap:5px; font-size:12px; color:var(--text); background:var(--panel2);
    border:1px solid var(--border); border-radius:999px; padding:4px 9px; cursor:pointer; user-select:none; }
  .chip input { margin:0; accent-color:var(--accent); }
  .dot { width:8px; height:8px; border-radius:999px; display:inline-block; }
  .btns { display:inline-flex; gap:6px; }
  .btns button { background:var(--panel2); color:var(--text); border:1px solid var(--border); border-radius:8px;
    padding:6px 11px; font-size:13px; cursor:pointer; }
  .btns button:hover { border-color:var(--accent); }
  .vis { color:var(--muted); font-size:13px; margin-left:auto; }
  .vis b { color:var(--text); }
  .card { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--accent);
    border-radius:12px; padding:6px 18px; margin:12px 0; }
  .card.fp { opacity:.68; }
  .card-head { display:flex; align-items:center; gap:10px; padding:12px 0; cursor:pointer; list-style:none; }
  .card-head::-webkit-details-marker { display:none; }
  .card-head::before { content:"\\25B8"; color:var(--muted); font-size:12px; transition:transform .12s; }
  .card[open] .card-head::before { transform:rotate(90deg); }
  .card-title { font-weight:600; font-size:16px; }
  .badge { color:#fff; font-size:11px; font-weight:700; letter-spacing:.05em; padding:3px 9px; border-radius:999px; }
  .fp-tag { margin-left:auto; font-size:11px; color:var(--muted); border:1px dashed var(--border); padding:2px 8px; border-radius:999px; }
  .card-body { padding:0 0 12px; }
  .kv { display:grid; grid-template-columns:120px 1fr; gap:10px; padding:4px 0; font-size:14px; }
  .kv > span:first-child { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.03em; padding-top:2px; }
  .kv.remediation div { font-weight:500; }
  code { font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace; font-size:13px;
    background:var(--panel2); padding:1px 6px; border-radius:6px; word-break:break-all; }
  .muted { color:var(--muted); }
  .empty { text-align:center; color:var(--muted); padding:28px; display:none; }
  footer { margin-top:32px; color:var(--muted); font-size:13px; border-top:1px solid var(--border); padding-top:16px; }
  @media (max-width:640px) {
    .tiles { grid-template-columns:repeat(2,1fr); }
    .class-row { grid-template-columns:130px 1fr 32px; }
    .kv { grid-template-columns:1fr; gap:2px; }
    .controls { position:static; }
  }
  @media print { .controls,.btns { display:none !important; } .card { break-inside:avoid; } }
</style>
</head>
<body>
  <div class="wrap">
    <header class="top">
      <div class="top-left">
        <svg class="logo" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="var(--accent)" opacity="0.18"/>
          <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="var(--accent)" stroke-width="1.5"/>
          <path d="m8.5 12 2.3 2.3L15.7 9.4" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <h1>Cullwise Triage Report</h1>
      </div>
      <a class="back-link" href="https://unifosec.github.io/">&larr; Portfolio</a>
    </header>
    <p class="subtitle">AI-assisted application-security triage &middot; findings clustered by vulnerability class</p>

    <p class="summary">__SUMMARY__</p>
    <div class="tiles">__TILES__</div>

    <h2 class="section">Vulnerability classes</h2>
    <div class="classes">__CLASSES__</div>

    <h2 class="section">Findings (prioritized)</h2>
    __CONTROLS__
    <div id="findings">__CARDS__</div>
    <div class="empty" id="empty">No findings match the current filters.</div>

    <footer>Generated by Cullwise &middot; triage is advisory &mdash; confirm before acting.</footer>
  </div>
<script>
(function () {
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card'));
  var list = document.getElementById('findings');
  var q = document.getElementById('q');
  var sevBoxes = Array.prototype.slice.call(document.querySelectorAll('input[data-sev]'));
  var classFilter = document.getElementById('classFilter');
  var hideFp = document.getElementById('hideFp');
  var sortBy = document.getElementById('sortBy');
  var visCount = document.getElementById('visCount');
  var empty = document.getElementById('empty');

  function activeSevs() {
    var s = {};
    sevBoxes.forEach(function (b) { if (b.checked) s[b.getAttribute('data-sev')] = true; });
    return s;
  }
  function apply() {
    var term = (q.value || '').toLowerCase();
    var sevs = activeSevs();
    var cls = classFilter.value;
    var hf = hideFp.checked;
    var visible = 0;
    cards.forEach(function (c) {
      var okSev = !!sevs[c.getAttribute('data-severity')];
      var okCls = cls === '__all__' || c.getAttribute('data-class') === cls;
      var okFp = !hf || c.getAttribute('data-fp') !== '1';
      var okQ = !term || (c.getAttribute('data-text') || '').indexOf(term) >= 0;
      var show = okSev && okCls && okFp && okQ;
      c.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    visCount.textContent = visible;
    empty.style.display = visible ? 'none' : 'block';
  }
  function sortCards() {
    var by = sortBy.value;
    cards.slice().sort(function (a, b) {
      var fa = a.getAttribute('data-fp') === '1' ? 0 : 1;
      var fb = b.getAttribute('data-fp') === '1' ? 0 : 1;
      if (fa !== fb) return fb - fa;
      if (by === 'file') return (a.getAttribute('data-file') || '').localeCompare(b.getAttribute('data-file') || '');
      var ka = by === 'confidence' ? parseFloat(a.getAttribute('data-confidence')) : parseInt(a.getAttribute('data-rank'), 10);
      var kb = by === 'confidence' ? parseFloat(b.getAttribute('data-confidence')) : parseInt(b.getAttribute('data-rank'), 10);
      return kb - ka;
    }).forEach(function (c) { list.appendChild(c); });
  }
  q.addEventListener('input', apply);
  sevBoxes.forEach(function (b) { b.addEventListener('change', apply); });
  classFilter.addEventListener('change', apply);
  hideFp.addEventListener('change', apply);
  sortBy.addEventListener('change', function () { sortCards(); apply(); });
  document.getElementById('expandAll').addEventListener('click', function () { cards.forEach(function (c) { c.open = true; }); });
  document.getElementById('collapseAll').addEventListener('click', function () { cards.forEach(function (c) { c.open = false; }); });
  document.getElementById('printBtn').addEventListener('click', function () { window.print(); });
  sortCards();
  apply();
})();
</script>
</body>
</html>"""


def render_html(result: TriageResult, *, title: str = "Cullwise Triage Report") -> str:
    s = result.stats
    summary = (
        f"<b>{s.raw_count}</b> raw findings &rarr; <b>{s.deduped_count}</b> unique &rarr; "
        f"<b>{s.actionable_count}</b> actionable ({s.false_positive_count} likely false-positive / low-risk)."
    )
    tiles = "".join(
        [
            _stat_tile(s.raw_count, "Raw findings", "#e2e8f0"),
            _stat_tile(s.deduped_count, "Unique", "#38bdf8"),
            _stat_tile(s.actionable_count, "Actionable", "#f97316"),
            _stat_tile(s.false_positive_count, "Likely false-positive", "#64748b"),
        ]
    )
    sevs_present = sorted(
        {t.adjusted_severity for t in result.findings}, key=lambda sv: sv.rank, reverse=True
    )
    cards = "\n".join(_finding_card(t) for t in result.findings)
    return (
        _TEMPLATE.replace("__TITLE__", _e(title))
        .replace("__SUMMARY__", summary)
        .replace("__TILES__", tiles)
        .replace("__CLASSES__", _class_rows(result))
        .replace("__CONTROLS__", _controls(result, sevs_present))
        .replace("__CARDS__", cards)
    )
