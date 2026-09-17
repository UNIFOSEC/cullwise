"""ThreatLens command-line interface.

    threatlens triage examples/semgrep-sample.json --out report.md
    threatlens triage findings.json --llm --min-severity MEDIUM
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .ingest import load_semgrep_file
from .models import Severity
from .report import render_html, render_markdown
from .triage import triage


def _resolve_format(args: argparse.Namespace) -> str:
    if args.format:
        return args.format
    # Auto-detect from the output filename when --format is not given.
    if args.out and args.out.lower().endswith((".html", ".htm")):
        return "html"
    return "md"


def _cmd_triage(args: argparse.Namespace) -> int:
    findings = load_semgrep_file(args.input)
    if args.min_severity:
        floor = Severity(args.min_severity).rank
        findings = [f for f in findings if f.severity.rank >= floor]

    result = triage(findings, use_llm=args.llm)
    fmt = _resolve_format(args)
    report = render_html(result) if fmt == "html" else render_markdown(result)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"[threatlens] wrote {args.out}")
    else:
        print(report)

    s = result.stats
    print(
        f"[threatlens] {s.raw_count} raw → {s.deduped_count} unique → "
        f"{s.actionable_count} actionable ({s.false_positive_count} likely FP)",
        file=sys.stderr,
    )
    # Non-zero exit when actionable findings exist, so CI can gate on it.
    return 1 if (args.fail_on_findings and s.actionable_count > 0) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatlens", description=__doc__)
    parser.add_argument("--version", action="version", version=f"threatlens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    tri = sub.add_parser("triage", help="Triage a scanner findings file.")
    tri.add_argument("input", help="Path to a Semgrep JSON results file.")
    tri.add_argument("--out", help="Write the report to this file (format auto-detected from extension).")
    tri.add_argument(
        "--format",
        choices=["md", "html"],
        help="Report format. Defaults to html when --out ends in .html, else md.",
    )
    tri.add_argument("--llm", action="store_true", help="Use Claude for triage (needs ANTHROPIC_API_KEY).")
    tri.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="Drop findings below this reported severity before triage.",
    )
    tri.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit non-zero when actionable findings remain (for CI gating).",
    )
    tri.set_defaults(func=_cmd_triage)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Reports contain UTF-8 (emoji, arrows). On Windows the default console/redirect
    # encoding is cp1252, which raises UnicodeEncodeError when piped to a file.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
