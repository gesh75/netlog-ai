"""CLI entrypoint — `ai-log-analyzer serve` or `ai-log-analyzer analyze <container>`."""
from __future__ import annotations

import argparse
import itertools
import json
import sys

from ai_log_analyzer.adapters import frr
from ai_log_analyzer.adapters.file import parse_file, parse_lines
from ai_log_analyzer.analyzer import analyze
from ai_log_analyzer.web.app import main as serve_main


def cmd_serve(_args: argparse.Namespace) -> int:
    serve_main()
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    # Chain lazy iterators — analyze() streams them, so multi-GB files run in
    # bounded memory (the web route caps size; the CLI is the big-file path).
    streams: list = []
    if args.frr:
        for c in args.frr:
            streams.append(frr.frr_docker_logs(c, tail=args.tail))
    if args.file:
        for path in args.file:
            streams.append(parse_file(path))
    if args.stdin:
        streams.append(parse_lines(sys.stdin.readlines()))

    event_iter = itertools.chain.from_iterable(streams)
    try:
        first = next(event_iter)
    except StopIteration:
        print("error: no input — pass --frr, --file, or --stdin", file=sys.stderr)
        return 2

    result = analyze(itertools.chain([first], event_iter), use_llm=not args.no_llm)
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def cmd_containers(_args: argparse.Namespace) -> int:
    for name in frr.list_lab_containers():
        print(name)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Zero-setup demo: analyze a deterministic synthetic incident storyline.

    --serve additionally starts the web UI with a local syslog listener and a
    feeder thread replaying the storyline, so the Live Tail panel streams
    events in real time — no lab or devices needed.
    """
    import os

    from ai_log_analyzer.adapters.file import parse_lines
    from ai_log_analyzer.demo import generate_demo_lines, start_udp_feeder

    lines = generate_demo_lines()
    result = analyze(parse_lines(lines), use_llm=args.llm)

    d = result.to_dict()
    print(f"Demo storyline : {len(lines)} synthetic log lines, 6 devices, 4 vendor dialects")
    print(f"Health score   : {d['score']}/100 (grade {d['grade']} — {d['grade_label']})")
    print(f"Fabric stability: {d['stability']['fabric_score']}/100")
    print()
    print("Executive summary:")
    for b in d["executive_summary"]:
        print(f"  • {b}")
    print()
    print("Top action items:")
    for a in d["action_items"][:5]:
        devs = ", ".join(a["devices"][:3])
        print(f"  [{a['severity'].upper():8}] {a['description']} ({a['count']}× on {devs})")
    up = d["unknown_patterns"]
    if up["top_templates"]:
        print()
        print(f"Unknown patterns ({up['template_count']} templates from {up['total_unclassified']} unmatched lines):")
        for t in up["top_templates"][:3]:
            flag = "⚠ " if t["severity_hint"] != "info" else "  "
            print(f"  {flag}{t['count']:>3}× {t['template'][:90]}")

    if not args.serve:
        print("\nRun `ai-log-analyzer demo --serve` to watch this stream live in the UI.")
        return 0

    port = int(os.environ.get("NETLOG_DEMO_SYSLOG_PORT", "5514"))
    os.environ.setdefault("NETLOG_SOURCE_demo_TYPE", "syslog")
    os.environ.setdefault("NETLOG_SOURCE_demo_URL", "udp://127.0.0.1")
    os.environ.setdefault("NETLOG_SOURCE_demo_PORT", str(port))
    os.environ.setdefault("NETLOG_SOURCE_demo_BIND", "127.0.0.1")
    start_udp_feeder(port)
    print(f"\nDemo feeder streaming to udp://127.0.0.1:{port} — open the UI,")
    print("expand '🔴 Live Tail' in the Logs tab, pick source 'demo', press Start.")
    serve_main()
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Score playbook quality with the LLM-as-Judge harness.

    Default: self-test every rule-based KB playbook (the quality floor with
    the LLM off). --file scores a saved /api/analyze JSON result instead.
    --min-score turns the run into a CI gate (exit 1 below threshold).
    """
    from ai_log_analyzer import judge

    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                result = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
        report = judge.judge_analysis_result(result, use_llm=args.use_llm)
    else:
        report = judge.judge_kb(use_llm=args.use_llm)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Playbooks scored : {report['playbooks_scored']}")
        print(f"Overall quality  : {report['overall']}/10")
        print()
        for v in report["verdicts"][: args.show]:
            s = v["scores"]
            label = v.get("description") or v.get("category", "")
            print(f"  {s['overall']:>4}/10  [{v.get('judge')}] {label[:70]}")
            print(f"          action={s['actionability']} safety={s['safety']} "
                  f"grounding={s['grounding']} complete={s['completeness']}")
            for note in v.get("notes", [])[:2]:
                print(f"          ! {note}")

    if args.min_score and report["overall"] < args.min_score:
        print(f"\nFAIL: overall {report['overall']} < required {args.min_score}",
              file=sys.stderr)
        return 1
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP server (stdio by default) so Claude Code / Cursor / Continue
    can call netlog-ai tools directly."""
    try:
        from ai_log_analyzer.mcp_server import run_mcp_server
    except ImportError as exc:
        print(f"error: MCP server not available — {exc}", file=sys.stderr)
        print("Install with: pip install 'netlog-ai[mcp]'", file=sys.stderr)
        return 2
    try:
        run_mcp_server(transport=args.transport)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="ai-log-analyzer", description="AI-powered network log analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="Run the web UI on port ANALYZER_PORT (default 6060)")
    sp.set_defaults(func=cmd_serve)

    ap = sub.add_parser("analyze", help="Analyze logs and print JSON to stdout")
    ap.add_argument("--frr", nargs="*", help="FRR docker container names")
    ap.add_argument("--file", nargs="*", help="Syslog file path(s)")
    ap.add_argument("--stdin", action="store_true", help="Read log lines from stdin")
    ap.add_argument("--tail", type=int, default=500, help="Lines per FRR container (default 500)")
    ap.add_argument("--no-llm", action="store_true", help="Skip LLM, use rule-based KB only")
    ap.set_defaults(func=cmd_analyze)

    cp = sub.add_parser("containers", help="List running FRR lab containers")
    cp.set_defaults(func=cmd_containers)

    dp = sub.add_parser("demo", help="Zero-setup demo: synthetic incident storyline through the full pipeline")
    dp.add_argument("--serve", action="store_true", help="Also start the web UI with a live syslog feeder (Live Tail demo)")
    dp.add_argument("--llm", action="store_true", help="Use the configured LLM (default: rule-based KB, fully offline)")
    dp.set_defaults(func=cmd_demo)

    ep = sub.add_parser("eval", help="Score playbook quality (LLM-as-Judge; KB self-test by default)")
    ep.add_argument("--file", help="Saved /api/analyze JSON result to score (default: score the built-in KB)")
    ep.add_argument("--use-llm", action="store_true", help="Blend in a real LLM judge (falls back to heuristic)")
    ep.add_argument("--json", action="store_true", help="Machine-readable output")
    ep.add_argument("--show", type=int, default=10, help="Verdicts to print, worst first (default 10)")
    ep.add_argument("--min-score", type=float, default=0.0, help="Exit 1 if overall quality is below this (CI gate)")
    ep.set_defaults(func=cmd_eval)

    mp = sub.add_parser("mcp", help="Run as an MCP server (for Claude Code / Cursor / Continue)")
    mp.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http"],
                    help="MCP transport (default: stdio)")
    mp.set_defaults(func=cmd_mcp)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
