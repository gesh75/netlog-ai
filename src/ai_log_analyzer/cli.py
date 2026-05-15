"""CLI entrypoint — `ai-log-analyzer serve` or `ai-log-analyzer analyze <container>`."""
from __future__ import annotations

import argparse
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
    events: list = []
    if args.frr:
        for c in args.frr:
            events.extend(frr.frr_docker_logs(c, tail=args.tail))
    if args.file:
        for path in args.file:
            events.extend(parse_file(path))
    if args.stdin:
        events.extend(parse_lines(sys.stdin.readlines()))

    if not events:
        print("error: no input — pass --frr, --file, or --stdin", file=sys.stderr)
        return 2

    result = analyze(events, use_llm=not args.no_llm)
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def cmd_containers(_args: argparse.Namespace) -> int:
    for name in frr.list_lab_containers():
        print(name)
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

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
