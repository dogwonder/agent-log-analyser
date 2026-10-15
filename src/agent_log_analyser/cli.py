"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import analyse
from .networks import fetch_ranges, load_known_clusters, load_published_ranges, ranges_fetched_at
from .readers import read_requests
from .report import render


def _analyse(args: argparse.Namespace) -> int:
    missing = [str(p) for p in args.logs if not p.is_file()]
    if missing:
        print(f"Log file not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    requests = []
    for path in args.logs:
        requests.extend(read_requests(path, args.format))
    analysis = analyse(
        requests,
        published=load_published_ranges(args.ranges),
        known=load_known_clusters(args.clusters),
        min_requests=args.min_requests,
        schedule_window=args.schedule_window,
    )
    report = render(
        analysis,
        ", ".join(p.name for p in args.logs),
        top=args.top,
        ranges_fetched=ranges_fetched_at(args.ranges),
    )
    if args.out:
        args.out.write_text(report)
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(report)
    return 0


def _fetch_ranges(args: argparse.Namespace) -> int:
    outcomes = fetch_ranges(args.out)
    for key, outcome in outcomes.items():
        print(f"{key:32} {outcome}")
    return 0 if any(not o.startswith(("failed", "no prefixes")) for o in outcomes.values()) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-log-analyser",
        description="Find AI agents in web server logs, including ones that pretend to be browsers.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("analyse", help="analyse one or more log files")
    run.add_argument("logs", nargs="+", type=Path, help="log files (.csv export, combined format, or .gz)")
    run.add_argument("--format", default="auto", choices=["auto", "wpcloud-csv", "combined"])
    run.add_argument("--ranges", type=Path, default=Path("ranges"), help="directory from fetch-ranges")
    run.add_argument("--clusters", type=Path, help="extra known-clusters JSON file")
    run.add_argument("--min-requests", type=int, default=5, help="smallest cluster to flag (default 5)")
    run.add_argument("--schedule-window", type=int, default=30, help="schedule window in minutes (default 30)")
    run.add_argument("--top", type=int, default=15, help="rows per section (default 15)")
    run.add_argument("--out", type=Path, help="write the Markdown report here instead of stdout")
    run.set_defaults(handler=_analyse)

    fetch = commands.add_parser("fetch-ranges", help="download operators' published IP ranges")
    fetch.add_argument("--out", type=Path, default=Path("ranges"))
    fetch.set_defaults(handler=_fetch_ranges)

    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
