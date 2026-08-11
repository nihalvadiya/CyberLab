"""
Command-line entry point.

    python -m security_scanner https://example.com --authorize \\
        --confirm I_AUTHORIZE_TESTING

Run with -h for the full option list.
"""

from __future__ import annotations

import argparse
import json
import sys

from security_scanner.config import DEFAULT_MIN_INTERVAL_SEC
from security_scanner.report import render_text
from security_scanner.scanner import run_scan
from security_scanner.validators import AUTHORIZATION_PHRASE, ValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_scanner",
        description=(
            "Educational, detection-only web vulnerability scanner. "
            "Requires explicit authorization for every run."
        ),
    )
    parser.add_argument("target_url", help="Full URL to scan, e.g. https://example.com/")
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm you are authorized to test this target. Required.",
    )
    parser.add_argument(
        "--confirm",
        metavar="PHRASE",
        help=f'Must be exactly "{AUTHORIZATION_PHRASE}". Required with --authorize.',
    )
    parser.add_argument(
        "--allow-internal",
        action="store_true",
        help="Allow scanning hosts that resolve to loopback/private addresses "
        "(needed for a local lab target such as 127.0.0.1). Off by default to "
        "prevent the scanner being pointed at internal infrastructure via SSRF.",
    )
    parser.add_argument(
        "--min-interval",
        type=float,
        default=DEFAULT_MIN_INTERVAL_SEC,
        help=f"Minimum seconds between requests (default {DEFAULT_MIN_INTERVAL_SEC}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of plain text.",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="Write the report to a file instead of stdout.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = run_scan(
            args.target_url,
            authorize=args.authorize,
            authorize_text=args.confirm,
            allow_internal=args.allow_internal,
            min_interval_sec=args.min_interval,
        )
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(result.to_dict(), indent=2) if args.json else render_text(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Report written to {args.output}")
    else:
        print(text)

    return 1 if any(f.risk.value == "High" for f in result.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
