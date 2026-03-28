"""CLI entry point for Deploy Guard."""

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .models import Issue, deduplicate, final_decision
from .scanner import DeployGuard
from .git_scanner import scan_git_history
from .config import find_config, load_config
from .formatters.terminal import print_report
from .formatters.json_fmt import json_report
from .formatters.sarif import sarif_report
from .formatters.html import html_report

# Garantir UTF-8 no terminal do Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

BANNER = r"""
   ___           _               ___                     _
  |   \ ___ _ __| |___ _  _     / __|_  _ __ _ _ _ __ __| |
  | |) / -_) '_ \ / _ \ || |   | (_ | || / _` | '_/ _` |_|
  |___/\___| .__/_\___/\_, |    \___|\_,_\__,_|_| \__,_(_)
            |_|        |__/     v{version}
"""


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy-guard",
        description="🛡️  Deploy Guard — Pre-deploy security scanner with LGPD compliance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  deploy-guard ./dist --target frontend
  deploy-guard .env --strict-lgpd
  deploy-guard . --target any --format sarif -o report.sarif
  deploy-guard . --format html -o report.html
  deploy-guard ./infra --target iac --history 50
        """,
    )

    parser.add_argument(
        "path",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"deploy-guard {__version__}",
    )
    parser.add_argument(
        "--target",
        choices=["frontend", "backend", "iac", "any"],
        default="any",
        help="Deploy target type (affects rule set)",
    )
    parser.add_argument(
        "--strict-lgpd",
        action="store_true",
        help="Enable stricter LGPD rules (recommended for Brazilian data)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Shortcut for --format json (CI/CD compatibility)",
    )
    parser.add_argument(
        "--history",
        type=int,
        metavar="N",
        help="Scan last N git commits for leaked secrets",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Enable PDF text-layer scanning (requires: pip install pdfplumber)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to .deploy-guard.yml config file",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Always exit 0 even on BLOCK (useful for CI report-only mode)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    # Format shortcut
    if args.json:
        args.format = "json"

    # Banner
    if args.format == "terminal" and not args.no_banner:
        print(BANNER.format(version=__version__), file=sys.stderr)

    # Config file
    config_path = Path(args.config) if args.config else find_config(args.path)
    config = load_config(config_path)
    if config_path and args.format == "terminal":
        print(f"  📋 Config: {config_path}", file=sys.stderr)

    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        return 2

    # Apply config defaults
    target = config.get("target", args.target)
    strict_lgpd = config.get("strict_lgpd", args.strict_lgpd)

    # Run scanner
    guard = DeployGuard(
        target=target,
        strict_lgpd=strict_lgpd,
        scan_pdf_enabled=args.pdf,
    )
    all_issues = guard.scan_path(args.path)

    # Git history
    if args.history:
        history_issues = scan_git_history(args.history, guard)
        all_issues.extend(history_issues)

    all_issues = deduplicate(all_issues)

    # Output
    if args.format == "terminal":
        print_report(all_issues, args.path)
    elif args.format == "json":
        output = json_report(all_issues, args.path)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"JSON report written to {args.output}", file=sys.stderr)
        else:
            print(output)
    elif args.format == "sarif":
        output = sarif_report(all_issues, args.path)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"SARIF report written to {args.output}", file=sys.stderr)
        else:
            print(output)
    elif args.format == "html":
        output = html_report(all_issues, args.path)
        out_file = args.output or "deploy-guard-report.html"
        Path(out_file).write_text(output, encoding="utf-8")
        print(f"HTML report written to {out_file}", file=sys.stderr)

    decision = final_decision(all_issues)
    if args.exit_zero:
        return 0
    return 1 if decision == "block" else 0


def cli():
    """Entry point for the installed CLI command."""
    sys.exit(main())


if __name__ == "__main__":
    cli()
