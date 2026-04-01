"""CLI entry point for mapguard.

Provides the main argparse-based command-line interface with three subcommands:
- scan-dir: Scan a local directory for source map issues
- scan-tarball: Scan a local .tgz tarball for source map issues
- scan-npm: Fetch and scan a published npm package by name and optional version
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from mapguard import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the mapguard CLI.

    Returns:
        argparse.ArgumentParser: Configured argument parser with all subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="mapguard",
        description=(
            "mapguard - Scan npm packages and JS/TS bundles for leaked source maps. "
            "Detects accidentally published .map files that expose original source code."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  mapguard scan-dir ./dist\n"
            "  mapguard scan-tarball my-package-1.0.0.tgz\n"
            "  mapguard scan-npm react@18.2.0\n"
            "  mapguard scan-npm lodash --json\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mapguard {__version__}",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON (suitable for CI integration)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored terminal output",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # scan-dir subcommand
    scan_dir_parser = subparsers.add_parser(
        "scan-dir",
        help="Scan a local directory for source map issues",
        description="Recursively scan a local directory for .map files and sourceMappingURL references.",
    )
    scan_dir_parser.add_argument(
        "path",
        metavar="PATH",
        help="Path to the directory to scan",
    )
    scan_dir_parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum risk level to report (default: LOW)",
    )

    # scan-tarball subcommand
    scan_tarball_parser = subparsers.add_parser(
        "scan-tarball",
        help="Scan a local .tgz tarball for source map issues",
        description="Scan a local npm package tarball (.tgz) for .map files and sourceMappingURL references.",
    )
    scan_tarball_parser.add_argument(
        "path",
        metavar="PATH",
        help="Path to the .tgz tarball to scan",
    )
    scan_tarball_parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum risk level to report (default: LOW)",
    )

    # scan-npm subcommand
    scan_npm_parser = subparsers.add_parser(
        "scan-npm",
        help="Fetch and scan a published npm package",
        description=(
            "Download and scan a published npm package from the registry. "
            "Accepts package name with optional @version specifier."
        ),
    )
    scan_npm_parser.add_argument(
        "package",
        metavar="PACKAGE",
        help="npm package name, optionally with version (e.g. lodash or lodash@4.17.21)",
    )
    scan_npm_parser.add_argument(
        "--registry",
        default="https://registry.npmjs.org",
        help="npm registry base URL (default: https://registry.npmjs.org)",
    )
    scan_npm_parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="LOW",
        help="Minimum risk level to report (default: LOW)",
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the mapguard CLI.

    Args:
        argv: Optional list of command-line arguments. If None, sys.argv is used.

    Returns:
        int: Exit code (0 for success, non-zero for errors or findings above threshold).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # These imports will be fully implemented in later phases.
    # For now we just ensure the CLI parses and dispatches correctly.
    try:
        if args.command == "scan-dir":
            return _cmd_scan_dir(args)
        elif args.command == "scan-tarball":
            return _cmd_scan_tarball(args)
        elif args.command == "scan-npm":
            return _cmd_scan_npm(args)
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def _cmd_scan_dir(args: argparse.Namespace) -> int:
    """Handle the scan-dir subcommand.

    Args:
        args: Parsed argument namespace.

    Returns:
        int: Exit code.
    """
    from mapguard.scanner import Scanner
    from mapguard.reporter import Reporter

    scanner = Scanner()
    result = scanner.scan_directory(args.path)
    reporter = Reporter(use_json=args.json, no_color=args.no_color)
    reporter.report(result, min_risk=args.min_risk)
    return 0 if not result.findings else 1


def _cmd_scan_tarball(args: argparse.Namespace) -> int:
    """Handle the scan-tarball subcommand.

    Args:
        args: Parsed argument namespace.

    Returns:
        int: Exit code.
    """
    from mapguard.scanner import Scanner
    from mapguard.reporter import Reporter

    scanner = Scanner()
    result = scanner.scan_tarball(args.path)
    reporter = Reporter(use_json=args.json, no_color=args.no_color)
    reporter.report(result, min_risk=args.min_risk)
    return 0 if not result.findings else 1


def _cmd_scan_npm(args: argparse.Namespace) -> int:
    """Handle the scan-npm subcommand.

    Args:
        args: Parsed argument namespace.

    Returns:
        int: Exit code.
    """
    from mapguard.npm_fetcher import NpmFetcher
    from mapguard.scanner import Scanner
    from mapguard.reporter import Reporter

    fetcher = NpmFetcher(registry=args.registry)
    tarball_path = fetcher.fetch(args.package)
    scanner = Scanner()
    result = scanner.scan_tarball(tarball_path, source_label=args.package)
    reporter = Reporter(use_json=args.json, no_color=args.no_color)
    reporter.report(result, min_risk=args.min_risk)
    return 0 if not result.findings else 1


if __name__ == "__main__":
    sys.exit(main())
