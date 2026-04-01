"""CLI entry point for mapguard.

Provides the main argparse-based command-line interface with three subcommands:

- scan-dir: Scan a local directory for source map issues
- scan-tarball: Scan a local .tgz tarball for source map issues
- scan-npm: Fetch and scan a published npm package by name and optional version

Exit codes:
    0: Scan completed with no findings at or above the minimum risk level.
    1: Scan completed with one or more findings at or above the minimum risk level.
    2: Argument error or usage error.
    3: Fatal runtime error (file not found, network failure, etc.).
"""

from __future__ import annotations

import argparse
import sys
import tarfile
from pathlib import Path
from typing import Optional

from mapguard import __version__

# Exit codes
_EXIT_OK = 0
_EXIT_FINDINGS = 1
_EXIT_USAGE = 2
_EXIT_ERROR = 3

# Default minimum risk level that triggers a non-zero exit code
_DEFAULT_MIN_RISK = "HIGH"


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the mapguard CLI.

    Returns:
        argparse.ArgumentParser: Configured argument parser with all subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="mapguard",
        description=(
            "mapguard - Scan npm packages and JS/TS bundles for leaked source maps.\n"
            "Detects accidentally published .map files that expose original source code."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  mapguard scan-dir ./dist\n"
            "  mapguard scan-tarball package.tgz\n"
            "  mapguard scan-npm lodash@4.17.21\n"
            "  mapguard scan-npm @babel/core --json\n"
            "  mapguard scan-dir ./dist --min-risk CRITICAL\n"
            "  mapguard scan-npm my-package --no-remediation\n"
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
        dest="json_output",
        help="Output results as JSON instead of a rich terminal table.",
    )

    parser.add_argument(
        "--min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=_DEFAULT_MIN_RISK,
        dest="min_risk",
        metavar="LEVEL",
        help=(
            "Minimum risk level that causes a non-zero exit code. "
            "One of: LOW, MEDIUM, HIGH, CRITICAL (default: %(default)s)."
        ),
    )

    parser.add_argument(
        "--no-remediation",
        action="store_true",
        default=False,
        dest="no_remediation",
        help="Suppress the remediation advice section from the terminal output.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        dest="no_color",
        help="Disable colour output (implied when --json is used).",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="subcommands",
        metavar="COMMAND",
    )
    subparsers.required = True

    # ------------------------------------------------------------------
    # scan-dir
    # ------------------------------------------------------------------
    scan_dir = subparsers.add_parser(
        "scan-dir",
        help="Scan a local directory for source map issues.",
        description=(
            "Recursively scan a local directory for .map files and "
            "sourceMappingURL references in JavaScript/TypeScript bundle files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_dir.add_argument(
        "directory",
        metavar="DIRECTORY",
        help="Path to the local directory to scan.",
    )
    scan_dir.add_argument(
        "--label",
        metavar="LABEL",
        default=None,
        help="Human-readable label for the scan source (defaults to the directory path).",
    )

    # ------------------------------------------------------------------
    # scan-tarball
    # ------------------------------------------------------------------
    scan_tarball = subparsers.add_parser(
        "scan-tarball",
        help="Scan a local .tgz tarball for source map issues.",
        description=(
            "Extract a .tgz / .tar.gz tarball to a temporary directory and "
            "scan it for .map files and sourceMappingURL references."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_tarball.add_argument(
        "tarball",
        metavar="TARBALL",
        help="Path to the local .tgz tarball to scan.",
    )
    scan_tarball.add_argument(
        "--label",
        metavar="LABEL",
        default=None,
        help="Human-readable label for the scan source (defaults to the tarball filename).",
    )

    # ------------------------------------------------------------------
    # scan-npm
    # ------------------------------------------------------------------
    scan_npm = subparsers.add_parser(
        "scan-npm",
        help="Fetch and scan a published npm package by name/version.",
        description=(
            "Download a published npm package tarball from the registry "
            "and scan it for .map files and sourceMappingURL references.\n\n"
            "Package specifiers:\n"
            "  lodash              (resolves to latest version)\n"
            "  lodash@4.17.21      (specific version)\n"
            "  @babel/core         (scoped package, latest)\n"
            "  @babel/core@7.24.0  (scoped package, specific version)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_npm.add_argument(
        "package",
        metavar="PACKAGE[@VERSION]",
        help="npm package name with optional @version suffix.",
    )
    scan_npm.add_argument(
        "--registry",
        metavar="URL",
        default="https://registry.npmjs.org",
        help="npm registry base URL (default: %(default)s).",
    )
    scan_npm.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=60.0,
        help="HTTP request timeout in seconds (default: %(default)s).",
    )

    return parser


def cmd_scan_dir(args: argparse.Namespace) -> int:
    """Execute the scan-dir subcommand.

    Scans a local directory recursively for .map files and sourceMappingURL
    references in JavaScript/TypeScript bundle files.

    Args:
        args: Parsed CLI arguments containing:
            - args.directory: Path to the directory to scan.
            - args.label: Optional human-readable label.

    Returns:
        int: Exit code (0 = no high-risk findings, 1 = findings above threshold,
            3 = fatal error).
    """
    from mapguard.scanner import Scanner

    directory = Path(args.directory)
    scanner = Scanner()

    try:
        result = scanner.scan_directory(directory, source_label=args.label)
    except FileNotFoundError as exc:
        _print_error(str(exc), args)
        return _EXIT_ERROR
    except NotADirectoryError as exc:
        _print_error(str(exc), args)
        return _EXIT_ERROR
    except PermissionError as exc:
        _print_error(f"Permission denied accessing directory: {exc}", args)
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _print_error(f"Unexpected error during scan: {exc}", args)
        return _EXIT_ERROR

    return _handle_result(result, args)


def cmd_scan_tarball(args: argparse.Namespace) -> int:
    """Execute the scan-tarball subcommand.

    Extracts a .tgz tarball to a temporary directory and scans its contents
    for .map files and sourceMappingURL references.

    Args:
        args: Parsed CLI arguments containing:
            - args.tarball: Path to the tarball file.
            - args.label: Optional human-readable label.

    Returns:
        int: Exit code.
    """
    from mapguard.scanner import Scanner

    tarball = Path(args.tarball)
    scanner = Scanner()

    try:
        result = scanner.scan_tarball(tarball, source_label=args.label)
    except FileNotFoundError as exc:
        _print_error(str(exc), args)
        return _EXIT_ERROR
    except tarfile.TarError as exc:
        _print_error(f"Failed to read tarball: {exc}", args)
        return _EXIT_ERROR
    except PermissionError as exc:
        _print_error(f"Permission denied reading tarball: {exc}", args)
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _print_error(f"Unexpected error during scan: {exc}", args)
        return _EXIT_ERROR

    return _handle_result(result, args)


def cmd_scan_npm(args: argparse.Namespace) -> int:
    """Execute the scan-npm subcommand.

    Downloads the package tarball from the npm registry, then scans it for
    .map files and sourceMappingURL references.

    Args:
        args: Parsed CLI arguments containing:
            - args.package: Package specifier (name[@version]).
            - args.registry: Registry base URL.
            - args.timeout: HTTP timeout in seconds.

    Returns:
        int: Exit code.
    """
    import tempfile

    from mapguard.npm_fetcher import NpmFetchError, NpmFetcher
    from mapguard.scanner import Scanner

    fetcher = NpmFetcher(registry=args.registry, timeout=args.timeout)

    if not args.json_output:
        _print_status(f"Fetching {args.package!r} from {args.registry} ...", args)

    try:
        with tempfile.TemporaryDirectory(prefix="mapguard_npm_") as tmpdir:
            try:
                tarball_path = fetcher.fetch(args.package, dest_dir=tmpdir)
            except NpmFetchError as exc:
                _print_error(str(exc), args)
                return _EXIT_ERROR

            if not args.json_output:
                _print_status(f"Scanning {tarball_path.name} ...", args)

            scanner = Scanner()
            try:
                result = scanner.scan_tarball(
                    tarball_path,
                    source_label=args.package,
                )
            except FileNotFoundError as exc:
                _print_error(str(exc), args)
                return _EXIT_ERROR
            except tarfile.TarError as exc:
                _print_error(f"Failed to read downloaded tarball: {exc}", args)
                return _EXIT_ERROR
            except Exception as exc:  # noqa: BLE001
                _print_error(f"Unexpected error during scan: {exc}", args)
                return _EXIT_ERROR

            return _handle_result(result, args)

    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        _print_error(f"Unexpected error: {exc}", args)
        return _EXIT_ERROR


def _handle_result(result: object, args: argparse.Namespace) -> int:
    """Render the scan result and return the appropriate exit code.

    Delegates to the reporter for output (rich terminal or JSON), collects
    remediation advice when applicable, and computes the exit code based on
    whether any findings meet or exceed the configured minimum risk level.

    Args:
        result: A ScanResult object produced by the scanner.
        args: Parsed CLI arguments used for output mode and threshold settings.

    Returns:
        int: 0 if no findings at or above min_risk, 1 otherwise.
    """
    from mapguard.models import ScanResult
    from mapguard.remediation import RemediationAdvisor
    from mapguard.reporter import Reporter
    from mapguard.risk import RiskLevel

    if not isinstance(result, ScanResult):  # pragma: no cover
        _print_error("Internal error: unexpected result type.", args)
        return _EXIT_ERROR

    min_risk = RiskLevel(args.min_risk)
    use_color = not (args.no_color or args.json_output)

    if args.json_output:
        reporter = Reporter(use_color=False)
        reporter.print_json(result)
    else:
        reporter = Reporter(use_color=use_color)
        advice = []
        if not args.no_remediation and result.has_findings:
            advisor = RemediationAdvisor()
            advice = advisor.advise(result.findings)
        reporter.print_rich(result, advice=advice if not args.no_remediation else None)

        # Print any non-fatal errors encountered during scanning
        if result.scan_errors:
            _print_scan_errors(result.scan_errors, use_color)

    # Determine exit code based on min_risk threshold
    if result.max_risk is not None and result.max_risk >= min_risk:
        return _EXIT_FINDINGS
    return _EXIT_OK


def _print_error(
    message: str,
    args: Optional[argparse.Namespace] = None,
) -> None:
    """Print an error message to stderr, or a JSON error object to stdout.

    When the `--json` flag is active, writes a structured JSON error object to
    stdout so that automated consumers always receive valid JSON.  Otherwise,
    writes a plain text message to stderr.

    Args:
        message: The error message string.
        args: Parsed CLI arguments, used to check whether JSON mode is active.
    """
    import json as _json

    if args is not None and getattr(args, "json_output", False):
        error_obj = {"error": message}
        sys.stdout.write(_json.dumps(error_obj, indent=2))
        sys.stdout.write("\n")
    else:
        sys.stderr.write(f"[mapguard] error: {message}\n")


def _print_status(
    message: str,
    args: Optional[argparse.Namespace] = None,  # noqa: ARG001
) -> None:
    """Print a status/progress message to stderr.

    Progress messages are always written to stderr so they do not interfere
    with stdout output (which may be JSON being piped to another tool).

    Args:
        message: The status message to display.
        args: Parsed CLI arguments (reserved for future use).
    """
    sys.stderr.write(f"[mapguard] {message}\n")


def _print_scan_errors(errors: list[str], use_color: bool) -> None:
    """Print non-fatal scan errors encountered during file processing.

    Errors are written to stderr using rich formatting (if colour is enabled)
    so they stand out visually without polluting the main output stream.

    Args:
        errors: List of error message strings recorded during the scan.
        use_color: Whether to use rich colour/style codes.
    """
    from rich.console import Console

    console = Console(
        stderr=True,
        highlight=False,
        markup=True,
        force_terminal=use_color or None,
    )
    console.print(
        f"[bold yellow]⚠  {len(errors)} scan error(s) encountered:[/bold yellow]"
    )
    for err in errors:
        console.print(f"  [dim]• {err}[/dim]")


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the mapguard CLI.

    Parses command-line arguments, dispatches to the appropriate subcommand
    handler, and returns a numeric exit code.

    Args:
        argv: Optional list of argument strings.  Defaults to ``sys.argv[1:]``
            when ``None``.

    Returns:
        int: Exit code:
            0 = scan passed (no findings above threshold),
            1 = scan found issues above threshold,
            2 = argument/usage error,
            3 = fatal runtime error.
    """
    parser = build_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse calls sys.exit(2) on argument errors; propagate cleanly.
        return int(exc.code) if exc.code is not None else _EXIT_USAGE

    dispatch = {
        "scan-dir": cmd_scan_dir,
        "scan-tarball": cmd_scan_tarball,
        "scan-npm": cmd_scan_npm,
    }

    handler = dispatch.get(args.command)
    if handler is None:  # pragma: no cover
        parser.print_help(sys.stderr)
        return _EXIT_USAGE

    try:
        return handler(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[mapguard] Interrupted by user.\n")
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _print_error(f"Unhandled exception: {exc}", args)
        return _EXIT_ERROR


def entrypoint() -> None:
    """Console script entry point that calls :func:`main` and invokes sys.exit.

    This function is referenced by the ``[project.scripts]`` entry in
    ``pyproject.toml``:

    .. code-block:: toml

        [project.scripts]
        mapguard = "mapguard.cli:entrypoint"

    It simply delegates to :func:`main` and passes the return value to
    ``sys.exit`` so the shell receives the correct exit code.
    """
    sys.exit(main())


if __name__ == "__main__":
    entrypoint()
