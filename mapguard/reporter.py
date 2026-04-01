"""Results reporter for mapguard.

Formats and prints scan results as a rich terminal table with color-coded risk
badges and remediation advice, or as plain JSON for CI integration.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from mapguard.models import Finding, ScanResult
    from mapguard.risk import RiskLevel
    from mapguard.remediation import RemediationAdvice


# ---------------------------------------------------------------------------
# Risk level display configuration
# ---------------------------------------------------------------------------

# Rich markup styles for each risk level badge.
_RISK_STYLES: dict[str, str] = {
    "LOW": "bold green",
    "MEDIUM": "bold yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}

# Emoji / symbol prefix for each risk level in the badge.
_RISK_SYMBOLS: dict[str, str] = {
    "LOW": "●",
    "MEDIUM": "▲",
    "HIGH": "✖",
    "CRITICAL": "‼",
}


def _risk_badge(risk_value: str) -> Text:
    """Return a rich :class:`~rich.text.Text` badge for a risk level string.

    Args:
        risk_value: One of ``'LOW'``, ``'MEDIUM'``, ``'HIGH'``, or
            ``'CRITICAL'``.

    Returns:
        Text: Styled rich text object suitable for use in a table cell.
    """
    style = _RISK_STYLES.get(risk_value, "white")
    symbol = _RISK_SYMBOLS.get(risk_value, "?")
    label = f" {symbol} {risk_value} "
    return Text(label, style=style)


def _finding_type_label(finding_type_value: str) -> str:
    """Return a human-friendly label for a FindingType value string.

    Args:
        finding_type_value: The ``.value`` string of a FindingType member.

    Returns:
        str: A short, readable label.
    """
    mapping = {
        "MAP_FILE": ".map file",
        "SOURCE_MAPPING_URL": "sourceMappingURL",
    }
    return mapping.get(finding_type_value, finding_type_value)


def _truncate(text: str, max_len: int = 60) -> str:
    """Truncate *text* to *max_len* characters, appending '…' if shortened.

    Args:
        text: The string to truncate.
        max_len: Maximum number of characters to allow.

    Returns:
        str: Possibly truncated string.
    """
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


class Reporter:
    """Formats and renders scan results to a terminal or JSON stream.

    Supports two output modes:

    * **Rich terminal** (default): colour-coded table with risk badges,
      finding details, and a remediation advice section.
    * **JSON**: machine-readable output suitable for CI integration,
      written to *stdout* as a single JSON object.

    Args:
        console: Optional :class:`~rich.console.Console` instance.  A new
            one targeting *stdout* is created if not provided.
        use_color: When ``False``, colour and emoji output is suppressed
            (useful for non-TTY environments when not using ``--json``).

    Example::

        reporter = Reporter()
        reporter.print_rich(scan_result, advice_list)
        # or
        reporter.print_json(scan_result)
    """

    def __init__(
        self,
        console: Optional[Console] = None,
        use_color: bool = True,
    ) -> None:
        """Initialise the Reporter.

        Args:
            console: Optional rich Console to write to.  Defaults to a new
                Console targeting stdout.
            use_color: Whether to emit colour/style codes.  Set to False for
                plain text output.
        """
        if console is not None:
            self._console = console
        else:
            self._console = Console(
                highlight=False,
                markup=True,
                force_terminal=use_color or None,
            )
        self._use_color = use_color

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def print_rich(
        self,
        result: "ScanResult",
        advice: Optional[list["RemediationAdvice"]] = None,
    ) -> None:
        """Print a rich terminal report for *result*.

        Renders a header panel, a findings table with colour-coded risk
        badges, a summary line, and (optionally) a remediation advice
        section.

        Args:
            result: The :class:`~mapguard.models.ScanResult` to display.
            advice: Optional list of
                :class:`~mapguard.remediation.RemediationAdvice` items to
                display after the findings table.
        """
        self._print_header(result)

        if not result.has_findings:
            self._console.print(
                "[bold green]✔  No source map issues detected.[/bold green]\n"
            )
            return

        self._print_findings_table(result)
        self._print_summary(result)

        if advice:
            self._print_remediation(advice)

        self._console.print()

    def print_json(
        self,
        result: "ScanResult",
        file: object = None,
    ) -> None:
        """Print the scan result as a JSON object to *file* (default: stdout).

        The JSON schema mirrors :meth:`~mapguard.models.ScanResult.to_dict`.
        Output is written as a single formatted JSON blob followed by a
        newline.

        Args:
            result: The :class:`~mapguard.models.ScanResult` to serialise.
            file: File-like object to write to.  Defaults to ``sys.stdout``.
        """
        out = file if file is not None else sys.stdout
        data = result.to_dict()
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        out.write(json_str)
        out.write("\n")

    # ------------------------------------------------------------------
    # Private rendering helpers
    # ------------------------------------------------------------------

    def _print_header(self, result: "ScanResult") -> None:
        """Print a header panel showing the scan source and overall risk.

        Args:
            result: The scan result to summarise in the header.
        """
        max_risk = result.max_risk
        if max_risk is not None:
            risk_val = max_risk.value
            risk_style = _RISK_STYLES.get(risk_val, "white")
            risk_text = _risk_badge(risk_val)
            subtitle = Text.assemble("Overall risk: ", risk_text)
        else:
            subtitle = Text("No findings", style="green")

        source_text = Text(result.source, style="bold cyan")
        title_text = Text.assemble("[bold]mapguard[/bold] scan — ", source_text)

        header_content = Text.assemble(
            "Scanned: ",
            Text(result.source, style="cyan"),
            "\n",
            "Findings: ",
            Text(str(len(result.findings)), style="bold"),
            "  │  ",
            subtitle,
        )

        panel = Panel(
            header_content,
            title="[bold blue]mapguard[/bold blue]",
            border_style="blue",
            padding=(0, 1),
        )
        self._console.print(panel)
        self._console.print()

    def _print_findings_table(self, result: "ScanResult") -> None:
        """Render the findings as a rich table.

        Columns: Risk | Type | File | Details

        Rows are sorted by descending risk level so CRITICAL findings
        appear first.

        Args:
            result: The scan result whose findings to render.
        """
        table = Table(
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold bright_white",
            show_lines=True,
            expand=False,
        )

        table.add_column("Risk", justify="center", no_wrap=True, min_width=12)
        table.add_column("Type", no_wrap=True, min_width=16)
        table.add_column("File", no_wrap=False, min_width=20, max_width=55)
        table.add_column("Details", no_wrap=False, min_width=25)

        # Sort findings: CRITICAL first, then HIGH, MEDIUM, LOW.
        sorted_findings = sorted(
            result.findings,
            key=lambda f: f.risk_level,
            reverse=True,
        )

        for finding in sorted_findings:
            risk_val = finding.risk_level.value
            badge = _risk_badge(risk_val)
            type_label = _finding_type_label(finding.finding_type.value)
            file_text = Text(_truncate(finding.file_path, 55), style="cyan")
            details = self._build_details_text(finding)

            table.add_row(badge, type_label, file_text, details)

        self._console.print(table)
        self._console.print()

    def _build_details_text(self, finding: "Finding") -> Text:
        """Build a multi-line :class:`~rich.text.Text` cell for the Details column.

        Args:
            finding: The finding to describe.

        Returns:
            Text: Rich text with analysis details.
        """
        parts: list[tuple[str, str]] = []  # (text, style)

        analysis = finding.analysis

        if analysis.parse_error:
            parts.append((f"Parse error: {_truncate(analysis.parse_error, 50)}", "dim red"))
        else:
            # Embedded source content
            if analysis.has_embedded_content:
                count = analysis.embedded_content_count
                parts.append((
                    f"⚠ {count} embedded source file(s)",
                    "bold red",
                ))

            # Source file paths
            path_count = len(analysis.source_file_paths)
            if path_count > 0:
                parts.append((
                    f"{path_count} source path(s) referenced",
                    "yellow" if not analysis.has_embedded_content else "dim",
                ))
                # Show up to 3 example paths
                for p in analysis.source_file_paths[:3]:
                    parts.append((f"  · {_truncate(p, 45)}", "dim cyan"))
                if path_count > 3:
                    parts.append((
                        f"  … and {path_count - 3} more",
                        "dim",
                    ))

            # Data URL
            if analysis.is_data_url:
                parts.append(("⚠ Inline data: URL (embedded map)", "bold magenta"))

            # External reference
            if analysis.is_external_reference and finding.referenced_map_url:
                parts.append((
                    f"→ {_truncate(finding.referenced_map_url, 45)}",
                    "dim",
                ))

            # Source root
            if analysis.source_root:
                parts.append((
                    f"root: {_truncate(analysis.source_root, 40)}",
                    "dim",
                ))

            # Raw size
            if analysis.raw_size_bytes > 0:
                size_kb = analysis.raw_size_bytes / 1024
                parts.append((f"size: {size_kb:.1f} KB", "dim"))

        if not parts:
            parts.append(("No additional details", "dim"))

        text = Text()
        for i, (label, style) in enumerate(parts):
            if i > 0:
                text.append("\n")
            text.append(label, style=style)

        return text

    def _print_summary(self, result: "ScanResult") -> None:
        """Print a one-line summary of finding counts by risk level.

        Args:
            result: The scan result to summarise.
        """
        parts: list = []

        if result.critical_count:
            parts.append(
                Text(f" {result.critical_count} CRITICAL ", style=_RISK_STYLES["CRITICAL"])
            )
        if result.high_count:
            parts.append(
                Text(f" {result.high_count} HIGH ", style=_RISK_STYLES["HIGH"])
            )
        if result.medium_count:
            parts.append(
                Text(f" {result.medium_count} MEDIUM ", style=_RISK_STYLES["MEDIUM"])
            )
        if result.low_count:
            parts.append(
                Text(f" {result.low_count} LOW ", style=_RISK_STYLES["LOW"])
            )

        summary = Text("Summary: ")
        for i, badge in enumerate(parts):
            if i > 0:
                summary.append("  ")
            summary.append_text(badge)

        self._console.print(summary)
        self._console.print()

    def _print_remediation(
        self,
        advice: list["RemediationAdvice"],
    ) -> None:
        """Print a remediation advice section below the findings table.

        Each advice item is rendered as a titled panel containing the
        description and an optional code snippet.

        Args:
            advice: Ordered list of RemediationAdvice items to display.
        """
        self._console.print(Rule("[bold yellow]Remediation Advice[/bold yellow]", style="yellow"))
        self._console.print()

        for i, item in enumerate(advice, start=1):
            # Build the panel content
            content_parts: list[Text | str] = []

            desc = Text(item.description, style="white")
            content_parts.append(desc)

            if item.code_snippet:
                content_parts.append(Text("\n"))
                snippet_label = Text("Example:", style="bold dim")
                content_parts.append(snippet_label)
                content_parts.append(Text("\n"))
                snippet = Text(item.code_snippet, style="dim cyan")
                content_parts.append(snippet)

            combined = Text()
            for part in content_parts:
                if isinstance(part, str):
                    combined.append(part)
                else:
                    combined.append_text(part)

            panel = Panel(
                combined,
                title=f"[bold yellow]{i}. {item.title}[/bold yellow]",
                border_style="yellow",
                padding=(0, 1),
            )
            self._console.print(panel)

        self._console.print()

    def _print_errors(self, result: "ScanResult") -> None:
        """Print any scan errors recorded during the scan.

        Args:
            result: The scan result whose errors to display.
        """
        if not result.scan_errors:
            return
        self._console.print(
            f"[bold red]Scan encountered {len(result.scan_errors)} error(s):[/bold red]"
        )
        for err in result.scan_errors:
            self._console.print(f"  [dim red]• {err}[/dim red]")
        self._console.print()
