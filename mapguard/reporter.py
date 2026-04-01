"""Results reporter for mapguard.

Formats and prints scan results as a rich terminal table with color-coded risk
badges and remediation advice, or as plain JSON for CI integration.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

if TYPE_CHECKING:
    from mapguard.models import ScanResult, Finding  # type: ignore[import]
    from mapguard.risk import RiskLevel


# ANSI/rich styles for each risk level
_RISK_STYLES: dict[str, str] = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}

_RISK_EMOJIS: dict[str, str] = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🔴",
    "CRITICAL": "💀",
}


class Reporter:
    """Renders scan results to the terminal or as JSON.

    Attributes:
        use_json: If True, output is emitted as JSON.
        no_color: If True, rich color output is disabled.
        console: Rich Console instance used for rendering.
    """

    def __init__(
        self,
        use_json: bool = False,
        no_color: bool = False,
        file: Optional[object] = None,
    ) -> None:
        """Initialize the Reporter.

        Args:
            use_json: Output results as JSON instead of a rich table.
            no_color: Disable colored output.
            file: Output stream (defaults to stdout).
        """
        self.use_json = use_json
        self.no_color = no_color
        self.console = Console(
            no_color=no_color,
            highlight=False,
            file=file or sys.stdout,
        )

    def report(
        self,
        result: "ScanResult",
        min_risk: str = "LOW",
    ) -> None:
        """Render the scan result to the configured output.

        Args:
            result: ScanResult containing all findings.
            min_risk: Minimum risk level string to include in output.
        """
        if self.use_json:
            self._report_json(result, min_risk)
        else:
            self._report_rich(result, min_risk)

    def _filter_findings(
        self, result: "ScanResult", min_risk: str
    ) -> list["Finding"]:
        """Filter findings by minimum risk level.

        Args:
            result: ScanResult with all findings.
            min_risk: Minimum risk level string.

        Returns:
            list[Finding]: Findings at or above the minimum risk level.
        """
        from mapguard.risk import RiskLevel  # type: ignore[import]

        try:
            min_level = RiskLevel(min_risk)
        except ValueError:
            min_level = RiskLevel.LOW

        return [
            f for f in result.findings if f.risk_level >= min_level
        ]

    def _report_rich(
        self, result: "ScanResult", min_risk: str = "LOW"
    ) -> None:
        """Render findings as a rich terminal table.

        Args:
            result: ScanResult with all findings.
            min_risk: Minimum risk level to show.
        """
        from mapguard.remediation import RemediationAdvisor  # type: ignore[import]

        findings = self._filter_findings(result, min_risk)

        self.console.print()
        self.console.print(
            f"[bold]mapguard[/bold] scan results for [cyan]{result.source}[/cyan]"
        )
        self.console.print(
            f"Total findings: [bold]{len(result.findings)}[/bold] "
            f"(showing {len(findings)} at {min_risk}+)"
        )
        self.console.print()

        if not findings:
            self.console.print("[green]✓ No source map issues found at this risk level.[/green]")
            self.console.print()
            return

        table = Table(
            title=f"Source Map Findings — {result.source}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            expand=True,
        )
        table.add_column("Risk", width=12, justify="center")
        table.add_column("File", overflow="fold")
        table.add_column("Type", width=24)
        table.add_column("Details", overflow="fold")

        for finding in sorted(findings, key=lambda f: f.risk_level, reverse=True):
            risk_str = finding.risk_level.value
            style = _RISK_STYLES.get(risk_str, "white")
            emoji = _RISK_EMOJIS.get(risk_str, "")
            risk_cell = Text(f"{emoji} {risk_str}", style=style)
            details = self._format_details(finding)
            table.add_row(
                risk_cell,
                finding.file_path,
                finding.finding_type.value,
                details,
            )

        self.console.print(table)
        self.console.print()

        # Print remediation advice
        advisor = RemediationAdvisor()
        remediations = advisor.advise_all(findings)
        if remediations:
            self.console.print("[bold yellow]Remediation Recommendations:[/bold yellow]")
            for i, advice in enumerate(remediations, 1):
                self.console.print(f"[bold]{i}.[/bold] {advice.title}")
                self.console.print(f"   [dim]{advice.description}[/dim]")
                if advice.code_snippet:
                    self.console.print(f"   [green]{advice.code_snippet}[/green]")
                self.console.print()

    def _report_json(
        self, result: "ScanResult", min_risk: str = "LOW"
    ) -> None:
        """Render findings as JSON to stdout.

        Args:
            result: ScanResult with all findings.
            min_risk: Minimum risk level to include.
        """
        findings = self._filter_findings(result, min_risk)
        output = {
            "source": result.source,
            "total_findings": len(result.findings),
            "filtered_findings": len(findings),
            "min_risk": min_risk,
            "findings": [
                {
                    "file_path": f.file_path,
                    "finding_type": f.finding_type.value,
                    "risk_level": f.risk_level.value,
                    "referenced_map_url": f.referenced_map_url,
                    "analysis": {
                        "has_embedded_content": f.analysis.has_embedded_content,
                        "embedded_content_count": f.analysis.embedded_content_count,
                        "source_file_paths": f.analysis.source_file_paths,
                        "source_root": f.analysis.source_root,
                        "is_data_url": f.analysis.is_data_url,
                        "is_external_reference": f.analysis.is_external_reference,
                        "parse_error": f.analysis.parse_error,
                        "raw_size_bytes": f.analysis.raw_size_bytes,
                    },
                }
                for f in sorted(findings, key=lambda x: x.risk_level, reverse=True)
            ],
        }
        print(json.dumps(output, indent=2))

    def _format_details(self, finding: "Finding") -> str:
        """Format a human-readable detail string for a finding.

        Args:
            finding: The Finding to summarize.

        Returns:
            str: A short detail string.
        """
        parts: list[str] = []
        a = finding.analysis

        if a.has_embedded_content:
            parts.append(f"{a.embedded_content_count} source file(s) embedded")
        elif a.source_file_paths:
            parts.append(f"{len(a.source_file_paths)} path(s) referenced")

        if a.source_root:
            parts.append(f"sourceRoot: {a.source_root!r}")

        if a.is_data_url:
            parts.append("inline data: URL")

        if a.parse_error:
            parts.append(f"parse error: {a.parse_error}")

        if finding.referenced_map_url and not a.is_data_url:
            url = finding.referenced_map_url
            if len(url) > 60:
                url = url[:57] + "..."
            parts.append(f"→ {url}")

        return "; ".join(parts) if parts else "—"
