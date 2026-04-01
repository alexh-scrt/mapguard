"""Core data models for mapguard.

Defines the shared data structures used throughout the codebase:
- FindingType: Enum describing what kind of source map issue was detected
- Finding: A single detected source map issue with its analysis and risk level
- ScanResult: Aggregated result of scanning a directory, tarball, or npm package

All other modules import from here to ensure a stable type contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mapguard.analyzer import AnalysisResult
    from mapguard.risk import RiskLevel


class FindingType(Enum):
    """Describes the category of a source map finding.

    Attributes:
        MAP_FILE: A .map file was found directly in the scanned package.
        SOURCE_MAPPING_URL: A sourceMappingURL comment was found in a JS/TS bundle
            that references an external or inline source map.
    """

    MAP_FILE = "MAP_FILE"
    SOURCE_MAPPING_URL = "SOURCE_MAPPING_URL"


@dataclass
class Finding:
    """Represents a single detected source map issue.

    A Finding is produced by the scanner for each .map file discovered or each
    sourceMappingURL reference detected in a bundle file. It carries the
    corresponding AnalysisResult and computed RiskLevel.

    Attributes:
        file_path: Path to the file that triggered the finding, relative to the
            scan root.
        finding_type: Whether this is a direct MAP_FILE or a SOURCE_MAPPING_URL
            reference.
        risk_level: Computed severity (LOW/MEDIUM/HIGH/CRITICAL).
        analysis: Detailed AnalysisResult produced by the SourceMapAnalyzer.
        referenced_map_url: For SOURCE_MAPPING_URL findings, the raw URL string
            extracted from the sourceMappingURL comment. None for MAP_FILE findings.
    """

    file_path: str
    finding_type: FindingType
    risk_level: "RiskLevel"
    analysis: "AnalysisResult"
    referenced_map_url: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate the Finding after initialization.

        Raises:
            TypeError: If finding_type is not a FindingType instance.
            ValueError: If file_path is empty.
        """
        if not isinstance(self.finding_type, FindingType):
            raise TypeError(
                f"finding_type must be a FindingType instance, got {type(self.finding_type)!r}"
            )
        if not self.file_path:
            raise ValueError("file_path must not be empty")

    @property
    def is_critical(self) -> bool:
        """Return True if this finding has CRITICAL risk level."""
        from mapguard.risk import RiskLevel
        return self.risk_level == RiskLevel.CRITICAL

    @property
    def is_high_or_above(self) -> bool:
        """Return True if this finding has HIGH or CRITICAL risk level."""
        from mapguard.risk import RiskLevel
        return self.risk_level >= RiskLevel.HIGH

    @property
    def summary(self) -> str:
        """Return a brief one-line summary of the finding.

        Returns:
            str: Human-readable summary string.
        """
        risk = self.risk_level.value
        ftype = self.finding_type.value
        details = []
        if self.analysis.has_embedded_content:
            details.append(
                f"{self.analysis.embedded_content_count} embedded source file(s)"
            )
        elif self.analysis.source_file_paths:
            details.append(
                f"{len(self.analysis.source_file_paths)} source path(s) referenced"
            )
        if self.analysis.is_data_url:
            details.append("inline data URL")
        detail_str = "; ".join(details) if details else "no source content detected"
        return f"[{risk}] {ftype}: {self.file_path} — {detail_str}"


@dataclass
class ScanResult:
    """Aggregated result of a complete scan operation.

    Produced by the Scanner after scanning a directory, tarball, or npm
    package. Contains all raw findings before any filtering by risk level.

    Attributes:
        source: Human-readable label identifying what was scanned (e.g. directory
            path, tarball filename, or npm package specifier).
        findings: All Finding objects collected during the scan, in the order
            they were discovered.
        scan_errors: Non-fatal errors encountered during scanning (e.g. files
            that could not be read). Does not interrupt the scan.
    """

    source: str
    findings: list[Finding] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate the ScanResult after initialization.

        Raises:
            ValueError: If source is empty.
        """
        if not self.source:
            raise ValueError("source must not be empty")

    @property
    def has_findings(self) -> bool:
        """Return True if any findings were collected."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Return the number of CRITICAL findings."""
        from mapguard.risk import RiskLevel
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        """Return the number of HIGH findings."""
        from mapguard.risk import RiskLevel
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        """Return the number of MEDIUM findings."""
        from mapguard.risk import RiskLevel
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        """Return the number of LOW findings."""
        from mapguard.risk import RiskLevel
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW)

    @property
    def max_risk(self) -> Optional["RiskLevel"]:
        """Return the highest risk level found, or None if no findings.

        Returns:
            RiskLevel | None: Highest severity level among all findings, or None.
        """
        if not self.findings:
            return None
        return max(f.risk_level for f in self.findings)

    def findings_at_or_above(self, min_risk: "RiskLevel") -> list[Finding]:
        """Return findings filtered to those at or above the given risk level.

        Args:
            min_risk: Minimum RiskLevel to include.

        Returns:
            list[Finding]: Filtered findings sorted by risk level descending.
        """
        filtered = [f for f in self.findings if f.risk_level >= min_risk]
        return sorted(filtered, key=lambda f: f.risk_level, reverse=True)

    def to_dict(self) -> dict:
        """Serialize the ScanResult to a plain dictionary.

        Suitable for JSON serialization or programmatic inspection.

        Returns:
            dict: Dictionary representation of the scan result.
        """
        return {
            "source": self.source,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "scan_errors": self.scan_errors,
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
                for f in self.findings
            ],
        }
