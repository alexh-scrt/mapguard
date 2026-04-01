"""Risk scoring engine for mapguard.

Assigns a risk level (LOW/MEDIUM/HIGH/CRITICAL) to source map findings based
on presence of embedded source content, number of exposed source files,
sensitive path patterns, and other heuristics.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mapguard.analyzer import AnalysisResult


class RiskLevel(Enum):
    """Risk severity levels for source map findings.

    Attributes:
        LOW: Map file present but no source content exposed.
        MEDIUM: Map file references source file paths but no content.
        HIGH: Multiple source files referenced or sensitive paths detected.
        CRITICAL: Embedded source content (sourcesContent) is present.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "RiskLevel") -> bool:
        """Enable ordering of risk levels by severity."""
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) < order.index(other.value)

    def __le__(self, other: "RiskLevel") -> bool:
        """Enable ordering of risk levels by severity."""
        return self == other or self < other

    def __gt__(self, other: "RiskLevel") -> bool:
        """Enable ordering of risk levels by severity."""
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        return order.index(self.value) > order.index(other.value)

    def __ge__(self, other: "RiskLevel") -> bool:
        """Enable ordering of risk levels by severity."""
        return self == other or self > other


# Patterns that suggest sensitive internal paths
_SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsrc/", re.IGNORECASE),
    re.compile(r"\blib/", re.IGNORECASE),
    re.compile(r"\binternal/", re.IGNORECASE),
    re.compile(r"\bprivate/", re.IGNORECASE),
    re.compile(r"\bsecret", re.IGNORECASE),
    re.compile(r"\bpassword", re.IGNORECASE),
    re.compile(r"\btoken", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key", re.IGNORECASE),
    re.compile(r"\.ts$"),
    re.compile(r"\.tsx$"),
    re.compile(r"webpack://"),
    re.compile(r"node_modules"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"C:\\\\Users\\\\"),
]

# Threshold: number of source file references to escalate from MEDIUM to HIGH
_HIGH_FILE_COUNT_THRESHOLD = 5


class RiskScorer:
    """Scores findings based on source map analysis results.

    Uses a rule-based approach to determine risk level from an AnalysisResult
    produced by the SourceMapAnalyzer.
    """

    def score(self, analysis: "AnalysisResult") -> RiskLevel:
        """Compute the risk level for a given analysis result.

        Scoring rules (applied in priority order):
        1. CRITICAL - sourcesContent array is present with embedded code.
        2. HIGH - data: URL (inline map) OR >= threshold source files referenced
           OR sensitive path patterns detected.
        3. MEDIUM - source file paths are referenced without embedded content.
        4. LOW - .map file present but no actionable source info found.

        Args:
            analysis: AnalysisResult from SourceMapAnalyzer.

        Returns:
            RiskLevel: The computed risk level.
        """
        # CRITICAL: embedded source content present
        if analysis.has_embedded_content and analysis.embedded_content_count > 0:
            return RiskLevel.CRITICAL

        # CRITICAL: inline data URL with embedded map
        if analysis.is_data_url and analysis.has_embedded_content:
            return RiskLevel.CRITICAL

        # HIGH: data URL (even without verified content, the map is inlined)
        if analysis.is_data_url:
            return RiskLevel.HIGH

        # Check for sensitive path patterns
        has_sensitive_paths = self._has_sensitive_paths(analysis.source_file_paths)

        # HIGH: sensitive paths detected
        if has_sensitive_paths:
            return RiskLevel.HIGH

        # HIGH: large number of source files referenced
        if len(analysis.source_file_paths) >= _HIGH_FILE_COUNT_THRESHOLD:
            return RiskLevel.HIGH

        # MEDIUM: source file paths referenced
        if analysis.source_file_paths:
            return RiskLevel.MEDIUM

        # MEDIUM: external map file referenced from a bundle
        if analysis.is_external_reference:
            return RiskLevel.MEDIUM

        # LOW: map file present but minimal information exposed
        return RiskLevel.LOW

    def _has_sensitive_paths(self, paths: list[str]) -> bool:
        """Check whether any source path matches a sensitive pattern.

        Args:
            paths: List of source file paths from the source map.

        Returns:
            bool: True if any path matches a known sensitive pattern.
        """
        for path in paths:
            for pattern in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    return True
        return False
