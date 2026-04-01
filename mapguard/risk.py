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
        LOW: Map file present but no meaningful source information exposed.
        MEDIUM: Map file references source file paths but contains no embedded code.
        HIGH: Multiple source files referenced, sensitive paths detected, or
            an inline data URL source map is present without confirmed content.
        CRITICAL: Embedded source content (sourcesContent) is present in the map,
            exposing actual original source code.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    # ------------------------------------------------------------------
    # Ordering support — required for sorting, min/max, and comparisons
    # ------------------------------------------------------------------

    @staticmethod
    def _order(value: str) -> int:
        """Return the integer order index for a risk level value string."""
        return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(value)

    def __lt__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        """Return True if this level is less severe than *other*."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self._order(self.value) < self._order(other.value)

    def __le__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        """Return True if this level is less than or equal in severity to *other*."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self._order(self.value) <= self._order(other.value)

    def __gt__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        """Return True if this level is more severe than *other*."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self._order(self.value) > self._order(other.value)

    def __ge__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        """Return True if this level is greater than or equal in severity to *other*."""
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self._order(self.value) >= self._order(other.value)


# ---------------------------------------------------------------------------
# Sensitive path patterns
# ---------------------------------------------------------------------------
# These patterns, when found in the source file paths listed in a source map,
# indicate that the map exposes internal implementation details beyond what is
# normal for a published package.

_SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    # Common source directories
    re.compile(r"(?:^|/)src/", re.IGNORECASE),
    re.compile(r"(?:^|/)lib/", re.IGNORECASE),
    re.compile(r"(?:^|/)internal/", re.IGNORECASE),
    re.compile(r"(?:^|/)private/", re.IGNORECASE),
    # Secret / credential related names
    re.compile(r"\bsecret\b", re.IGNORECASE),
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\btoken\b", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\b", re.IGNORECASE),
    re.compile(r"\bcredential", re.IGNORECASE),
    # TypeScript source files (usually not intended in published artefacts)
    re.compile(r"\.tsx?$", re.IGNORECASE),
    # Webpack virtual filesystem prefix
    re.compile(r"webpack://"),
    # User home directory paths that indicate absolute paths leaked
    re.compile(r"/home/[^/]"),
    re.compile(r"/Users/[^/]"),
    re.compile(r"[A-Za-z]:\\\\Users\\\\"),
    re.compile(r"[A-Za-z]:/Users/"),
    # node_modules references (unusual to see in sources array)
    re.compile(r"node_modules"),
]

# If this many or more source file paths are referenced the risk escalates to HIGH.
_HIGH_FILE_COUNT_THRESHOLD: int = 5


class RiskScorer:
    """Scores source map findings using a rule-based priority system.

    The scoring rules are applied in strict priority order so that the most
    severe applicable rule wins:

    1. **CRITICAL** — ``sourcesContent`` array contains embedded source code.
    2. **CRITICAL** — inline data: URL whose decoded payload has embedded content.
    3. **HIGH** — inline data: URL (embedded map present even without confirmed content).
    4. **HIGH** — one or more source paths match a sensitive pattern.
    5. **HIGH** — the number of referenced source files meets or exceeds
       ``_HIGH_FILE_COUNT_THRESHOLD``.
    6. **MEDIUM** — source file paths are listed (but no embedded content).
    7. **MEDIUM** — sourceMappingURL points to an external file.
    8. **LOW** — .map file present but no actionable source information found.
    """

    def score(self, analysis: "AnalysisResult") -> RiskLevel:
        """Compute the risk level for a given AnalysisResult.

        Args:
            analysis: AnalysisResult produced by SourceMapAnalyzer.

        Returns:
            RiskLevel: The computed risk severity level.
        """
        # ------------------------------------------------------------------
        # CRITICAL: embedded source content present (highest priority)
        # ------------------------------------------------------------------
        if analysis.has_embedded_content and analysis.embedded_content_count > 0:
            return RiskLevel.CRITICAL

        # ------------------------------------------------------------------
        # HIGH: data URL — even without confirmed sourcesContent the entire
        # source map is inlined in the bundle which is a significant exposure.
        # ------------------------------------------------------------------
        if analysis.is_data_url:
            return RiskLevel.HIGH

        # ------------------------------------------------------------------
        # Check source file paths for sensitive patterns
        # ------------------------------------------------------------------
        has_sensitive = self._has_sensitive_paths(analysis.source_file_paths)

        if has_sensitive:
            return RiskLevel.HIGH

        # HIGH: large number of source files referenced
        if len(analysis.source_file_paths) >= _HIGH_FILE_COUNT_THRESHOLD:
            return RiskLevel.HIGH

        # ------------------------------------------------------------------
        # MEDIUM: source paths referenced without embedded content
        # ------------------------------------------------------------------
        if analysis.source_file_paths:
            return RiskLevel.MEDIUM

        # MEDIUM: external map file referenced from a bundle
        if analysis.is_external_reference:
            return RiskLevel.MEDIUM

        # ------------------------------------------------------------------
        # LOW: map file present but no meaningful info exposed
        # ------------------------------------------------------------------
        return RiskLevel.LOW

    def _has_sensitive_paths(self, paths: list[str]) -> bool:
        """Return True if any path in *paths* matches a sensitive pattern.

        Args:
            paths: List of source file paths from the source map's sources array.

        Returns:
            bool: True if any path matches at least one sensitive pattern.
        """
        for path in paths:
            for pattern in _SENSITIVE_PATH_PATTERNS:
                if pattern.search(path):
                    return True
        return False
