"""Remediation advisor for mapguard.

Generates context-aware remediation recommendations based on finding type
and risk level. Provides actionable advice such as .npmignore entries,
webpack/rollup configuration changes, and sourceMappingURL stripping commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mapguard.models import Finding
    from mapguard.risk import RiskLevel


@dataclass
class RemediationAdvice:
    """A single remediation recommendation.

    Attributes:
        title: Short title of the recommendation.
        description: Detailed explanation of what to do and why.
        code_snippet: Optional code or command example.
        applies_to: List of finding types this advice applies to (e.g. 'MAP_FILE').
        priority: Lower number means higher priority (1 = most important).
    """

    title: str
    description: str
    code_snippet: Optional[str] = None
    applies_to: list[str] = field(default_factory=list)
    priority: int = 5

    def __str__(self) -> str:
        """Return a human-readable string representation of this advice."""
        parts = [f"[{self.priority}] {self.title}", self.description]
        if self.code_snippet:
            parts.append(self.code_snippet)
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Pre-built advice catalogue
# ---------------------------------------------------------------------------

_ADVICE_NPMIGNORE_MAP_FILES = RemediationAdvice(
    title="Add .map files to .npmignore",
    description=(
        "Prevent source map files from being included in your published npm package "
        "by listing them in a .npmignore file at the root of your project. "
        "This is the simplest and most reliable fix."
    ),
    code_snippet=(
        "# .npmignore\n"
        "**/*.map\n"
        "**/*.js.map\n"
        "**/*.ts.map\n"
        "**/*.css.map"
    ),
    applies_to=["MAP_FILE"],
    priority=1,
)

_ADVICE_PACKAGE_JSON_FILES = RemediationAdvice(
    title="Use the 'files' allowlist in package.json",
    description=(
        "Instead of a .npmignore blocklist, use the 'files' field in package.json "
        "to explicitly list only the files that should be published. This approach "
        "is safer because it defaults to excluding everything not listed."
    ),
    code_snippet=(
        '{\n'
        '  "files": [\n'
        '    "dist/",\n'
        '    "README.md",\n'
        '    "LICENSE"\n'
        '  ]\n'
        '}'
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=2,
)

_ADVICE_WEBPACK_NOSOURCES = RemediationAdvice(
    title="Configure webpack to omit sourcesContent",
    description=(
        "If you need source maps for debugging in production but want to avoid "
        "embedding original source code, configure webpack to use the "
        "'nosources-source-map' devtool option. This produces maps that allow "
        "stack-trace line numbers without exposing source content."
    ),
    code_snippet=(
        "// webpack.config.js\n"
        "module.exports = {\n"
        "  // For production: omit sourcesContent from the map\n"
        "  devtool: 'nosources-source-map',\n"
        "  // Or to disable source maps entirely:\n"
        "  // devtool: false,\n"
        "};"
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=3,
)

_ADVICE_ROLLUP_SOURCEMAP = RemediationAdvice(
    title="Disable source maps or use external-only maps in Rollup",
    description=(
        "In Rollup, disable source map generation entirely for production builds, "
        "or generate external source maps without embedding sourcesContent. "
        "Set sourcemap to false or use the sourcemapExcludeSources plugin option."
    ),
    code_snippet=(
        "// rollup.config.js\n"
        "export default {\n"
        "  output: {\n"
        "    // Disable source maps in production:\n"
        "    sourcemap: false,\n"
        "    // Or generate external maps without embedded source:\n"
        "    // sourcemap: true,\n"
        "    // sourcemapExcludeSources: true,\n"
        "  },\n"
        "};"
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=3,
)

_ADVICE_VITE_SOURCEMAP = RemediationAdvice(
    title="Configure Vite to disable or restrict source maps",
    description=(
        "In Vite, control source map generation via the build.sourcemap option. "
        "Set it to false to disable maps entirely, or to 'hidden' to generate "
        "external maps that are not referenced from the bundle (useful for "
        "private error monitoring)."
    ),
    code_snippet=(
        "// vite.config.ts\n"
        "export default {\n"
        "  build: {\n"
        "    // Disable source maps:\n"
        "    sourcemap: false,\n"
        "    // Or generate hidden external maps (not referenced from bundles):\n"
        "    // sourcemap: 'hidden',\n"
        "  },\n"
        "};"
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=3,
)

_ADVICE_STRIP_SOURCEMAPPING_COMMENT = RemediationAdvice(
    title="Strip sourceMappingURL comments from published bundles",
    description=(
        "Remove sourceMappingURL comments from your JavaScript bundles before "
        "publishing. This prevents consumers from locating or fetching the "
        "corresponding source map file. You can do this with a post-build script."
    ),
    code_snippet=(
        "# Using sed (Unix/macOS):\n"
        "sed -i '' 's|//[#@] sourceMappingURL=.*||g' dist/*.js\n"
        "\n"
        "# Or install the 'strip-map-comments' npm package:\n"
        "npx strip-map-comments dist/*.js\n"
        "\n"
        "# Or use the official Google 'source-map-loader' strip option in webpack."
    ),
    applies_to=["SOURCE_MAPPING_URL"],
    priority=2,
)

_ADVICE_INLINE_DATA_URL = RemediationAdvice(
    title="Remove inline (data: URL) source maps from bundles",
    description=(
        "An inline source map embeds the entire original source code directly "
        "inside your JavaScript bundle as a base64-encoded data: URL comment. "
        "This is the most severe form of source map leak. Disable inline source "
        "maps in your bundler configuration and switch to external maps (or no "
        "maps) for production builds."
    ),
    code_snippet=(
        "// webpack.config.js – replace 'inline-source-map' with a safer option\n"
        "module.exports = {\n"
        "  // Bad (embeds source inline):\n"
        "  // devtool: 'inline-source-map',\n"
        "\n"
        "  // Good (no source maps in production):\n"
        "  devtool: false,\n"
        "\n"
        "  // Or: external maps without sourcesContent:\n"
        "  // devtool: 'nosources-source-map',\n"
        "};"
    ),
    applies_to=["SOURCE_MAPPING_URL"],
    priority=1,
)

_ADVICE_AUDIT_CI = RemediationAdvice(
    title="Add mapguard to your CI pipeline",
    description=(
        "Prevent future accidental source map leaks by adding mapguard to your "
        "CI pipeline. Run it against your build output before publishing to npm. "
        "Use the --json flag for machine-readable output and fail the build on "
        "HIGH or CRITICAL findings."
    ),
    code_snippet=(
        "# In your CI script (e.g., GitHub Actions):\n"
        "mapguard scan-dir ./dist --json | python3 -c \"\n"
        "import json, sys\n"
        "data = json.load(sys.stdin)\n"
        "if data.get('critical', 0) > 0 or data.get('high', 0) > 0:\n"
        "    sys.exit(1)\n"
        "\""
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=5,
)

_ADVICE_SENSITIVE_PATHS = RemediationAdvice(
    title="Review exposed source paths for sensitive information",
    description=(
        "Your source map references file paths that may reveal sensitive internal "
        "project structure (e.g. paths containing 'src/', 'internal/', 'secret', "
        "'token', 'password', absolute home-directory paths, or TypeScript source "
        "files). Even without embedded content, these paths can expose your "
        "project structure to attackers. Review the listed paths and consider "
        "configuring your bundler to anonymise or omit them."
    ),
    code_snippet=(
        "// webpack.config.js – use nosources-source-map to hide path contents,\n"
        "// or configure the output.devtoolModuleFilenameTemplate to sanitise paths:\n"
        "module.exports = {\n"
        "  devtool: 'nosources-source-map',\n"
        "  output: {\n"
        "    devtoolModuleFilenameTemplate: '[resource-path]',\n"
        "  },\n"
        "};"
    ),
    applies_to=["MAP_FILE", "SOURCE_MAPPING_URL"],
    priority=2,
)


class RemediationAdvisor:
    """Generates context-aware remediation advice for source map findings.

    Selects and orders the most relevant recommendations based on the
    type of finding (MAP_FILE vs SOURCE_MAPPING_URL), the risk level,
    and specific analysis attributes such as embedded content presence,
    data URLs, and sensitive path patterns.

    Example usage::

        advisor = RemediationAdvisor()
        findings = scan_result.findings
        advice_list = advisor.advise(findings)
        for advice in advice_list:
            print(advice.title)
    """

    def advise(self, findings: list["Finding"]) -> list[RemediationAdvice]:
        """Return deduplicated, prioritised remediation advice for a list of findings.

        Analyses all provided findings collectively and returns the most
        relevant subset of advice items, deduplicated by title and sorted
        by priority (ascending — 1 is most important).

        Args:
            findings: List of Finding objects from a completed scan.

        Returns:
            list[RemediationAdvice]: Ordered list of unique advice items.
                Returns an empty list if *findings* is empty.
        """
        if not findings:
            return []

        selected: dict[str, RemediationAdvice] = {}

        for finding in findings:
            for advice in self._advise_single(finding):
                if advice.title not in selected:
                    selected[advice.title] = advice

        return sorted(selected.values(), key=lambda a: a.priority)

    def advise_single(self, finding: "Finding") -> list[RemediationAdvice]:
        """Return prioritised remediation advice for a single finding.

        Convenience wrapper around :meth:`advise` for callers that process
        findings individually.

        Args:
            finding: A single Finding object.

        Returns:
            list[RemediationAdvice]: Ordered list of advice items.
        """
        return sorted(self._advise_single(finding), key=lambda a: a.priority)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _advise_single(self, finding: "Finding") -> list[RemediationAdvice]:
        """Generate advice items for a single finding without deduplication.

        Args:
            finding: A single Finding to analyse.

        Returns:
            list[RemediationAdvice]: Applicable advice items (may contain
                duplicates relative to other calls — dedup is the caller's
                responsibility).
        """
        from mapguard.models import FindingType
        from mapguard.risk import RiskLevel

        advice: list[RemediationAdvice] = []
        finding_type = finding.finding_type
        analysis = finding.analysis
        risk = finding.risk_level

        # ---------------------------------------------------------------
        # MAP_FILE specific advice
        # ---------------------------------------------------------------
        if finding_type == FindingType.MAP_FILE:
            # Always recommend excluding map files from the package.
            advice.append(_ADVICE_NPMIGNORE_MAP_FILES)
            advice.append(_ADVICE_PACKAGE_JSON_FILES)

            # If sourcesContent is embedded, recommend bundler config changes.
            if analysis.has_embedded_content and analysis.embedded_content_count > 0:
                advice.append(_ADVICE_WEBPACK_NOSOURCES)
                advice.append(_ADVICE_ROLLUP_SOURCEMAP)
                advice.append(_ADVICE_VITE_SOURCEMAP)

        # ---------------------------------------------------------------
        # SOURCE_MAPPING_URL specific advice
        # ---------------------------------------------------------------
        elif finding_type == FindingType.SOURCE_MAPPING_URL:
            if analysis.is_data_url:
                # Inline data URL — most severe form, prioritise removal.
                advice.append(_ADVICE_INLINE_DATA_URL)
                advice.append(_ADVICE_WEBPACK_NOSOURCES)
                advice.append(_ADVICE_ROLLUP_SOURCEMAP)
                advice.append(_ADVICE_VITE_SOURCEMAP)
            else:
                # External reference — recommend stripping the comment.
                advice.append(_ADVICE_STRIP_SOURCEMAPPING_COMMENT)
                advice.append(_ADVICE_PACKAGE_JSON_FILES)

            if analysis.has_embedded_content:
                advice.append(_ADVICE_WEBPACK_NOSOURCES)

        # ---------------------------------------------------------------
        # Cross-cutting advice based on risk level and analysis content
        # ---------------------------------------------------------------

        # If sensitive paths were found, add specific path remediation.
        if self._has_sensitive_paths(analysis.source_file_paths):
            advice.append(_ADVICE_SENSITIVE_PATHS)

        # For HIGH/CRITICAL findings, recommend adding to CI.
        if risk >= RiskLevel.HIGH:
            advice.append(_ADVICE_AUDIT_CI)

        return advice

    @staticmethod
    def _has_sensitive_paths(paths: list[str]) -> bool:
        """Return True if any path looks like it contains sensitive information.

        Mirrors the logic in :class:`~mapguard.risk.RiskScorer` but kept
        lightweight here to avoid circular imports.

        Args:
            paths: List of source file path strings from the source map.

        Returns:
            bool: True if any path matches a sensitivity heuristic.
        """
        import re

        _PATTERNS = [
            re.compile(r"(?:^|/)src/", re.IGNORECASE),
            re.compile(r"(?:^|/)internal/", re.IGNORECASE),
            re.compile(r"(?:^|/)private/", re.IGNORECASE),
            re.compile(r"\bsecret\b", re.IGNORECASE),
            re.compile(r"\bpassword\b", re.IGNORECASE),
            re.compile(r"\btoken\b", re.IGNORECASE),
            re.compile(r"\bapi[_-]?key\b", re.IGNORECASE),
            re.compile(r"\bcredential", re.IGNORECASE),
            re.compile(r"\.tsx?$", re.IGNORECASE),
            re.compile(r"webpack://"),
            re.compile(r"/home/[^/]"),
            re.compile(r"/Users/[^/]"),
        ]
        for path in paths:
            for pattern in _PATTERNS:
                if pattern.search(path):
                    return True
        return False
