"""Remediation advisor for mapguard.

Generates context-aware remediation recommendations based on finding type
and risk level. Provides actionable advice such as .npmignore entries,
webpack/rollup configuration changes, and sourceMappingURL stripping commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mapguard.models import Finding  # type: ignore[import]


@dataclass
class RemediationAdvice:
    """A single remediation recommendation.

    Attributes:
        title: Short title of the recommendation.
        description: Detailed explanation of what to do and why.
        code_snippet: Optional code or command example.
        applies_to: List of finding types this advice applies to.
    """

    title: str
    description: str
    code_snippet: Optional[str] = None
    applies_to: list[str] = field(default_factory=list)


class RemediationAdvisor:
    """Generates remediation advice for source map findings.

    Produces deduplicated, context-aware recommendations based on the
    types and risk levels of findings discovered during a scan.
    """

    def advise_all(
        self, findings: list["Finding"]
    ) -> list[RemediationAdvice]:
        """Generate all relevant remediation recommendations for a list of findings.

        Deduplicates advice so each recommendation appears at most once
        even if multiple findings of the same type are present.

        Args:
            findings: List of Finding objects from a scan.

        Returns:
            list[RemediationAdvice]: Ordered list of unique recommendations.
        """
        if not findings:
            return []

        from mapguard.models import FindingType  # type: ignore[import]
        from mapguard.risk import RiskLevel  # type: ignore[import]

        seen_titles: set[str] = set()
        advice_list: list[RemediationAdvice] = []

        has_map_files = any(
            f.finding_type == FindingType.MAP_FILE for f in findings
        )
        has_embedded = any(
            f.analysis.has_embedded_content for f in findings
        )
        has_source_mapping_url = any(
            f.finding_type == FindingType.SOURCE_MAPPING_URL for f in findings
        )
        has_data_url = any(
            f.analysis.is_data_url for f in findings
        )
        has_critical = any(
            f.risk_level == RiskLevel.CRITICAL for f in findings
        )

        def _add(advice: RemediationAdvice) -> None:
            if advice.title not in seen_titles:
                seen_titles.add(advice.title)
                advice_list.append(advice)

        # CRITICAL / embedded content advice
        if has_embedded:
            _add(RemediationAdvice(
                title="Disable sourcesContent in your bundler",
                description=(
                    "Your source maps contain embedded source code (sourcesContent). "
                    "Configure your bundler to omit sourcesContent from production builds."
                ),
                code_snippet=(
                    "# Webpack (webpack.config.js):\n"
                    "devtool: 'source-map',  // generates external .map without sourcesContent\n"
                    "# Or for no source maps in production:\n"
                    "devtool: false"
                ),
                applies_to=[FindingType.MAP_FILE.value],
            ))

        # Map files in package advice
        if has_map_files:
            _add(RemediationAdvice(
                title="Add .map files to .npmignore",
                description=(
                    "Source map files (.map) are included in your published npm package. "
                    "Add them to .npmignore to prevent them from being published."
                ),
                code_snippet=(
                    "# Add to .npmignore:\n"
                    "*.map\n"
                    "**/*.map"
                ),
                applies_to=[FindingType.MAP_FILE.value],
            ))

            _add(RemediationAdvice(
                title="Use 'files' in package.json to allowlist published files",
                description=(
                    "Instead of a denylist (.npmignore), use the 'files' field in package.json "
                    "to explicitly allowlist only the files that should be published."
                ),
                code_snippet=(
                    "// package.json\n"
                    "{\n"
                    '  "files": ["dist/**/*.js", "dist/**/*.d.ts", "README.md"]\n'
                    "}"
                ),
                applies_to=[FindingType.MAP_FILE.value],
            ))

        # sourceMappingURL in bundles
        if has_source_mapping_url and not has_data_url:
            _add(RemediationAdvice(
                title="Strip sourceMappingURL comments from production bundles",
                description=(
                    "Your bundles contain sourceMappingURL comments that reference "
                    "external .map files. Strip these comments in production builds."
                ),
                code_snippet=(
                    "# Using sed (Linux/macOS):\n"
                    "sed -i 's|//# sourceMappingURL=.*||g' dist/bundle.js\n"
                    "\n"
                    "# Or configure your bundler to not emit sourceMappingURL:\n"
                    "# Webpack: set devtool: false in production config"
                ),
                applies_to=[FindingType.SOURCE_MAPPING_URL.value],
            ))

        # Inline data: URL maps
        if has_data_url:
            _add(RemediationAdvice(
                title="Remove inline base64-encoded source maps from bundles",
                description=(
                    "Your bundles contain inline source maps encoded as base64 data: URLs. "
                    "These embed the full source map (possibly including source code) directly "
                    "in the bundle file. Disable inline source maps in production."
                ),
                code_snippet=(
                    "# Webpack: use 'source-map' (external) instead of 'inline-source-map':\n"
                    "devtool: 'source-map'\n"
                    "\n"
                    "# Rollup: set sourcemap: false in output options for production"
                ),
                applies_to=[FindingType.SOURCE_MAPPING_URL.value],
            ))

        # General best practice
        if has_critical or has_embedded:
            _add(RemediationAdvice(
                title="Audit your CI/CD pipeline for source map handling",
                description=(
                    "Ensure your CI/CD build pipeline explicitly configures source map "
                    "settings for production builds and validates that no .map files are "
                    "included before publishing to npm."
                ),
                code_snippet=(
                    "# Add a pre-publish check with mapguard:\n"
                    "mapguard scan-tarball $(npm pack --dry-run 2>&1 | tail -1)"
                ),
                applies_to=[],
            ))

        return advice_list

    def advise(
        self, finding: "Finding"
    ) -> list[RemediationAdvice]:
        """Generate remediation advice for a single finding.

        Args:
            finding: A single Finding from a scan.

        Returns:
            list[RemediationAdvice]: Relevant recommendations for this finding.
        """
        return self.advise_all([finding])
