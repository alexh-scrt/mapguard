"""Source map analyzer for mapguard.

Parses source map JSON payloads (version 3 source maps), checks for embedded
sourcesContent arrays, counts exposed source files, extracts referenced paths,
and produces an AnalysisResult used by the risk scoring engine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AnalysisResult:
    """Result of analyzing a source map file or reference.

    Attributes:
        file_path: Path to the .map file or the JS file containing the reference.
        has_embedded_content: True if sourcesContent array is present and non-empty.
        embedded_content_count: Number of non-null entries in sourcesContent.
        source_file_paths: List of paths from the sources array.
        source_root: Value of sourceRoot if present.
        referenced_map_url: URL from a sourceMappingURL comment (if applicable).
        is_data_url: True if the sourceMappingURL is a base64 data: URL.
        is_external_reference: True if the sourceMappingURL points to an external file.
        parse_error: Error message if JSON parsing failed.
        raw_size_bytes: Size of the raw map content in bytes.
    """

    file_path: str = ""
    has_embedded_content: bool = False
    embedded_content_count: int = 0
    source_file_paths: list[str] = field(default_factory=list)
    source_root: Optional[str] = None
    referenced_map_url: Optional[str] = None
    is_data_url: bool = False
    is_external_reference: bool = False
    parse_error: Optional[str] = None
    raw_size_bytes: int = 0


class SourceMapAnalyzer:
    """Analyzes source map JSON content and sourceMappingURL references.

    Supports both direct analysis of .map file content and analysis of
    sourceMappingURL comment references found in JS/TS bundle files.
    """

    def analyze(self, content: str, file_path: str = "") -> AnalysisResult:
        """Parse and analyze the content of a source map JSON file.

        Args:
            content: Raw string content of the .map file.
            file_path: Path to the .map file (used for reporting).

        Returns:
            AnalysisResult: Structured analysis of the source map.
        """
        result = AnalysisResult(
            file_path=file_path,
            raw_size_bytes=len(content.encode("utf-8", errors="replace")),
        )

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            result.parse_error = f"Invalid JSON: {exc}"
            return result

        if not isinstance(data, dict):
            result.parse_error = "Source map is not a JSON object"
            return result

        # Extract sources array
        sources = data.get("sources", [])
        if isinstance(sources, list):
            result.source_file_paths = [
                str(s) for s in sources if s is not None
            ]

        # Extract sourceRoot
        source_root = data.get("sourceRoot")
        if source_root and isinstance(source_root, str):
            result.source_root = source_root

        # Extract sourcesContent array
        sources_content = data.get("sourcesContent")
        if isinstance(sources_content, list):
            non_null = [c for c in sources_content if c is not None and c != ""]
            if non_null:
                result.has_embedded_content = True
                result.embedded_content_count = len(non_null)

        return result

    def analyze_reference(
        self, url: str, referencing_file: str = ""
    ) -> AnalysisResult:
        """Analyze a sourceMappingURL reference found in a JS/TS bundle.

        Determines whether the URL is a data: URL (inline embedded map),
        an external file reference, or a remote URL.

        Args:
            url: The URL extracted from the sourceMappingURL comment.
            referencing_file: Path to the file that contained the reference.

        Returns:
            AnalysisResult: Structured analysis of the reference.
        """
        result = AnalysisResult(
            file_path=referencing_file,
            referenced_map_url=url,
        )

        if url.startswith("data:"):
            result.is_data_url = True
            # Attempt to decode base64 embedded map
            try:
                import base64

                # Format: data:application/json;base64,<payload>
                if ";base64," in url:
                    _, payload = url.split(";base64,", 1)
                    decoded = base64.b64decode(payload).decode("utf-8", errors="replace")
                    embedded = self.analyze(decoded, file_path=referencing_file)
                    # Merge findings from embedded map
                    result.has_embedded_content = embedded.has_embedded_content
                    result.embedded_content_count = embedded.embedded_content_count
                    result.source_file_paths = embedded.source_file_paths
                    result.source_root = embedded.source_root
                    result.parse_error = embedded.parse_error
                    result.raw_size_bytes = len(decoded.encode("utf-8", errors="replace"))
            except Exception as exc:  # noqa: BLE001
                result.parse_error = f"Failed to decode data URL: {exc}"
        else:
            result.is_external_reference = True

        return result
