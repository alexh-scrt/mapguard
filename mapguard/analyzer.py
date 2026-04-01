"""Source map analyzer for mapguard.

Parses source map JSON payloads (version 3 source maps), checks for embedded
sourcesContent arrays, counts exposed source files, extracts referenced paths,
and produces an AnalysisResult used by the risk scoring engine.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AnalysisResult:
    """Result of analyzing a source map file or reference.

    Attributes:
        file_path: Path to the .map file or the JS file containing the reference.
        has_embedded_content: True if sourcesContent array is present and non-empty.
        embedded_content_count: Number of non-null, non-empty entries in sourcesContent.
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

    The analyzer handles:
    - Standard v3 source maps with sources and sourcesContent arrays
    - sourceRoot field extraction
    - Inline base64-encoded data: URL source maps
    - External file references from sourceMappingURL comments
    """

    def analyze(self, content: str, file_path: str = "") -> AnalysisResult:
        """Parse and analyze the content of a source map JSON file.

        Extracts the sources array, sourceRoot, and sourcesContent from a
        version 3 source map. Computes flags for embedded content presence
        and counts exposed source files.

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

        if not content.strip():
            result.parse_error = "Empty source map content"
            return result

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            result.parse_error = f"Invalid JSON: {exc}"
            return result

        if not isinstance(data, dict):
            result.parse_error = "Source map is not a JSON object"
            return result

        # Extract sources array — list of original file path strings
        sources = data.get("sources", [])
        if isinstance(sources, list):
            result.source_file_paths = [
                str(s) for s in sources if s is not None
            ]
        else:
            result.source_file_paths = []

        # Extract sourceRoot string
        source_root = data.get("sourceRoot")
        if source_root is not None and isinstance(source_root, str) and source_root.strip():
            result.source_root = source_root.strip()

        # Extract sourcesContent array
        # Each entry corresponds to the source at the same index; null means not embedded.
        sources_content = data.get("sourcesContent")
        if isinstance(sources_content, list):
            non_null_entries = [
                c for c in sources_content
                if c is not None and isinstance(c, str) and c != ""
            ]
            if non_null_entries:
                result.has_embedded_content = True
                result.embedded_content_count = len(non_null_entries)

        return result

    def analyze_reference(
        self, url: str, referencing_file: str = ""
    ) -> AnalysisResult:
        """Analyze a sourceMappingURL reference found in a JS/TS bundle.

        Determines whether the URL is a data: URL (inline embedded map),
        an external file reference, or a remote URL.  For data: URLs the
        embedded payload is decoded and recursively analyzed so that
        sourcesContent presence can be detected.

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

        stripped = url.strip()

        if stripped.startswith("data:"):
            result.is_data_url = True
            self._decode_data_url(stripped, result, referencing_file)
        else:
            # Any non-data URL is an external reference (relative path or absolute URL)
            result.is_external_reference = True

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _decode_data_url(
        self, url: str, result: AnalysisResult, referencing_file: str
    ) -> None:
        """Attempt to decode a base64 data: URL and merge findings into result.

        Modifies *result* in-place with information extracted from the
        embedded source map payload.

        Args:
            url: The raw data: URL string.
            result: AnalysisResult to update with decoded content.
            referencing_file: Path used as file_path in recursive analysis.
        """
        try:
            if ";base64," not in url:
                # Could be plain-text JSON data URL — try to extract after comma
                if "," in url:
                    _, payload_raw = url.split(",", 1)
                    import urllib.parse
                    decoded_str = urllib.parse.unquote(payload_raw)
                    embedded = self.analyze(decoded_str, file_path=referencing_file)
                    self._merge_embedded(result, embedded)
                else:
                    result.parse_error = "data: URL has no recognisable payload delimiter"
                return

            _, payload = url.split(";base64,", 1)
            # Strip any trailing whitespace that might have been included
            payload = payload.strip()
            # Add padding if necessary
            missing_padding = len(payload) % 4
            if missing_padding:
                payload += "=" * (4 - missing_padding)

            decoded_bytes = base64.b64decode(payload)
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
            result.raw_size_bytes = len(decoded_bytes)

            embedded = self.analyze(decoded_str, file_path=referencing_file)
            self._merge_embedded(result, embedded)

        except (ValueError, Exception) as exc:  # noqa: BLE001
            result.parse_error = f"Failed to decode data URL: {exc}"

    @staticmethod
    def _merge_embedded(result: AnalysisResult, embedded: AnalysisResult) -> None:
        """Merge relevant fields from an embedded analysis into the parent result.

        Args:
            result: Parent AnalysisResult to update.
            embedded: AnalysisResult from the decoded embedded map.
        """
        result.has_embedded_content = embedded.has_embedded_content
        result.embedded_content_count = embedded.embedded_content_count
        result.source_file_paths = embedded.source_file_paths
        result.source_root = embedded.source_root
        if embedded.parse_error:
            result.parse_error = embedded.parse_error
        if embedded.raw_size_bytes and not result.raw_size_bytes:
            result.raw_size_bytes = embedded.raw_size_bytes
