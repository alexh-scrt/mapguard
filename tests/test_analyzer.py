"""Unit tests for mapguard.analyzer (SourceMapAnalyzer and AnalysisResult).

Covers:
- Parsing well-formed source maps with and without sourcesContent
- Handling of null/empty sourcesContent entries
- sourceRoot extraction
- sources array extraction
- data: URL (inline base64) analysis
- External reference detection
- Error handling for invalid JSON and non-object payloads
- Empty content handling
- The sample and ref_only fixture files
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from mapguard.analyzer import AnalysisResult, SourceMapAnalyzer

# Path to the fixtures directory
FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_map(
    sources: list = None,
    sources_content: list = None,
    source_root: str = None,
    extra: dict = None,
) -> str:
    """Build a minimal JSON source map string for testing."""
    data: dict = {"version": 3, "mappings": "", "names": []}
    if sources is not None:
        data["sources"] = sources
    if sources_content is not None:
        data["sourcesContent"] = sources_content
    if source_root is not None:
        data["sourceRoot"] = source_root
    if extra:
        data.update(extra)
    return json.dumps(data)


def _b64_encode_map(content: str) -> str:
    """Encode a string as a base64 source map data: URL."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return f"data:application/json;base64,{encoded}"


# ---------------------------------------------------------------------------
# AnalysisResult default values
# ---------------------------------------------------------------------------

class TestAnalysisResultDefaults:
    def test_default_values(self):
        result = AnalysisResult()
        assert result.file_path == ""
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0
        assert result.source_file_paths == []
        assert result.source_root is None
        assert result.referenced_map_url is None
        assert result.is_data_url is False
        assert result.is_external_reference is False
        assert result.parse_error is None
        assert result.raw_size_bytes == 0

    def test_explicit_construction(self):
        result = AnalysisResult(
            file_path="foo.js.map",
            has_embedded_content=True,
            embedded_content_count=3,
            source_file_paths=["src/a.ts"],
        )
        assert result.file_path == "foo.js.map"
        assert result.has_embedded_content is True
        assert result.embedded_content_count == 3
        assert result.source_file_paths == ["src/a.ts"]


# ---------------------------------------------------------------------------
# SourceMapAnalyzer.analyze — core parsing
# ---------------------------------------------------------------------------

class TestAnalyzeBasic:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()

    def test_empty_content_returns_parse_error(self):
        result = self.analyzer.analyze("")
        assert result.parse_error is not None
        assert "Empty" in result.parse_error or "empty" in result.parse_error

    def test_whitespace_only_returns_parse_error(self):
        result = self.analyzer.analyze("   \n  ")
        assert result.parse_error is not None

    def test_invalid_json_returns_parse_error(self):
        result = self.analyzer.analyze("{not valid json}")
        assert result.parse_error is not None
        assert "Invalid JSON" in result.parse_error

    def test_json_array_returns_parse_error(self):
        result = self.analyzer.analyze("[1, 2, 3]")
        assert result.parse_error is not None
        assert "not a JSON object" in result.parse_error

    def test_minimal_valid_map(self):
        content = _make_map()
        result = self.analyzer.analyze(content, file_path="bundle.js.map")
        assert result.parse_error is None
        assert result.file_path == "bundle.js.map"
        assert result.source_file_paths == []
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0
        assert result.source_root is None

    def test_raw_size_bytes_is_set(self):
        content = _make_map(sources=["src/a.ts"])
        result = self.analyzer.analyze(content)
        assert result.raw_size_bytes == len(content.encode("utf-8"))

    def test_file_path_stored(self):
        content = _make_map()
        result = self.analyzer.analyze(content, file_path="dist/app.js.map")
        assert result.file_path == "dist/app.js.map"


class TestAnalyzeSources:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()

    def test_sources_extracted(self):
        content = _make_map(sources=["src/index.ts", "src/utils.ts"])
        result = self.analyzer.analyze(content)
        assert result.source_file_paths == ["src/index.ts", "src/utils.ts"]

    def test_null_sources_filtered(self):
        content = _make_map(sources=["src/a.ts", None, "src/b.ts"])
        result = self.analyzer.analyze(content)
        assert result.source_file_paths == ["src/a.ts", "src/b.ts"]

    def test_sources_coerced_to_strings(self):
        # Non-string entries should be coerced
        data = {"version": 3, "mappings": "", "sources": ["a.ts", 42]}
        result = self.analyzer.analyze(json.dumps(data))
        assert "42" in result.source_file_paths

    def test_missing_sources_key_yields_empty_list(self):
        data = {"version": 3, "mappings": ""}
        result = self.analyzer.analyze(json.dumps(data))
        assert result.source_file_paths == []

    def test_non_list_sources_yields_empty_list(self):
        data = {"version": 3, "mappings": "", "sources": "src/a.ts"}
        result = self.analyzer.analyze(json.dumps(data))
        assert result.source_file_paths == []


class TestAnalyzeSourceRoot:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()

    def test_source_root_extracted(self):
        content = _make_map(source_root="webpack://my-app/")
        result = self.analyzer.analyze(content)
        assert result.source_root == "webpack://my-app/"

    def test_empty_source_root_is_none(self):
        content = _make_map(source_root="")
        result = self.analyzer.analyze(content)
        assert result.source_root is None

    def test_whitespace_source_root_is_none(self):
        content = _make_map(source_root="   ")
        result = self.analyzer.analyze(content)
        assert result.source_root is None

    def test_missing_source_root_is_none(self):
        content = _make_map()
        result = self.analyzer.analyze(content)
        assert result.source_root is None

    def test_non_string_source_root_ignored(self):
        data = {"version": 3, "mappings": "", "sourceRoot": 42}
        result = self.analyzer.analyze(json.dumps(data))
        assert result.source_root is None


class TestAnalyzeSourcesContent:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()

    def test_embedded_content_detected(self):
        content = _make_map(
            sources=["src/a.ts"],
            sources_content=["const x = 1;"],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is True
        assert result.embedded_content_count == 1

    def test_multiple_embedded_entries_counted(self):
        content = _make_map(
            sources=["src/a.ts", "src/b.ts", "src/c.ts"],
            sources_content=["code a", "code b", "code c"],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is True
        assert result.embedded_content_count == 3

    def test_null_entries_not_counted(self):
        content = _make_map(
            sources=["src/a.ts", "src/b.ts"],
            sources_content=[None, None],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0

    def test_mixed_null_and_content(self):
        content = _make_map(
            sources=["src/a.ts", "src/b.ts", "src/c.ts"],
            sources_content=[None, "real code here", None],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is True
        assert result.embedded_content_count == 1

    def test_empty_string_entries_not_counted(self):
        content = _make_map(
            sources=["src/a.ts"],
            sources_content=[""],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0

    def test_all_empty_strings_not_counted(self):
        content = _make_map(
            sources=["src/a.ts", "src/b.ts"],
            sources_content=["", ""],
        )
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0

    def test_missing_sources_content_key(self):
        content = _make_map(sources=["src/a.ts"])
        result = self.analyzer.analyze(content)
        assert result.has_embedded_content is False
        assert result.embedded_content_count == 0

    def test_non_list_sources_content_ignored(self):
        data = {"version": 3, "mappings": "", "sourcesContent": "not a list"}
        result = self.analyzer.analyze(json.dumps(data))
        assert result.has_embedded_content is False


# ---------------------------------------------------------------------------
# SourceMapAnalyzer.analyze_reference
# ---------------------------------------------------------------------------

class TestAnalyzeReference:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()

    def test_external_file_reference(self):
        result = self.analyzer.analyze_reference(
            url="bundle.js.map", referencing_file="dist/bundle.js"
        )
        assert result.is_external_reference is True
        assert result.is_data_url is False
        assert result.referenced_map_url == "bundle.js.map"
        assert result.file_path == "dist/bundle.js"

    def test_relative_path_reference(self):
        result = self.analyzer.analyze_reference(
            url="../maps/bundle.js.map"
        )
        assert result.is_external_reference is True
        assert result.is_data_url is False

    def test_absolute_url_reference(self):
        result = self.analyzer.analyze_reference(
            url="https://cdn.example.com/bundle.js.map"
        )
        assert result.is_external_reference is True
        assert result.is_data_url is False

    def test_data_url_detected(self):
        map_content = _make_map(sources=["src/a.ts"], sources_content=["code"])
        data_url = _b64_encode_map(map_content)
        result = self.analyzer.analyze_reference(url=data_url)
        assert result.is_data_url is True
        assert result.is_external_reference is False

    def test_data_url_decodes_embedded_content(self):
        map_content = _make_map(
            sources=["src/index.ts"],
            sources_content=["export const x = 42;"],
        )
        data_url = _b64_encode_map(map_content)
        result = self.analyzer.analyze_reference(url=data_url)
        assert result.is_data_url is True
        assert result.has_embedded_content is True
        assert result.embedded_content_count == 1

    def test_data_url_decodes_sources_array(self):
        map_content = _make_map(
            sources=["src/a.ts", "src/b.ts"],
            sources_content=[None, None],
        )
        data_url = _b64_encode_map(map_content)
        result = self.analyzer.analyze_reference(url=data_url)
        assert result.is_data_url is True
        assert result.source_file_paths == ["src/a.ts", "src/b.ts"]

    def test_data_url_without_embedded_content(self):
        map_content = _make_map(sources=["src/a.ts"])
        data_url = _b64_encode_map(map_content)
        result = self.analyzer.analyze_reference(url=data_url)
        assert result.is_data_url is True
        assert result.has_embedded_content is False

    def test_data_url_invalid_base64_sets_parse_error(self):
        result = self.analyzer.analyze_reference(
            url="data:application/json;base64,!!!not_valid_base64!!!"
        )
        assert result.is_data_url is True
        assert result.parse_error is not None

    def test_referenced_map_url_stored(self):
        result = self.analyzer.analyze_reference(
            url="output.js.map", referencing_file="output.js"
        )
        assert result.referenced_map_url == "output.js.map"

    def test_file_path_stored(self):
        result = self.analyzer.analyze_reference(
            url="bundle.js.map", referencing_file="dist/bundle.js"
        )
        assert result.file_path == "dist/bundle.js"

    def test_data_url_referencing_file_stored(self):
        map_content = _make_map()
        data_url = _b64_encode_map(map_content)
        result = self.analyzer.analyze_reference(
            url=data_url, referencing_file="dist/app.js"
        )
        assert result.file_path == "dist/app.js"


# ---------------------------------------------------------------------------
# Fixture file tests
# ---------------------------------------------------------------------------

class TestSampleFixture:
    """Tests against tests/fixtures/sample.js.map (has embedded sourcesContent)."""

    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()
        self.content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")

    def test_fixture_file_exists(self):
        assert (FIXTURES / "sample.js.map").exists()

    def test_parse_succeeds(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert result.parse_error is None

    def test_has_embedded_content(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert result.has_embedded_content is True

    def test_embedded_content_count(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert result.embedded_content_count == 5

    def test_source_file_paths_count(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert len(result.source_file_paths) == 5

    def test_source_file_paths_contain_ts_files(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert any(p.endswith(".ts") or p.endswith(".tsx") for p in result.source_file_paths)

    def test_source_root_extracted(self):
        result = self.analyzer.analyze(self.content, file_path="sample.js.map")
        assert result.source_root is not None
        assert "webpack" in result.source_root.lower() or result.source_root != ""

    def test_raw_size_bytes_positive(self):
        result = self.analyzer.analyze(self.content)
        assert result.raw_size_bytes > 0


class TestRefOnlyFixture:
    """Tests against tests/fixtures/ref_only.js.map (no embedded content)."""

    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()
        self.content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")

    def test_fixture_file_exists(self):
        assert (FIXTURES / "ref_only.js.map").exists()

    def test_parse_succeeds(self):
        result = self.analyzer.analyze(self.content, file_path="ref_only.js.map")
        assert result.parse_error is None

    def test_no_embedded_content(self):
        result = self.analyzer.analyze(self.content, file_path="ref_only.js.map")
        assert result.has_embedded_content is False

    def test_embedded_content_count_zero(self):
        result = self.analyzer.analyze(self.content, file_path="ref_only.js.map")
        assert result.embedded_content_count == 0

    def test_source_file_paths_present(self):
        result = self.analyzer.analyze(self.content, file_path="ref_only.js.map")
        assert len(result.source_file_paths) == 2

    def test_source_file_paths_values(self):
        result = self.analyzer.analyze(self.content)
        assert "../src/index.js" in result.source_file_paths
        assert "../src/utils.js" in result.source_file_paths

    def test_source_root_empty_treated_as_none(self):
        result = self.analyzer.analyze(self.content)
        assert result.source_root is None
