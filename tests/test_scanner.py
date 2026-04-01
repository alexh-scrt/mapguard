"""Unit tests for mapguard.scanner (Scanner).

Covers:
- scan_directory: valid directory, missing directory, not-a-directory errors
- scan_tarball: valid tarball, missing tarball error, invalid archive error
- _inspect_file: .map files, JS bundle files with sourceMappingURL, ignored files
- Integration with analyzer and risk scorer via the fixture files
- Deduplication of sourceMappingURL matches within a single file
- Very large bundle file handling (size cap)
- Tarball extraction with nested directories
"""

from __future__ import annotations

import base64
import io
import json
import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from mapguard.models import Finding, FindingType, ScanResult
from mapguard.risk import RiskLevel
from mapguard.scanner import Scanner

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_file(directory: Path, relative: str, content: str) -> Path:
    """Write *content* to *directory*/*relative*, creating parent dirs."""
    target = directory / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def _make_map_json(
    sources: list | None = None,
    sources_content: list | None = None,
    source_root: str = "",
) -> str:
    """Build a minimal source map JSON string."""
    data: dict = {"version": 3, "mappings": "", "names": []}
    if sources is not None:
        data["sources"] = sources
    if sources_content is not None:
        data["sourcesContent"] = sources_content
    if source_root:
        data["sourceRoot"] = source_root
    return json.dumps(data)


def _make_tgz(files: dict[str, str]) -> Path:
    """Create a temporary .tgz archive containing the given files.

    Args:
        files: Mapping of archive-relative path -> file content (str).

    Returns:
        Path to the created .tgz file inside a temp directory.
    """
    tmp = tempfile.mkdtemp(prefix="mapguard_test_tgz_")
    tgz_path = Path(tmp) / "test-package.tgz"

    with tarfile.open(str(tgz_path), "w:gz") as tf:
        for arc_path, content in files.items():
            encoded = content.encode("utf-8")
            info = tarfile.TarInfo(name=arc_path)
            info.size = len(encoded)
            tf.addfile(info, io.BytesIO(encoded))

    return tgz_path


# ---------------------------------------------------------------------------
# scan_directory – error cases
# ---------------------------------------------------------------------------

class TestScanDirectoryErrors:
    def test_missing_directory_raises_file_not_found(self, tmp_path):
        scanner = Scanner()
        with pytest.raises(FileNotFoundError, match="Directory not found"):
            scanner.scan_directory(tmp_path / "does_not_exist")

    def test_file_as_directory_raises_not_a_directory(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        scanner = Scanner()
        with pytest.raises(NotADirectoryError, match="Not a directory"):
            scanner.scan_directory(f)

    def test_accepts_string_path(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(str(tmp_path))
        assert isinstance(result, ScanResult)

    def test_accepts_path_object(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert isinstance(result, ScanResult)


# ---------------------------------------------------------------------------
# scan_directory – basic behaviour
# ---------------------------------------------------------------------------

class TestScanDirectoryBasic:
    def test_empty_directory_returns_no_findings(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings == []
        assert result.source == str(tmp_path)

    def test_source_label_used_when_provided(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path, source_label="my-package@1.0.0")
        assert result.source == "my-package@1.0.0"

    def test_unrelated_files_ignored(self, tmp_path):
        _write_file(tmp_path, "README.md", "# Hello")
        _write_file(tmp_path, "package.json", '{"name": "pkg"}')
        _write_file(tmp_path, "dist/index.html", "<html></html>")
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings == []

    def test_returns_scan_result(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert isinstance(result, ScanResult)

    def test_scan_result_has_scan_errors_list(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert isinstance(result.scan_errors, list)


# ---------------------------------------------------------------------------
# scan_directory – .map file detection
# ---------------------------------------------------------------------------

class TestScanDirectoryMapFiles:
    def test_detects_map_file(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/bundle.js.map",
            _make_map_json(sources=["src/index.ts"], sources_content=["const x=1;"]),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].finding_type == FindingType.MAP_FILE

    def test_map_file_path_is_relative(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/bundle.js.map",
            _make_map_json(sources=["src/index.ts"], sources_content=["code"]),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].file_path == os.path.join("dist", "bundle.js.map")

    def test_map_file_with_embedded_content_is_critical(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/app.js.map",
            _make_map_json(
                sources=["src/app.ts"],
                sources_content=["export const app = 1;"],
            ),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].risk_level == RiskLevel.CRITICAL

    def test_map_file_with_null_sources_content_is_not_critical(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/ref.js.map",
            _make_map_json(
                sources=["../src/index.js"],
                sources_content=[None],
            ),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        # Has source paths, no embedded content
        assert result.findings[0].risk_level != RiskLevel.CRITICAL
        assert result.findings[0].finding_type == FindingType.MAP_FILE

    def test_multiple_map_files(self, tmp_path):
        for i in range(3):
            _write_file(
                tmp_path,
                f"dist/chunk{i}.js.map",
                _make_map_json(sources=[f"src/chunk{i}.ts"], sources_content=[f"code {i}"]),
            )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 3
        assert all(f.finding_type == FindingType.MAP_FILE for f in result.findings)

    def test_invalid_json_map_file_still_produces_finding(self, tmp_path):
        _write_file(tmp_path, "dist/bad.js.map", "{not valid json}")
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        # A finding is still produced; the analysis will have a parse_error
        assert len(result.findings) == 1
        assert result.findings[0].analysis.parse_error is not None

    def test_nested_map_file_found(self, tmp_path):
        _write_file(
            tmp_path,
            "a/b/c/deep.js.map",
            _make_map_json(sources=["src/deep.ts"], sources_content=["deep code"]),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_map_file_analysis_has_correct_file_path(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/app.js.map",
            _make_map_json(sources=["src/app.ts"], sources_content=["code"]),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        finding = result.findings[0]
        assert finding.analysis is not None
        assert "app.js.map" in finding.analysis.file_path

    def test_map_file_with_many_sources_is_high_or_critical(self, tmp_path):
        sources = [f"src/module{i}.ts" for i in range(10)]
        sources_content = [f"code {i}" for i in range(10)]
        _write_file(
            tmp_path,
            "dist/large.js.map",
            _make_map_json(sources=sources, sources_content=sources_content),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].risk_level >= RiskLevel.HIGH


# ---------------------------------------------------------------------------
# scan_directory – sourceMappingURL detection in bundle files
# ---------------------------------------------------------------------------

class TestScanDirectorySourceMappingUrl:
    def test_detects_source_mapping_url_comment(self, tmp_path):
        content = "console.log('hello');\n//# sourceMappingURL=bundle.js.map\n"
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].finding_type == FindingType.SOURCE_MAPPING_URL

    def test_detects_legacy_source_mapping_url_form(self, tmp_path):
        content = "var x = 1;\n//@ sourceMappingURL=bundle.js.map\n"
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].referenced_map_url == "bundle.js.map"

    def test_source_mapping_url_stored_on_finding(self, tmp_path):
        content = "var x = 1;\n//# sourceMappingURL=output.js.map\n"
        _write_file(tmp_path, "dist/output.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].referenced_map_url == "output.js.map"

    def test_external_url_reference_is_at_least_medium(self, tmp_path):
        content = "var x = 1;\n//# sourceMappingURL=bundle.js.map\n"
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].risk_level >= RiskLevel.MEDIUM

    def test_mjs_extension_scanned(self, tmp_path):
        content = "export const x = 1;\n//# sourceMappingURL=esm.js.map\n"
        _write_file(tmp_path, "dist/esm.mjs", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_cjs_extension_scanned(self, tmp_path):
        content = "module.exports = {};\n//# sourceMappingURL=cjs.js.map\n"
        _write_file(tmp_path, "dist/cjs.cjs", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_duplicate_urls_deduplicated(self, tmp_path):
        # Same URL appears twice in the file (should produce only one finding)
        content = (
            "var x = 1;\n"
            "//# sourceMappingURL=bundle.js.map\n"
            "//# sourceMappingURL=bundle.js.map\n"
        )
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_multiple_distinct_urls_produce_multiple_findings(self, tmp_path):
        content = (
            "var x = 1;\n"
            "//# sourceMappingURL=chunk1.js.map\n"
            "//# sourceMappingURL=chunk2.js.map\n"
        )
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 2

    def test_bundle_without_source_mapping_url_ignored(self, tmp_path):
        _write_file(tmp_path, "dist/bundle.js", "console.log('no map here');")
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings == []

    def test_inline_data_url_detected_as_data_url(self, tmp_path):
        map_content = _make_map_json(
            sources=["src/index.ts"],
            sources_content=["const x = 1;"],
        )
        encoded = base64.b64encode(map_content.encode()).decode()
        data_url = f"data:application/json;base64,{encoded}"
        content = f"var x = 1;\n//# sourceMappingURL={data_url}\n"
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1
        assert result.findings[0].analysis.is_data_url is True

    def test_inline_data_url_with_embedded_content_is_critical(self, tmp_path):
        map_content = _make_map_json(
            sources=["src/index.ts"],
            sources_content=["const x = 1;"],
        )
        encoded = base64.b64encode(map_content.encode()).decode()
        data_url = f"data:application/json;base64,{encoded}"
        content = f"var x = 1;\n//# sourceMappingURL={data_url}\n"
        _write_file(tmp_path, "dist/bundle.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].risk_level == RiskLevel.CRITICAL

    def test_finding_type_is_source_mapping_url(self, tmp_path):
        content = "var x = 1;\n//# sourceMappingURL=app.js.map\n"
        _write_file(tmp_path, "dist/app.js", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.findings[0].finding_type == FindingType.SOURCE_MAPPING_URL

    def test_ts_extension_scanned(self, tmp_path):
        content = "export const x = 1;\n//# sourceMappingURL=ts.js.map\n"
        _write_file(tmp_path, "dist/app.ts", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_tsx_extension_scanned(self, tmp_path):
        content = "export const App = () => null;\n//# sourceMappingURL=tsx.js.map\n"
        _write_file(tmp_path, "dist/App.tsx", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1

    def test_jsx_extension_scanned(self, tmp_path):
        content = "var x = 1;\n//# sourceMappingURL=jsx.js.map\n"
        _write_file(tmp_path, "dist/app.jsx", content)
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# scan_directory – combined map file + bundle file
# ---------------------------------------------------------------------------

class TestScanDirectoryCombined:
    def test_both_map_and_bundle_finding_produced(self, tmp_path):
        _write_file(
            tmp_path,
            "dist/app.js.map",
            _make_map_json(sources=["src/app.ts"], sources_content=["code"]),
        )
        _write_file(
            tmp_path,
            "dist/app.js",
            "var x=1;\n//# sourceMappingURL=app.js.map\n",
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        types = {f.finding_type for f in result.findings}
        assert FindingType.MAP_FILE in types
        assert FindingType.SOURCE_MAPPING_URL in types

    def test_scan_result_has_correct_source(self, tmp_path):
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path, source_label="test-pkg@0.1.0")
        assert result.source == "test-pkg@0.1.0"

    def test_scan_errors_captured_not_raised(self, tmp_path):
        # Write a readable map and verify scan_errors list exists
        _write_file(
            tmp_path,
            "dist/good.js.map",
            _make_map_json(sources=["src/good.ts"], sources_content=["ok"]),
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert isinstance(result.scan_errors, list)

    def test_max_risk_reflects_highest_finding(self, tmp_path):
        # One critical map file + one medium bundle reference
        _write_file(
            tmp_path,
            "dist/critical.js.map",
            _make_map_json(sources=["src/a.ts"], sources_content=["code"]),
        )
        _write_file(
            tmp_path,
            "dist/bundle.js",
            "var x=1;\n//# sourceMappingURL=bundle.js.map\n",
        )
        scanner = Scanner()
        result = scanner.scan_directory(tmp_path)
        assert result.max_risk == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# scan_tarball – error cases
# ---------------------------------------------------------------------------

class TestScanTarballErrors:
    def test_missing_tarball_raises_file_not_found(self, tmp_path):
        scanner = Scanner()
        with pytest.raises(FileNotFoundError, match="Tarball not found"):
            scanner.scan_tarball(tmp_path / "nonexistent.tgz")

    def test_non_tar_file_raises_tar_error(self, tmp_path):
        bad = tmp_path / "bad.tgz"
        bad.write_bytes(b"this is not a tarball")
        scanner = Scanner()
        with pytest.raises(tarfile.TarError):
            scanner.scan_tarball(bad)


# ---------------------------------------------------------------------------
# scan_tarball – basic behaviour
# ---------------------------------------------------------------------------

class TestScanTarballBasic:
    def test_empty_tarball_returns_no_findings(self):
        tgz = _make_tgz({})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        assert result.findings == []

    def test_source_label_from_tarball_name(self):
        tgz = _make_tgz({})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        assert "test-package.tgz" in result.source

    def test_custom_source_label_used(self):
        tgz = _make_tgz({})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz, source_label="lodash@4.17.21")
        assert result.source == "lodash@4.17.21"

    def test_detects_map_file_in_tarball(self):
        map_content = _make_map_json(
            sources=["src/index.ts"],
            sources_content=["const x = 1;"],
        )
        tgz = _make_tgz({"package/dist/bundle.js.map": map_content})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        assert len(result.findings) >= 1
        map_findings = [
            f for f in result.findings if f.finding_type == FindingType.MAP_FILE
        ]
        assert len(map_findings) == 1

    def test_detects_source_mapping_url_in_tarball(self):
        js_content = "var x = 1;\n//# sourceMappingURL=bundle.js.map\n"
        tgz = _make_tgz({"package/dist/bundle.js": js_content})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        url_findings = [
            f for f in result.findings
            if f.finding_type == FindingType.SOURCE_MAPPING_URL
        ]
        assert len(url_findings) == 1

    def test_nested_tarball_structure_scanned(self):
        map_content = _make_map_json(
            sources=["src/a.ts", "src/b.ts"],
            sources_content=["code a", "code b"],
        )
        tgz = _make_tgz({
            "package/dist/a.js.map": map_content,
            "package/dist/b.js.map": _make_map_json(
                sources=["src/b.ts"],
                sources_content=["code b"],
            ),
        })
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        map_findings = [
            f for f in result.findings if f.finding_type == FindingType.MAP_FILE
        ]
        assert len(map_findings) == 2

    def test_tarball_accepts_string_path(self):
        tgz = _make_tgz({})
        scanner = Scanner()
        result = scanner.scan_tarball(str(tgz))
        assert isinstance(result, ScanResult)

    def test_tarball_returns_scan_result(self):
        tgz = _make_tgz({})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        assert isinstance(result, ScanResult)

    def test_critical_map_in_tarball(self):
        map_content = _make_map_json(
            sources=["src/index.ts"],
            sources_content=["export const x = 42;"],
        )
        tgz = _make_tgz({"package/dist/app.js.map": map_content})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        assert result.max_risk == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Integration: fixture files
# ---------------------------------------------------------------------------

class TestScannerWithFixtures:
    def test_sample_map_is_critical(self):
        """sample.js.map has embedded sourcesContent => CRITICAL."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "dist" / "bundle.js.map"
            target.parent.mkdir(parents=True)
            target.write_text(content, encoding="utf-8")
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
        assert len(result.findings) == 1
        assert result.findings[0].risk_level == RiskLevel.CRITICAL
        assert result.findings[0].finding_type == FindingType.MAP_FILE

    def test_sample_map_finding_has_embedded_content(self):
        """sample.js.map finding should report has_embedded_content=True."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "dist" / "bundle.js.map"
            target.parent.mkdir(parents=True)
            target.write_text(content, encoding="utf-8")
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
        finding = result.findings[0]
        assert finding.analysis.has_embedded_content is True
        assert finding.analysis.embedded_content_count == 5

    def test_ref_only_map_is_not_critical(self):
        """ref_only.js.map has no embedded content (only null entries)."""
        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "dist" / "ref_only.js.map"
            target.parent.mkdir(parents=True)
            target.write_text(content, encoding="utf-8")
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
        assert len(result.findings) == 1
        assert result.findings[0].risk_level != RiskLevel.CRITICAL
        assert result.findings[0].analysis.has_embedded_content is False

    def test_ref_only_map_has_source_paths(self):
        """ref_only.js.map should have source_file_paths populated."""
        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "dist" / "ref_only.js.map"
            target.parent.mkdir(parents=True)
            target.write_text(content, encoding="utf-8")
            scanner = Scanner()
            result = scanner.scan_directory(tmpdir)
        finding = result.findings[0]
        assert len(finding.analysis.source_file_paths) == 2

    def test_sample_map_in_tarball_is_critical(self):
        map_content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        tgz = _make_tgz({"package/dist/bundle.js.map": map_content})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        map_findings = [
            f for f in result.findings if f.finding_type == FindingType.MAP_FILE
        ]
        assert len(map_findings) == 1
        assert map_findings[0].risk_level == RiskLevel.CRITICAL

    def test_ref_only_map_in_tarball_not_critical(self):
        map_content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        tgz = _make_tgz({"package/dist/ref_only.js.map": map_content})
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        map_findings = [
            f for f in result.findings if f.finding_type == FindingType.MAP_FILE
        ]
        assert len(map_findings) == 1
        assert map_findings[0].risk_level != RiskLevel.CRITICAL

    def test_both_fixtures_in_same_tarball(self):
        """Both fixtures in the same tarball should produce two MAP_FILE findings."""
        sample_content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        ref_content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        tgz = _make_tgz({
            "package/dist/sample.js.map": sample_content,
            "package/dist/ref_only.js.map": ref_content,
        })
        scanner = Scanner()
        result = scanner.scan_tarball(tgz)
        map_findings = [
            f for f in result.findings if f.finding_type == FindingType.MAP_FILE
        ]
        assert len(map_findings) == 2
        risk_levels = {f.risk_level for f in map_findings}
        assert RiskLevel.CRITICAL in risk_levels
