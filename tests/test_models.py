"""Unit tests for mapguard.models and mapguard.risk.

Tests cover:
- FindingType enum values and identity
- RiskLevel enum ordering operators
- Finding construction, validation, and computed properties
- ScanResult aggregation, filtering, and serialization
"""

from __future__ import annotations

import pytest

from mapguard.models import Finding, FindingType, ScanResult
from mapguard.risk import RiskLevel
from mapguard.analyzer import AnalysisResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analysis(
    has_embedded: bool = False,
    embedded_count: int = 0,
    source_paths: list[str] | None = None,
    is_data_url: bool = False,
    is_external: bool = False,
) -> AnalysisResult:
    """Create a minimal AnalysisResult for testing."""
    return AnalysisResult(
        file_path="dummy.js.map",
        has_embedded_content=has_embedded,
        embedded_content_count=embedded_count,
        source_file_paths=source_paths or [],
        is_data_url=is_data_url,
        is_external_reference=is_external,
    )


def _make_finding(
    file_path: str = "dist/bundle.js.map",
    finding_type: FindingType = FindingType.MAP_FILE,
    risk_level: RiskLevel = RiskLevel.LOW,
    analysis: AnalysisResult | None = None,
    referenced_map_url: str | None = None,
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    if analysis is None:
        analysis = _make_analysis()
    return Finding(
        file_path=file_path,
        finding_type=finding_type,
        risk_level=risk_level,
        analysis=analysis,
        referenced_map_url=referenced_map_url,
    )


# ---------------------------------------------------------------------------
# FindingType tests
# ---------------------------------------------------------------------------

class TestFindingType:
    def test_map_file_value(self):
        assert FindingType.MAP_FILE.value == "MAP_FILE"

    def test_source_mapping_url_value(self):
        assert FindingType.SOURCE_MAPPING_URL.value == "SOURCE_MAPPING_URL"

    def test_members(self):
        members = {ft.value for ft in FindingType}
        assert "MAP_FILE" in members
        assert "SOURCE_MAPPING_URL" in members

    def test_identity(self):
        assert FindingType.MAP_FILE is FindingType.MAP_FILE


# ---------------------------------------------------------------------------
# RiskLevel ordering tests
# ---------------------------------------------------------------------------

class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.LOW.value == "LOW"
        assert RiskLevel.MEDIUM.value == "MEDIUM"
        assert RiskLevel.HIGH.value == "HIGH"
        assert RiskLevel.CRITICAL.value == "CRITICAL"

    def test_lt_ordering(self):
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_gt_ordering(self):
        assert RiskLevel.CRITICAL > RiskLevel.HIGH
        assert RiskLevel.HIGH > RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM > RiskLevel.LOW

    def test_le_ordering(self):
        assert RiskLevel.LOW <= RiskLevel.LOW
        assert RiskLevel.LOW <= RiskLevel.MEDIUM
        assert RiskLevel.CRITICAL <= RiskLevel.CRITICAL

    def test_ge_ordering(self):
        assert RiskLevel.HIGH >= RiskLevel.HIGH
        assert RiskLevel.HIGH >= RiskLevel.LOW
        assert RiskLevel.MEDIUM >= RiskLevel.LOW

    def test_not_lt_same(self):
        assert not (RiskLevel.MEDIUM < RiskLevel.MEDIUM)

    def test_not_gt_same(self):
        assert not (RiskLevel.HIGH > RiskLevel.HIGH)

    def test_sort_ascending(self):
        levels = [RiskLevel.CRITICAL, RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM]
        assert sorted(levels) == [
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]

    def test_max(self):
        levels = [RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]
        assert max(levels) == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------

class TestFinding:
    def test_basic_construction(self):
        analysis = _make_analysis()
        finding = Finding(
            file_path="dist/app.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.LOW,
            analysis=analysis,
        )
        assert finding.file_path == "dist/app.js.map"
        assert finding.finding_type == FindingType.MAP_FILE
        assert finding.risk_level == RiskLevel.LOW
        assert finding.referenced_map_url is None

    def test_with_referenced_url(self):
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            referenced_map_url="bundle.js.map",
        )
        assert finding.referenced_map_url == "bundle.js.map"

    def test_empty_file_path_raises(self):
        with pytest.raises(ValueError, match="file_path must not be empty"):
            Finding(
                file_path="",
                finding_type=FindingType.MAP_FILE,
                risk_level=RiskLevel.LOW,
                analysis=_make_analysis(),
            )

    def test_invalid_finding_type_raises(self):
        with pytest.raises(TypeError, match="finding_type must be a FindingType instance"):
            Finding(
                file_path="foo.map",
                finding_type="MAP_FILE",  # type: ignore[arg-type]
                risk_level=RiskLevel.LOW,
                analysis=_make_analysis(),
            )

    def test_is_critical_true(self):
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        assert finding.is_critical is True

    def test_is_critical_false(self):
        finding = _make_finding(risk_level=RiskLevel.HIGH)
        assert finding.is_critical is False

    def test_is_high_or_above_high(self):
        finding = _make_finding(risk_level=RiskLevel.HIGH)
        assert finding.is_high_or_above is True

    def test_is_high_or_above_critical(self):
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        assert finding.is_high_or_above is True

    def test_is_high_or_above_medium_false(self):
        finding = _make_finding(risk_level=RiskLevel.MEDIUM)
        assert finding.is_high_or_above is False

    def test_summary_embedded_content(self):
        analysis = _make_analysis(has_embedded=True, embedded_count=3)
        finding = _make_finding(risk_level=RiskLevel.CRITICAL, analysis=analysis)
        summary = finding.summary
        assert "CRITICAL" in summary
        assert "3 embedded source file(s)" in summary

    def test_summary_source_paths(self):
        analysis = _make_analysis(source_paths=["src/a.ts", "src/b.ts"])
        finding = _make_finding(risk_level=RiskLevel.MEDIUM, analysis=analysis)
        summary = finding.summary
        assert "MEDIUM" in summary
        assert "2 source path(s) referenced" in summary

    def test_summary_no_content(self):
        finding = _make_finding(risk_level=RiskLevel.LOW)
        summary = finding.summary
        assert "LOW" in summary
        assert "no source content detected" in summary

    def test_summary_data_url(self):
        analysis = _make_analysis(is_data_url=True)
        finding = _make_finding(risk_level=RiskLevel.HIGH, analysis=analysis)
        summary = finding.summary
        assert "inline data URL" in summary


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_basic_construction(self):
        result = ScanResult(source="dist/")
        assert result.source == "dist/"
        assert result.findings == []
        assert result.scan_errors == []

    def test_empty_source_raises(self):
        with pytest.raises(ValueError, match="source must not be empty"):
            ScanResult(source="")

    def test_has_findings_false(self):
        result = ScanResult(source="dist/")
        assert result.has_findings is False

    def test_has_findings_true(self):
        result = ScanResult(
            source="dist/",
            findings=[_make_finding()],
        )
        assert result.has_findings is True

    def test_max_risk_none_when_empty(self):
        result = ScanResult(source="pkg")
        assert result.max_risk is None

    def test_max_risk_returns_highest(self):
        result = ScanResult(
            source="pkg",
            findings=[
                _make_finding(risk_level=RiskLevel.LOW),
                _make_finding(risk_level=RiskLevel.HIGH),
                _make_finding(risk_level=RiskLevel.MEDIUM),
            ],
        )
        assert result.max_risk == RiskLevel.HIGH

    def test_counts(self):
        findings = [
            _make_finding(risk_level=RiskLevel.LOW),
            _make_finding(risk_level=RiskLevel.LOW),
            _make_finding(risk_level=RiskLevel.MEDIUM),
            _make_finding(risk_level=RiskLevel.HIGH),
            _make_finding(risk_level=RiskLevel.CRITICAL),
            _make_finding(risk_level=RiskLevel.CRITICAL),
        ]
        result = ScanResult(source="pkg", findings=findings)
        assert result.low_count == 2
        assert result.medium_count == 1
        assert result.high_count == 1
        assert result.critical_count == 2

    def test_findings_at_or_above_medium(self):
        findings = [
            _make_finding(risk_level=RiskLevel.LOW),
            _make_finding(risk_level=RiskLevel.MEDIUM),
            _make_finding(risk_level=RiskLevel.HIGH),
            _make_finding(risk_level=RiskLevel.CRITICAL),
        ]
        result = ScanResult(source="pkg", findings=findings)
        filtered = result.findings_at_or_above(RiskLevel.MEDIUM)
        assert len(filtered) == 3
        assert all(f.risk_level >= RiskLevel.MEDIUM for f in filtered)

    def test_findings_at_or_above_critical_only(self):
        findings = [
            _make_finding(risk_level=RiskLevel.LOW),
            _make_finding(risk_level=RiskLevel.CRITICAL),
        ]
        result = ScanResult(source="pkg", findings=findings)
        filtered = result.findings_at_or_above(RiskLevel.CRITICAL)
        assert len(filtered) == 1
        assert filtered[0].risk_level == RiskLevel.CRITICAL

    def test_findings_at_or_above_sorted_descending(self):
        findings = [
            _make_finding(risk_level=RiskLevel.MEDIUM),
            _make_finding(risk_level=RiskLevel.CRITICAL),
            _make_finding(risk_level=RiskLevel.HIGH),
        ]
        result = ScanResult(source="pkg", findings=findings)
        filtered = result.findings_at_or_above(RiskLevel.LOW)
        risk_levels = [f.risk_level for f in filtered]
        assert risk_levels == sorted(risk_levels, reverse=True)

    def test_to_dict_structure(self):
        analysis = _make_analysis(has_embedded=True, embedded_count=2)
        finding = Finding(
            file_path="dist/app.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        result = ScanResult(source="my-pkg@1.0.0", findings=[finding])
        d = result.to_dict()

        assert d["source"] == "my-pkg@1.0.0"
        assert d["total_findings"] == 1
        assert d["critical"] == 1
        assert d["high"] == 0
        assert d["medium"] == 0
        assert d["low"] == 0
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 1

        f_dict = d["findings"][0]
        assert f_dict["file_path"] == "dist/app.js.map"
        assert f_dict["finding_type"] == "MAP_FILE"
        assert f_dict["risk_level"] == "CRITICAL"
        assert f_dict["referenced_map_url"] is None

        a_dict = f_dict["analysis"]
        assert a_dict["has_embedded_content"] is True
        assert a_dict["embedded_content_count"] == 2
        assert a_dict["is_data_url"] is False
        assert a_dict["is_external_reference"] is False
        assert a_dict["parse_error"] is None

    def test_to_dict_scan_errors(self):
        result = ScanResult(
            source="pkg",
            scan_errors=["could not read file: permission denied"],
        )
        d = result.to_dict()
        assert d["scan_errors"] == ["could not read file: permission denied"]

    def test_scan_errors_default_empty(self):
        result = ScanResult(source="pkg")
        assert result.scan_errors == []


# ---------------------------------------------------------------------------
# Integration: import from package top-level
# ---------------------------------------------------------------------------

class TestTopLevelImports:
    def test_import_finding_from_package(self):
        from mapguard import Finding as F
        assert F is Finding

    def test_import_finding_type_from_package(self):
        from mapguard import FindingType as FT
        assert FT is FindingType

    def test_import_scan_result_from_package(self):
        from mapguard import ScanResult as SR
        assert SR is ScanResult

    def test_import_risk_level_from_package(self):
        from mapguard import RiskLevel as RL
        assert RL is RiskLevel

    def test_version_present(self):
        import mapguard
        assert mapguard.__version__ == "0.1.0"
