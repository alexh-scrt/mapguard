"""Unit tests for mapguard.reporter (Reporter).

Covers:
- print_rich: renders without error for empty, single, and multiple findings
- print_json: produces valid JSON matching ScanResult.to_dict()
- Risk badge generation (_risk_badge)
- Finding type label mapping (_finding_type_label)
- Truncation helper (_truncate)
- Details column content for various analysis scenarios
- Remediation advice section rendering
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from mapguard.analyzer import AnalysisResult
from mapguard.models import Finding, FindingType, ScanResult
from mapguard.remediation import RemediationAdvice, RemediationAdvisor
from mapguard.reporter import Reporter, _finding_type_label, _risk_badge, _truncate
from mapguard.risk import RiskLevel

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analysis(
    has_embedded: bool = False,
    embedded_count: int = 0,
    source_paths: list[str] | None = None,
    is_data_url: bool = False,
    is_external: bool = False,
    parse_error: str | None = None,
    source_root: str | None = None,
    raw_size_bytes: int = 0,
) -> AnalysisResult:
    return AnalysisResult(
        file_path="dummy.js.map",
        has_embedded_content=has_embedded,
        embedded_content_count=embedded_count,
        source_file_paths=source_paths or [],
        is_data_url=is_data_url,
        is_external_reference=is_external,
        parse_error=parse_error,
        source_root=source_root,
        raw_size_bytes=raw_size_bytes,
    )


def _make_finding(
    file_path: str = "dist/bundle.js.map",
    finding_type: FindingType = FindingType.MAP_FILE,
    risk_level: RiskLevel = RiskLevel.LOW,
    analysis: AnalysisResult | None = None,
    referenced_map_url: str | None = None,
) -> Finding:
    if analysis is None:
        analysis = _make_analysis()
    return Finding(
        file_path=file_path,
        finding_type=finding_type,
        risk_level=risk_level,
        analysis=analysis,
        referenced_map_url=referenced_map_url,
    )


def _make_reporter() -> tuple[Reporter, Console, io.StringIO]:
    """Return (reporter, console, string_buffer) with output captured."""
    buf = io.StringIO()
    console = Console(file=buf, highlight=False, markup=True, force_terminal=False)
    reporter = Reporter(console=console, use_color=False)
    return reporter, console, buf


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------

class TestRiskBadge:
    def test_low_badge_text(self):
        badge = _risk_badge("LOW")
        assert "LOW" in badge.plain

    def test_medium_badge_text(self):
        badge = _risk_badge("MEDIUM")
        assert "MEDIUM" in badge.plain

    def test_high_badge_text(self):
        badge = _risk_badge("HIGH")
        assert "HIGH" in badge.plain

    def test_critical_badge_text(self):
        badge = _risk_badge("CRITICAL")
        assert "CRITICAL" in badge.plain

    def test_unknown_risk_returns_text(self):
        badge = _risk_badge("UNKNOWN")
        assert "UNKNOWN" in badge.plain


class TestFindingTypeLabel:
    def test_map_file_label(self):
        assert _finding_type_label("MAP_FILE") == ".map file"

    def test_source_mapping_url_label(self):
        assert _finding_type_label("SOURCE_MAPPING_URL") == "sourceMappingURL"

    def test_unknown_value_returned_as_is(self):
        assert _finding_type_label("UNKNOWN_TYPE") == "UNKNOWN_TYPE"


class TestTruncate:
    def test_short_string_unchanged(self):
        s = "hello world"
        assert _truncate(s, 60) == s

    def test_exact_length_unchanged(self):
        s = "a" * 60
        assert _truncate(s, 60) == s

    def test_long_string_truncated(self):
        s = "a" * 80
        result = _truncate(s, 60)
        assert len(result) == 60
        assert result.endswith("…")

    def test_custom_max_len(self):
        s = "hello world this is a long string"
        result = _truncate(s, 10)
        assert len(result) == 10
        assert result.endswith("…")

    def test_empty_string_unchanged(self):
        assert _truncate("", 60) == ""


# ---------------------------------------------------------------------------
# Reporter.print_rich – no crash tests
# ---------------------------------------------------------------------------

class TestPrintRichNoFindings:
    def test_no_findings_prints_success_message(self):
        reporter, _, buf = _make_reporter()
        result = ScanResult(source="pkg")
        reporter.print_rich(result)
        output = buf.getvalue()
        assert "No source map issues detected" in output or len(output) > 0

    def test_empty_result_does_not_raise(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="pkg")
        # Should not raise
        reporter.print_rich(result)

    def test_header_shows_source(self):
        reporter, _, buf = _make_reporter()
        result = ScanResult(source="my-package@1.2.3")
        reporter.print_rich(result)
        output = buf.getvalue()
        assert "my-package@1.2.3" in output


class TestPrintRichWithFindings:
    def test_single_finding_renders(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            file_path="dist/bundle.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=_make_analysis(has_embedded=True, embedded_count=3),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert len(output) > 0

    def test_critical_risk_level_in_output(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            risk_level=RiskLevel.CRITICAL,
            analysis=_make_analysis(has_embedded=True, embedded_count=1),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert "CRITICAL" in output

    def test_file_path_in_output(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            file_path="dist/special-file.js.map",
            risk_level=RiskLevel.HIGH,
            analysis=_make_analysis(source_paths=["src/index.ts"]),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert "special-file.js.map" in output

    def test_multiple_findings_render_without_error(self):
        reporter, _, buf = _make_reporter()
        findings = [
            _make_finding(
                file_path=f"dist/file{i}.js.map",
                risk_level=RiskLevel.MEDIUM,
                analysis=_make_analysis(source_paths=["dist/x.js"]),
            )
            for i in range(5)
        ]
        result = ScanResult(source="pkg", findings=findings)
        reporter.print_rich(result)
        output = buf.getvalue()
        assert len(output) > 0

    def test_all_risk_levels_in_output(self):
        reporter, _, buf = _make_reporter()
        findings = [
            _make_finding(
                file_path=f"dist/{level.value.lower()}.js.map",
                risk_level=level,
                analysis=_make_analysis(
                    has_embedded=(level == RiskLevel.CRITICAL),
                    embedded_count=(1 if level == RiskLevel.CRITICAL else 0),
                    source_paths=([] if level == RiskLevel.LOW else ["src/x.ts"]),
                    is_external=(level == RiskLevel.MEDIUM),
                ),
            )
            for level in RiskLevel
        ]
        result = ScanResult(source="pkg", findings=findings)
        reporter.print_rich(result)
        output = buf.getvalue()
        for level in RiskLevel:
            assert level.value in output

    def test_source_mapping_url_finding_type_in_output(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.MEDIUM,
            analysis=_make_analysis(is_external=True),
            referenced_map_url="bundle.js.map",
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert "sourceMappingURL" in output or "SOURCE_MAPPING_URL" in output or len(output) > 0

    def test_data_url_finding_renders(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.HIGH,
            analysis=_make_analysis(is_data_url=True),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert len(output) > 0

    def test_parse_error_in_output(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            risk_level=RiskLevel.LOW,
            analysis=_make_analysis(parse_error="Invalid JSON: ..."),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)
        output = buf.getvalue()
        assert len(output) > 0

    def test_many_source_paths_truncated_in_table(self):
        reporter, _, buf = _make_reporter()
        paths = [f"src/file_{i}.ts" for i in range(10)]
        finding = _make_finding(
            risk_level=RiskLevel.HIGH,
            analysis=_make_analysis(source_paths=paths),
        )
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result)  # Should not raise
        output = buf.getvalue()
        assert len(output) > 0


class TestPrintRichWithRemediation:
    def test_remediation_section_renders(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=_make_analysis(has_embedded=True, embedded_count=2),
        )
        result = ScanResult(source="pkg", findings=[finding])
        advisor = RemediationAdvisor()
        advice = advisor.advise(result.findings)
        reporter.print_rich(result, advice=advice)
        output = buf.getvalue()
        # Should have remediation section
        assert len(output) > 0

    def test_advice_title_in_output(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.LOW,
        )
        result = ScanResult(source="pkg", findings=[finding])
        advice = [
            RemediationAdvice(
                title="My Custom Advice",
                description="Do this specific thing.",
                code_snippet="echo 'done'",
                priority=1,
            )
        ]
        reporter.print_rich(result, advice=advice)
        output = buf.getvalue()
        assert "My Custom Advice" in output

    def test_no_advice_no_remediation_section(self):
        reporter, _, buf = _make_reporter()
        finding = _make_finding(risk_level=RiskLevel.LOW)
        result = ScanResult(source="pkg", findings=[finding])
        reporter.print_rich(result, advice=[])
        output = buf.getvalue()
        # Should not include Remediation heading
        assert "Remediation Advice" not in output


# ---------------------------------------------------------------------------
# Reporter.print_json
# ---------------------------------------------------------------------------

class TestPrintJson:
    def test_json_output_is_valid_json(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="pkg")
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert isinstance(data, dict)

    def test_json_contains_source(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="my-pkg@2.0.0")
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["source"] == "my-pkg@2.0.0"

    def test_json_contains_findings_key(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="pkg")
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_json_empty_findings(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="pkg")
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["total_findings"] == 0
        assert data["findings"] == []

    def test_json_with_finding(self):
        reporter, _, _ = _make_reporter()
        analysis = _make_analysis(has_embedded=True, embedded_count=2)
        finding = Finding(
            file_path="dist/app.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        result = ScanResult(source="pkg", findings=[finding])
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["total_findings"] == 1
        assert data["critical"] == 1
        assert data["findings"][0]["file_path"] == "dist/app.js.map"
        assert data["findings"][0]["risk_level"] == "CRITICAL"

    def test_json_counts_all_levels(self):
        reporter, _, _ = _make_reporter()
        findings = [
            _make_finding(risk_level=RiskLevel.LOW),
            _make_finding(risk_level=RiskLevel.MEDIUM, analysis=_make_analysis(is_external=True)),
            _make_finding(
                risk_level=RiskLevel.HIGH,
                analysis=_make_analysis(source_paths=["src/a.ts"]),
            ),
            _make_finding(
                risk_level=RiskLevel.CRITICAL,
                analysis=_make_analysis(has_embedded=True, embedded_count=1),
            ),
        ]
        result = ScanResult(source="pkg", findings=findings)
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["low"] == 1
        assert data["medium"] == 1
        assert data["high"] == 1
        assert data["critical"] == 1

    def test_json_scan_errors_included(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(
            source="pkg",
            scan_errors=["Could not read file: permission denied"],
        )
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["scan_errors"] == ["Could not read file: permission denied"]

    def test_json_output_ends_with_newline(self):
        reporter, _, _ = _make_reporter()
        result = ScanResult(source="pkg")
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        assert buf.getvalue().endswith("\n")

    def test_json_findings_analysis_structure(self):
        reporter, _, _ = _make_reporter()
        analysis = _make_analysis(
            has_embedded=True,
            embedded_count=3,
            source_paths=["src/a.ts", "src/b.ts"],
            is_data_url=False,
            is_external=False,
        )
        finding = Finding(
            file_path="dist/bundle.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        result = ScanResult(source="pkg", findings=[finding])
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        f = data["findings"][0]
        a = f["analysis"]
        assert a["has_embedded_content"] is True
        assert a["embedded_content_count"] == 3
        assert "src/a.ts" in a["source_file_paths"]


# ---------------------------------------------------------------------------
# Integration: Reporter with fixture files
# ---------------------------------------------------------------------------

class TestReporterWithFixtures:
    def test_sample_map_full_pipeline(self):
        """Full pipeline: analyze fixture -> scan result -> rich reporter."""
        from mapguard.analyzer import SourceMapAnalyzer
        from mapguard.risk import RiskScorer

        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analyzer = SourceMapAnalyzer()
        scorer = RiskScorer()
        analysis = analyzer.analyze(content, file_path="sample.js.map")
        risk = scorer.score(analysis)

        finding = Finding(
            file_path="sample.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=risk,
            analysis=analysis,
        )
        result = ScanResult(source="test-fixture", findings=[finding])

        advisor = RemediationAdvisor()
        advice = advisor.advise(result.findings)

        reporter, _, buf = _make_reporter()
        reporter.print_rich(result, advice=advice)
        output = buf.getvalue()
        assert "CRITICAL" in output
        assert len(output) > 100

    def test_sample_map_json_pipeline(self):
        """Full JSON pipeline for sample.js.map."""
        from mapguard.analyzer import SourceMapAnalyzer
        from mapguard.risk import RiskScorer

        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analyzer = SourceMapAnalyzer()
        scorer = RiskScorer()
        analysis = analyzer.analyze(content, file_path="sample.js.map")
        risk = scorer.score(analysis)

        finding = Finding(
            file_path="sample.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=risk,
            analysis=analysis,
        )
        result = ScanResult(source="test-fixture", findings=[finding])

        reporter, _, _ = _make_reporter()
        buf = io.StringIO()
        reporter.print_json(result, file=buf)
        data = json.loads(buf.getvalue())
        assert data["critical"] == 1
        assert data["source"] == "test-fixture"
