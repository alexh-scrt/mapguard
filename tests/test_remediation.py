"""Unit tests for mapguard.remediation (RemediationAdvisor and RemediationAdvice).

Covers:
- RemediationAdvice dataclass construction and __str__
- RemediationAdvisor.advise() for various finding combinations
- RemediationAdvisor.advise_single() for MAP_FILE and SOURCE_MAPPING_URL findings
- Deduplication of advice across multiple findings
- Advice ordering by priority
- Sensitive path detection triggering SENSITIVE_PATHS advice
- CI advice for HIGH/CRITICAL findings
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mapguard.analyzer import AnalysisResult
from mapguard.models import Finding, FindingType, ScanResult
from mapguard.remediation import RemediationAdvice, RemediationAdvisor
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
) -> AnalysisResult:
    """Build a minimal AnalysisResult for testing."""
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
# RemediationAdvice dataclass tests
# ---------------------------------------------------------------------------

class TestRemediationAdvice:
    def test_basic_construction(self):
        advice = RemediationAdvice(
            title="Do something",
            description="You should do something about this.",
        )
        assert advice.title == "Do something"
        assert advice.description == "You should do something about this."
        assert advice.code_snippet is None
        assert advice.applies_to == []
        assert advice.priority == 5

    def test_full_construction(self):
        advice = RemediationAdvice(
            title="Fix it",
            description="Here is how to fix it.",
            code_snippet="echo 'fix'",
            applies_to=["MAP_FILE"],
            priority=1,
        )
        assert advice.code_snippet == "echo 'fix'"
        assert advice.applies_to == ["MAP_FILE"]
        assert advice.priority == 1

    def test_str_includes_title_and_description(self):
        advice = RemediationAdvice(
            title="My advice",
            description="Do this thing.",
        )
        s = str(advice)
        assert "My advice" in s
        assert "Do this thing." in s

    def test_str_includes_code_snippet(self):
        advice = RemediationAdvice(
            title="My advice",
            description="Do this.",
            code_snippet="npm install",
        )
        s = str(advice)
        assert "npm install" in s

    def test_str_without_snippet_no_code(self):
        advice = RemediationAdvice(
            title="Title",
            description="Desc",
        )
        s = str(advice)
        # No code snippet means no extra lines from it
        assert "Title" in s
        assert "Desc" in s


# ---------------------------------------------------------------------------
# RemediationAdvisor.advise() – empty findings
# ---------------------------------------------------------------------------

class TestRemediationAdvisorEmpty:
    def test_empty_findings_returns_empty(self):
        advisor = RemediationAdvisor()
        assert advisor.advise([]) == []

    def test_empty_findings_returns_list(self):
        advisor = RemediationAdvisor()
        result = advisor.advise([])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# RemediationAdvisor – MAP_FILE findings
# ---------------------------------------------------------------------------

class TestAdviceForMapFile:
    def setup_method(self):
        self.advisor = RemediationAdvisor()

    def test_map_file_low_includes_npmignore(self):
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.LOW,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any(".npmignore" in t for t in titles)

    def test_map_file_low_includes_package_json_files(self):
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.LOW,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("files" in t.lower() for t in titles)

    def test_map_file_critical_includes_bundler_config(self):
        analysis = _make_analysis(has_embedded=True, embedded_count=3)
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("webpack" in t.lower() or "rollup" in t.lower() or "vite" in t.lower() for t in titles)

    def test_map_file_critical_includes_ci_advice(self):
        analysis = _make_analysis(has_embedded=True, embedded_count=2)
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("ci" in t.lower() or "pipeline" in t.lower() for t in titles)

    def test_map_file_high_includes_ci_advice(self):
        analysis = _make_analysis(source_paths=["src/index.ts"])
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.HIGH,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("ci" in t.lower() or "pipeline" in t.lower() for t in titles)

    def test_map_file_sensitive_paths_includes_path_advice(self):
        analysis = _make_analysis(source_paths=["src/secret.ts"])
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.HIGH,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("sensitive" in t.lower() or "path" in t.lower() for t in titles)

    def test_map_file_no_sensitive_paths_no_path_advice(self):
        analysis = _make_analysis(source_paths=["dist/bundle.js"])
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.MEDIUM,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        # Should NOT include sensitive path advice for non-sensitive paths
        assert not any("sensitive" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# RemediationAdvisor – SOURCE_MAPPING_URL findings
# ---------------------------------------------------------------------------

class TestAdviceForSourceMappingUrl:
    def setup_method(self):
        self.advisor = RemediationAdvisor()

    def test_external_url_includes_strip_comment_advice(self):
        analysis = _make_analysis(is_external=True)
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.MEDIUM,
            analysis=analysis,
            referenced_map_url="bundle.js.map",
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("strip" in t.lower() or "sourcemappingurl" in t.lower() for t in titles)

    def test_data_url_includes_inline_removal_advice(self):
        analysis = _make_analysis(is_data_url=True)
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.HIGH,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("inline" in t.lower() or "data" in t.lower() for t in titles)

    def test_data_url_with_embedded_includes_bundler_config(self):
        analysis = _make_analysis(
            is_data_url=True,
            has_embedded=True,
            embedded_count=2,
        )
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any(
            "webpack" in t.lower() or "rollup" in t.lower() or "vite" in t.lower()
            for t in titles
        )

    def test_data_url_critical_includes_ci_advice(self):
        analysis = _make_analysis(
            is_data_url=True,
            has_embedded=True,
            embedded_count=1,
        )
        finding = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        titles = [a.title for a in advice]
        assert any("ci" in t.lower() or "pipeline" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# RemediationAdvisor – deduplication and ordering
# ---------------------------------------------------------------------------

class TestAdviceDeduplicationAndOrdering:
    def setup_method(self):
        self.advisor = RemediationAdvisor()

    def test_advice_deduplicated_across_findings(self):
        # Two MAP_FILE findings — npmignore advice should appear only once
        findings = [
            _make_finding(
                file_path="dist/a.js.map",
                finding_type=FindingType.MAP_FILE,
                risk_level=RiskLevel.LOW,
            ),
            _make_finding(
                file_path="dist/b.js.map",
                finding_type=FindingType.MAP_FILE,
                risk_level=RiskLevel.LOW,
            ),
        ]
        advice = self.advisor.advise(findings)
        titles = [a.title for a in advice]
        # Check uniqueness
        assert len(titles) == len(set(titles))

    def test_advice_sorted_by_priority(self):
        analysis = _make_analysis(has_embedded=True, embedded_count=3)
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=analysis,
        )
        advice = self.advisor.advise([finding])
        priorities = [a.priority for a in advice]
        assert priorities == sorted(priorities)

    def test_single_finding_and_multi_finding_give_superset(self):
        finding1 = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.LOW,
        )
        finding2 = _make_finding(
            finding_type=FindingType.SOURCE_MAPPING_URL,
            risk_level=RiskLevel.MEDIUM,
            analysis=_make_analysis(is_external=True),
        )
        single1 = {a.title for a in self.advisor.advise([finding1])}
        single2 = {a.title for a in self.advisor.advise([finding2])}
        combined = {a.title for a in self.advisor.advise([finding1, finding2])}
        # Combined advice should include at least the union
        assert single1.issubset(combined)
        assert single2.issubset(combined)

    def test_advise_single_same_as_advise_list_of_one(self):
        finding = _make_finding(
            finding_type=FindingType.MAP_FILE,
            risk_level=RiskLevel.CRITICAL,
            analysis=_make_analysis(has_embedded=True, embedded_count=2),
        )
        single = self.advisor.advise_single(finding)
        multi = self.advisor.advise([finding])
        assert [a.title for a in single] == [a.title for a in multi]


# ---------------------------------------------------------------------------
# Integration: fixture files
# ---------------------------------------------------------------------------

class TestRemediationWithFixtures:
    def test_sample_map_critical_advice_non_empty(self):
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

        advisor = RemediationAdvisor()
        advice = advisor.advise([finding])
        assert len(advice) > 0
        assert advice[0].priority <= advice[-1].priority  # sorted

    def test_ref_only_map_advice_non_empty(self):
        from mapguard.analyzer import SourceMapAnalyzer
        from mapguard.risk import RiskScorer

        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        analyzer = SourceMapAnalyzer()
        scorer = RiskScorer()
        analysis = analyzer.analyze(content, file_path="ref_only.js.map")
        risk = scorer.score(analysis)

        finding = Finding(
            file_path="ref_only.js.map",
            finding_type=FindingType.MAP_FILE,
            risk_level=risk,
            analysis=analysis,
        )

        advisor = RemediationAdvisor()
        advice = advisor.advise([finding])
        assert len(advice) > 0
