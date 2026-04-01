"""Unit tests for mapguard.risk (RiskLevel and RiskScorer).

Covers:
- RiskLevel enum values and ordering operators
- RiskScorer.score() for all rule branches:
    CRITICAL: embedded sourcesContent
    HIGH: data URL, sensitive paths, large file count
    MEDIUM: source file paths present, external reference
    LOW: no meaningful information
- Sensitive path pattern matching
- Edge cases (empty paths, zero embedded count, etc.)
- Integration with fixture files via SourceMapAnalyzer
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mapguard.analyzer import AnalysisResult, SourceMapAnalyzer
from mapguard.risk import RiskLevel, RiskScorer, _HIGH_FILE_COUNT_THRESHOLD

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result(
    has_embedded: bool = False,
    embedded_count: int = 0,
    source_paths: list[str] | None = None,
    is_data_url: bool = False,
    is_external: bool = False,
    source_root: str | None = None,
) -> AnalysisResult:
    """Build a minimal AnalysisResult for risk scoring tests."""
    return AnalysisResult(
        file_path="test.js.map",
        has_embedded_content=has_embedded,
        embedded_content_count=embedded_count,
        source_file_paths=source_paths or [],
        is_data_url=is_data_url,
        is_external_reference=is_external,
        source_root=source_root,
    )


# ---------------------------------------------------------------------------
# RiskLevel enum tests
# ---------------------------------------------------------------------------

class TestRiskLevelEnum:
    def test_all_members_exist(self):
        members = {r.value for r in RiskLevel}
        assert members == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_from_value_low(self):
        assert RiskLevel("LOW") is RiskLevel.LOW

    def test_from_value_medium(self):
        assert RiskLevel("MEDIUM") is RiskLevel.MEDIUM

    def test_from_value_high(self):
        assert RiskLevel("HIGH") is RiskLevel.HIGH

    def test_from_value_critical(self):
        assert RiskLevel("CRITICAL") is RiskLevel.CRITICAL

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            RiskLevel("EXTREME")

    def test_sort_order(self):
        levels = [RiskLevel.CRITICAL, RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.MEDIUM]
        assert sorted(levels) == [
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]

    def test_min(self):
        levels = [RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM]
        assert min(levels) == RiskLevel.MEDIUM

    def test_max(self):
        levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
        assert max(levels) == RiskLevel.HIGH

    def test_not_less_than_self(self):
        for level in RiskLevel:
            assert not (level < level)

    def test_not_greater_than_self(self):
        for level in RiskLevel:
            assert not (level > level)

    def test_le_self(self):
        for level in RiskLevel:
            assert level <= level

    def test_ge_self(self):
        for level in RiskLevel:
            assert level >= level

    def test_comparison_not_implemented_for_non_risk_level(self):
        result = RiskLevel.LOW.__lt__("LOW")
        assert result is NotImplemented

    def test_lt_ordering(self):
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_gt_ordering(self):
        assert RiskLevel.CRITICAL > RiskLevel.HIGH
        assert RiskLevel.HIGH > RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM > RiskLevel.LOW

    def test_le_ordering(self):
        assert RiskLevel.LOW <= RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM <= RiskLevel.HIGH
        assert RiskLevel.HIGH <= RiskLevel.CRITICAL

    def test_ge_ordering(self):
        assert RiskLevel.CRITICAL >= RiskLevel.HIGH
        assert RiskLevel.HIGH >= RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM >= RiskLevel.LOW

    def test_low_value_string(self):
        assert RiskLevel.LOW.value == "LOW"

    def test_medium_value_string(self):
        assert RiskLevel.MEDIUM.value == "MEDIUM"

    def test_high_value_string(self):
        assert RiskLevel.HIGH.value == "HIGH"

    def test_critical_value_string(self):
        assert RiskLevel.CRITICAL.value == "CRITICAL"

    def test_ge_not_implemented_for_non_risk_level(self):
        result = RiskLevel.LOW.__ge__("LOW")
        assert result is NotImplemented

    def test_le_not_implemented_for_non_risk_level(self):
        result = RiskLevel.LOW.__le__("LOW")
        assert result is NotImplemented

    def test_gt_not_implemented_for_non_risk_level(self):
        result = RiskLevel.LOW.__gt__("LOW")
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# RiskScorer CRITICAL rule
# ---------------------------------------------------------------------------

class TestRiskScorerCritical:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_embedded_content_is_critical(self):
        analysis = _result(has_embedded=True, embedded_count=1)
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL

    def test_multiple_embedded_entries_still_critical(self):
        analysis = _result(has_embedded=True, embedded_count=10)
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL

    def test_embedded_content_with_source_paths_is_critical(self):
        analysis = _result(
            has_embedded=True,
            embedded_count=3,
            source_paths=["src/a.ts", "src/b.ts"],
        )
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL

    def test_embedded_zero_count_not_critical(self):
        # has_embedded_content=True but count=0 should not trigger CRITICAL
        analysis = _result(has_embedded=True, embedded_count=0)
        # Falls through to lower rules — should be LOW (no paths, no data url, etc.)
        result = self.scorer.score(analysis)
        assert result != RiskLevel.CRITICAL

    def test_embedded_with_sensitive_paths_is_critical(self):
        analysis = _result(
            has_embedded=True,
            embedded_count=2,
            source_paths=["/home/user/project/src/secret.ts"],
        )
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL

    def test_single_source_with_content_is_critical(self):
        analysis = _result(has_embedded=True, embedded_count=1, source_paths=["src/app.ts"])
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL

    def test_data_url_with_embedded_content_is_critical(self):
        analysis = _result(has_embedded=True, embedded_count=2, is_data_url=True)
        assert self.scorer.score(analysis) == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# RiskScorer HIGH rule
# ---------------------------------------------------------------------------

class TestRiskScorerHigh:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_data_url_is_high(self):
        analysis = _result(is_data_url=True)
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_data_url_with_no_content_still_high(self):
        analysis = _result(is_data_url=True, has_embedded=False, embedded_count=0)
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_src_is_high(self):
        analysis = _result(source_paths=["src/index.ts"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_internal_is_high(self):
        analysis = _result(source_paths=["internal/auth.ts"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_private_is_high(self):
        analysis = _result(source_paths=["private/keys.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_secret_keyword_is_high(self):
        analysis = _result(source_paths=["utils/secret_manager.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_password_keyword_is_high(self):
        analysis = _result(source_paths=["lib/password_hasher.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_token_keyword_is_high(self):
        analysis = _result(source_paths=["services/token_validator.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_api_key_is_high(self):
        analysis = _result(source_paths=["config/api_key.ts"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_ts_extension_is_high(self):
        analysis = _result(source_paths=["components/App.ts"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_tsx_extension_is_high(self):
        analysis = _result(source_paths=["components/App.tsx"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_webpack_prefix_is_high(self):
        analysis = _result(source_paths=["webpack://./src/index.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_unix_home_is_high(self):
        analysis = _result(source_paths=["/home/alice/project/src/main.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_macos_users_is_high(self):
        analysis = _result(source_paths=["/Users/bob/dev/app/src/index.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_sensitive_path_node_modules_is_high(self):
        analysis = _result(source_paths=["node_modules/lodash/index.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_high_file_count_threshold_is_high(self):
        paths = [f"dist/chunk_{i}.js" for i in range(_HIGH_FILE_COUNT_THRESHOLD)]
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_one_below_threshold_is_medium(self):
        paths = [f"dist/chunk_{i}.js" for i in range(_HIGH_FILE_COUNT_THRESHOLD - 1)]
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_well_above_threshold_is_high(self):
        paths = [f"dist/chunk_{i}.js" for i in range(_HIGH_FILE_COUNT_THRESHOLD + 10)]
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_single_sensitive_among_many_is_high(self):
        # One sensitive path among many non-sensitive should still be HIGH
        paths = [f"dist/file_{i}.js" for i in range(2)]
        paths.append("src/critical.ts")
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_lib_directory_is_high(self):
        analysis = _result(source_paths=["lib/utils.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH

    def test_credential_path_is_high(self):
        analysis = _result(source_paths=["config/credentials.js"])
        assert self.scorer.score(analysis) == RiskLevel.HIGH


# ---------------------------------------------------------------------------
# RiskScorer MEDIUM rule
# ---------------------------------------------------------------------------

class TestRiskScorerMedium:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_non_sensitive_source_paths_is_medium(self):
        # Plain .js paths without sensitive patterns
        analysis = _result(source_paths=["dist/bundle.js", "dist/vendor.js"])
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_single_non_sensitive_path_is_medium(self):
        analysis = _result(source_paths=["output.js"])
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_external_reference_is_medium(self):
        analysis = _result(is_external=True)
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_external_reference_no_paths_is_medium(self):
        analysis = _result(is_external=True, source_paths=[])
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_four_non_sensitive_paths_is_medium(self):
        # 4 paths < threshold of 5
        paths = [f"dist/chunk_{i}.js" for i in range(4)]
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM

    def test_below_threshold_with_safe_paths_is_medium(self):
        paths = ["dist/a.js", "dist/b.js", "dist/c.js"]
        analysis = _result(source_paths=paths)
        assert self.scorer.score(analysis) == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# RiskScorer LOW rule
# ---------------------------------------------------------------------------

class TestRiskScorerLow:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_empty_analysis_is_low(self):
        analysis = _result()
        assert self.scorer.score(analysis) == RiskLevel.LOW

    def test_no_paths_no_embedded_no_flags_is_low(self):
        analysis = AnalysisResult(file_path="empty.js.map")
        assert self.scorer.score(analysis) == RiskLevel.LOW

    def test_parse_error_analysis_is_low(self):
        analysis = AnalysisResult(
            file_path="bad.js.map",
            parse_error="Invalid JSON: ...",
        )
        assert self.scorer.score(analysis) == RiskLevel.LOW

    def test_source_root_only_is_low(self):
        analysis = _result(source_root="webpack://")
        assert self.scorer.score(analysis) == RiskLevel.LOW

    def test_all_false_flags_is_low(self):
        analysis = AnalysisResult(
            file_path="x.js.map",
            has_embedded_content=False,
            embedded_content_count=0,
            source_file_paths=[],
            is_data_url=False,
            is_external_reference=False,
        )
        assert self.scorer.score(analysis) == RiskLevel.LOW

    def test_embedded_true_but_zero_count_is_not_critical(self):
        # Edge case: has_embedded_content is True but count is 0
        analysis = _result(has_embedded=True, embedded_count=0)
        # Not CRITICAL, falls through to LOW
        assert self.scorer.score(analysis) == RiskLevel.LOW


# ---------------------------------------------------------------------------
# Sensitive path helper tests
# ---------------------------------------------------------------------------

class TestSensitivePathDetection:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_no_sensitive_paths(self):
        assert self.scorer._has_sensitive_paths(["dist/bundle.js", "dist/vendor.js"]) is False

    def test_empty_paths(self):
        assert self.scorer._has_sensitive_paths([]) is False

    def test_src_prefix_detected(self):
        assert self.scorer._has_sensitive_paths(["src/index.ts"]) is True

    def test_lib_prefix_detected(self):
        assert self.scorer._has_sensitive_paths(["lib/utils.js"]) is True

    def test_nested_src_detected(self):
        assert self.scorer._has_sensitive_paths(["packages/app/src/main.ts"]) is True

    def test_credential_keyword(self):
        assert self.scorer._has_sensitive_paths(["config/credentials.js"]) is True

    def test_ts_extension_detected(self):
        assert self.scorer._has_sensitive_paths(["components/Button.ts"]) is True

    def test_tsx_extension_detected(self):
        assert self.scorer._has_sensitive_paths(["components/Button.tsx"]) is True

    def test_case_insensitive_secret(self):
        assert self.scorer._has_sensitive_paths(["utils/SECRET_KEY.js"]) is True

    def test_case_insensitive_password(self):
        assert self.scorer._has_sensitive_paths(["auth/PASSWORD_HASH.js"]) is True

    def test_mixed_list_with_one_sensitive(self):
        paths = ["dist/a.js", "dist/b.js", "src/c.ts"]
        assert self.scorer._has_sensitive_paths(paths) is True

    def test_all_non_sensitive(self):
        paths = ["dist/a.js", "dist/b.js", "dist/vendor.js"]
        assert self.scorer._has_sensitive_paths(paths) is False

    def test_webpack_prefix_detected(self):
        assert self.scorer._has_sensitive_paths(["webpack://./src/app.js"]) is True

    def test_home_directory_unix_detected(self):
        assert self.scorer._has_sensitive_paths(["/home/alice/project/main.js"]) is True

    def test_users_directory_macos_detected(self):
        assert self.scorer._has_sensitive_paths(["/Users/bob/dev/app.js"]) is True

    def test_node_modules_detected(self):
        assert self.scorer._has_sensitive_paths(["node_modules/react/index.js"]) is True

    def test_internal_prefix_detected(self):
        assert self.scorer._has_sensitive_paths(["internal/auth.js"]) is True

    def test_private_prefix_detected(self):
        assert self.scorer._has_sensitive_paths(["private/keys.js"]) is True

    def test_token_keyword_detected(self):
        assert self.scorer._has_sensitive_paths(["utils/token_store.js"]) is True

    def test_api_key_keyword_detected(self):
        assert self.scorer._has_sensitive_paths(["config/api_key.js"]) is True

    def test_single_safe_dist_file(self):
        assert self.scorer._has_sensitive_paths(["dist/output.js"]) is False


# ---------------------------------------------------------------------------
# Integration: fixture files
# ---------------------------------------------------------------------------

class TestRiskScorerWithFixtures:
    def setup_method(self):
        self.analyzer = SourceMapAnalyzer()
        self.scorer = RiskScorer()

    def test_sample_map_is_critical(self):
        """sample.js.map has embedded sourcesContent => CRITICAL."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content, file_path="sample.js.map")
        risk = self.scorer.score(analysis)
        assert risk == RiskLevel.CRITICAL

    def test_ref_only_map_is_high_or_medium(self):
        """ref_only.js.map has source paths referencing .js files.

        The exact level depends on path sensitivity; the fixture uses
        '../src/index.js' paths which match the src/ pattern => HIGH.
        """
        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content, file_path="ref_only.js.map")
        risk = self.scorer.score(analysis)
        # src/ pattern triggers HIGH
        assert risk == RiskLevel.HIGH

    def test_sample_map_via_full_pipeline(self):
        """Full pipeline: read fixture -> analyze -> score."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content)
        assert analysis.has_embedded_content is True
        assert analysis.embedded_content_count > 0
        risk = self.scorer.score(analysis)
        assert risk == RiskLevel.CRITICAL

    def test_ref_only_not_critical(self):
        """ref_only.js.map should not be CRITICAL."""
        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content)
        risk = self.scorer.score(analysis)
        assert risk != RiskLevel.CRITICAL

    def test_sample_map_analysis_has_correct_count(self):
        """sample.js.map should have exactly 5 embedded sources."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content)
        assert analysis.embedded_content_count == 5

    def test_ref_only_map_analysis_has_no_embedded_content(self):
        """ref_only.js.map should have no embedded content."""
        content = (FIXTURES / "ref_only.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content)
        assert analysis.has_embedded_content is False
        assert analysis.embedded_content_count == 0

    def test_scorer_produces_risk_level_instance(self):
        """score() always returns a RiskLevel instance."""
        content = (FIXTURES / "sample.js.map").read_text(encoding="utf-8")
        analysis = self.analyzer.analyze(content)
        risk = self.scorer.score(analysis)
        assert isinstance(risk, RiskLevel)
