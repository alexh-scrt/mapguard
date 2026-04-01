"""Core scanning logic for mapguard.

Walks local directories or tarball archives, identifies .map files and
sourceMappingURL references in JavaScript/TypeScript files, and collects
raw findings for downstream analysis and risk scoring.
"""

from __future__ import annotations

import os
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Optional


# Regex to detect sourceMappingURL comments in JS/TS files
_SOURCE_MAPPING_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(.+)$",
    re.MULTILINE,
)

# File extensions considered as JavaScript/TypeScript bundles
_BUNDLE_EXTENSIONS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})


class Scanner:
    """Scans directories and tarballs for source map leaks.

    This class provides methods to scan a local directory tree or a .tgz
    tarball for .map files and sourceMappingURL references. Found items
    are returned as a ScanResult containing raw findings before risk scoring.
    """

    def scan_directory(
        self, directory: str | Path, source_label: Optional[str] = None
    ) -> "ScanResult":  # noqa: F821
        """Recursively scan a local directory for source map issues.

        Args:
            directory: Path to the directory to scan.
            source_label: Optional human-readable label for the scan source.

        Returns:
            ScanResult: Raw findings from the scan.

        Raises:
            FileNotFoundError: If the directory does not exist.
            NotADirectoryError: If the path is not a directory.
        """
        # Defer import to avoid circular dependency; models defined in phase 2
        from mapguard.models import ScanResult, Finding  # type: ignore[import]

        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        label = source_label or str(directory)
        findings: list[Finding] = []

        for root, _dirs, files in os.walk(directory):
            for filename in files:
                filepath = Path(root) / filename
                relative = filepath.relative_to(directory)
                file_findings = self._inspect_file(
                    filepath=filepath,
                    relative_path=str(relative),
                )
                findings.extend(file_findings)

        return ScanResult(source=label, findings=findings)

    def scan_tarball(
        self, tarball_path: str | Path, source_label: Optional[str] = None
    ) -> "ScanResult":  # noqa: F821
        """Scan a .tgz tarball for source map issues.

        Extracts the tarball to a temporary directory, scans it, then
        cleans up the temporary files automatically.

        Args:
            tarball_path: Path to the .tgz tarball to scan.
            source_label: Optional human-readable label for the scan source.

        Returns:
            ScanResult: Raw findings from the scan.

        Raises:
            FileNotFoundError: If the tarball file does not exist.
            tarfile.TarError: If the file is not a valid tar archive.
        """
        tarball_path = Path(tarball_path)
        if not tarball_path.exists():
            raise FileNotFoundError(f"Tarball not found: {tarball_path}")

        label = source_label or tarball_path.name

        with tempfile.TemporaryDirectory(prefix="mapguard_") as tmpdir:
            try:
                with tarfile.open(tarball_path, mode="r:gz") as tf:
                    tf.extractall(path=tmpdir)  # noqa: S202
            except tarfile.TarError as exc:
                raise tarfile.TarError(
                    f"Failed to extract tarball {tarball_path}: {exc}"
                ) from exc

            return self.scan_directory(tmpdir, source_label=label)

    def _inspect_file(
        self, filepath: Path, relative_path: str
    ) -> list:  # list[Finding]
        """Inspect a single file for source map issues.

        Checks whether the file is a .map file (potential leak) or a
        JavaScript/TypeScript file containing a sourceMappingURL comment.

        Args:
            filepath: Absolute path to the file on disk.
            relative_path: Path relative to the scan root (used in reports).

        Returns:
            list[Finding]: Zero or more findings for this file.
        """
        # Defer import to avoid circular dependency
        from mapguard.models import Finding, FindingType  # type: ignore[import]
        from mapguard.analyzer import SourceMapAnalyzer  # type: ignore[import]
        from mapguard.risk import RiskScorer  # type: ignore[import]

        findings: list = []
        suffix = filepath.suffix.lower()

        if suffix == ".map":
            # Direct .map file found
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return findings

            analyzer = SourceMapAnalyzer()
            analysis = analyzer.analyze(content, file_path=relative_path)
            scorer = RiskScorer()
            risk = scorer.score(analysis)

            finding = Finding(
                file_path=relative_path,
                finding_type=FindingType.MAP_FILE,
                risk_level=risk,
                analysis=analysis,
            )
            findings.append(finding)

        elif suffix in _BUNDLE_EXTENSIONS:
            # Check for sourceMappingURL references
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return findings

            matches = _SOURCE_MAPPING_URL_RE.findall(content)
            for match in matches:
                url = match.strip()
                analyzer = SourceMapAnalyzer()
                analysis = analyzer.analyze_reference(
                    url=url, referencing_file=relative_path
                )
                scorer = RiskScorer()
                risk = scorer.score(analysis)

                finding = Finding(
                    file_path=relative_path,
                    finding_type=FindingType.SOURCE_MAPPING_URL,
                    risk_level=risk,
                    analysis=analysis,
                    referenced_map_url=url,
                )
                findings.append(finding)

        return findings
