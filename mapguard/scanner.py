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


# Regex to detect sourceMappingURL comments in JS/TS files.
# Matches both //# and //@ forms (the latter is legacy).
_SOURCE_MAPPING_URL_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(.+)$",
    re.MULTILINE,
)

# File extensions considered as JavaScript/TypeScript bundles that may
# contain sourceMappingURL comments.
_BUNDLE_EXTENSIONS: frozenset[str] = frozenset(
    {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
)

# Maximum file size (bytes) to read when scanning for sourceMappingURL comments.
# Very large files are unlikely to be hand-crafted bundles; cap reading to avoid
# excessive memory usage.  20 MB is generous for a typical JS bundle.
_MAX_BUNDLE_READ_BYTES: int = 20 * 1024 * 1024


class Scanner:
    """Scans directories and tarballs for source map leaks.

    Provides methods to scan a local directory tree or a .tgz tarball for
    .map files and sourceMappingURL references.  Found items are returned as
    a :class:`~mapguard.models.ScanResult` containing
    :class:`~mapguard.models.Finding` objects ready for risk scoring.

    Usage::

        scanner = Scanner()
        result = scanner.scan_directory("./dist")
        # or
        result = scanner.scan_tarball("my-package-1.0.0.tgz")
    """

    def scan_directory(
        self,
        directory: str | Path,
        source_label: Optional[str] = None,
    ) -> "ScanResult":  # noqa: F821 – resolved at runtime
        """Recursively scan a local directory for source map issues.

        Walks every file under *directory*, inspecting ``.map`` files
        directly and scanning JS/TS bundle files for ``sourceMappingURL``
        comments.  Non-fatal I/O errors are recorded in
        :attr:`~mapguard.models.ScanResult.scan_errors` rather than
        raising an exception so that a single unreadable file does not
        abort the whole scan.

        Args:
            directory: Path to the directory to scan.  May be a string or
                :class:`pathlib.Path`.
            source_label: Optional human-readable label used as the
                :attr:`~mapguard.models.ScanResult.source` field.  Defaults
                to the resolved string form of *directory*.

        Returns:
            ScanResult: Aggregated findings from the scan.

        Raises:
            FileNotFoundError: If *directory* does not exist on disk.
            NotADirectoryError: If *directory* exists but is not a directory.
        """
        from mapguard.models import Finding, ScanResult  # noqa: F401 – runtime import

        directory = Path(directory)
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        label = source_label or str(directory)
        findings: list[Finding] = []
        scan_errors: list[str] = []

        for root, _dirs, files in os.walk(directory):
            root_path = Path(root)
            for filename in sorted(files):  # sorted for deterministic ordering
                filepath = root_path / filename
                try:
                    relative = filepath.relative_to(directory)
                except ValueError:
                    # Symlink resolution edge-case; use absolute path as fallback
                    relative = filepath  # type: ignore[assignment]

                try:
                    file_findings = self._inspect_file(
                        filepath=filepath,
                        relative_path=str(relative),
                    )
                    findings.extend(file_findings)
                except OSError as exc:
                    scan_errors.append(
                        f"Could not read {relative}: {exc}"
                    )
                except Exception as exc:  # noqa: BLE001
                    # Catch any unexpected error for a single file so the
                    # overall scan continues.
                    scan_errors.append(
                        f"Unexpected error processing {relative}: {exc}"
                    )

        return ScanResult(source=label, findings=findings, scan_errors=scan_errors)

    def scan_tarball(
        self,
        tarball_path: str | Path,
        source_label: Optional[str] = None,
    ) -> "ScanResult":  # noqa: F821
        """Scan a ``.tgz`` / ``.tar.gz`` tarball for source map issues.

        Extracts the archive to a temporary directory, delegates to
        :meth:`scan_directory`, then cleans up automatically regardless
        of whether an exception is raised.

        Args:
            tarball_path: Path to the ``.tgz`` tarball to scan.
            source_label: Optional human-readable label for the scan
                source.  Defaults to the tarball's filename stem.

        Returns:
            ScanResult: Aggregated findings from the scan.

        Raises:
            FileNotFoundError: If the tarball does not exist on disk.
            tarfile.TarError: If the file is not a valid gzipped tar archive.
        """
        tarball_path = Path(tarball_path)
        if not tarball_path.exists():
            raise FileNotFoundError(f"Tarball not found: {tarball_path}")

        label = source_label or tarball_path.name

        with tempfile.TemporaryDirectory(prefix="mapguard_scan_") as tmpdir:
            try:
                with tarfile.open(str(tarball_path), mode="r:gz") as tf:
                    # filter= parameter available in Python 3.12+; use the
                    # safer 'data' filter when available, otherwise fall back.
                    try:
                        tf.extractall(path=tmpdir, filter="data")  # type: ignore[call-arg]
                    except TypeError:
                        # Python < 3.12 does not support the filter keyword.
                        tf.extractall(path=tmpdir)  # noqa: S202
            except tarfile.TarError as exc:
                raise tarfile.TarError(
                    f"Failed to extract tarball {tarball_path}: {exc}"
                ) from exc

            return self.scan_directory(tmpdir, source_label=label)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _inspect_file(
        self,
        filepath: Path,
        relative_path: str,
    ) -> list:  # list[Finding]
        """Inspect a single file for source map issues.

        Dispatches to the appropriate inspection method based on the
        file extension:

        * ``.map`` files → parse as source map JSON.
        * JS/TS bundle extensions → scan for ``sourceMappingURL`` comments.
        * All other files → ignored (empty list returned).

        Args:
            filepath: Absolute path to the file on disk.
            relative_path: Path relative to the scan root, used in reports.

        Returns:
            list[Finding]: Zero or more findings for this file.  The list
                may be empty if the file is not relevant or contains no
                source map references.
        """
        suffix = filepath.suffix.lower()

        if suffix == ".map":
            return self._inspect_map_file(filepath, relative_path)

        if suffix in _BUNDLE_EXTENSIONS:
            return self._inspect_bundle_file(filepath, relative_path)

        return []

    def _inspect_map_file(
        self,
        filepath: Path,
        relative_path: str,
    ) -> list:  # list[Finding]
        """Analyse a ``.map`` file and return a corresponding Finding.

        Reads the file content, runs it through
        :class:`~mapguard.analyzer.SourceMapAnalyzer`, scores it with
        :class:`~mapguard.risk.RiskScorer`, and wraps the result in a
        :class:`~mapguard.models.Finding`.

        Args:
            filepath: Absolute path to the ``.map`` file.
            relative_path: Relative path used in the finding report.

        Returns:
            list[Finding]: A list containing exactly one Finding, or an
                empty list if the file could not be read.
        """
        from mapguard.analyzer import SourceMapAnalyzer
        from mapguard.models import Finding, FindingType
        from mapguard.risk import RiskScorer

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

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
        return [finding]

    def _inspect_bundle_file(
        self,
        filepath: Path,
        relative_path: str,
    ) -> list:  # list[Finding]
        """Scan a JS/TS bundle file for ``sourceMappingURL`` comments.

        Reads up to :data:`_MAX_BUNDLE_READ_BYTES` bytes from the file and
        searches for ``sourceMappingURL`` comment patterns.  Each match
        produces one :class:`~mapguard.models.Finding`.

        Args:
            filepath: Absolute path to the bundle file.
            relative_path: Relative path used in the finding report.

        Returns:
            list[Finding]: Zero or more findings, one per sourceMappingURL
                reference found in the file.
        """
        from mapguard.analyzer import SourceMapAnalyzer
        from mapguard.models import Finding, FindingType
        from mapguard.risk import RiskScorer

        try:
            # Read with a size cap to avoid loading multi-GB files entirely.
            stat = filepath.stat()
            if stat.st_size > _MAX_BUNDLE_READ_BYTES:
                # Read only the first chunk; sourceMappingURL is always at
                # the very end of the file per the spec, so also read the
                # last 4 KB to catch it.
                with open(filepath, "rb") as fh:
                    head = fh.read(_MAX_BUNDLE_READ_BYTES - 4096)
                    fh.seek(max(0, stat.st_size - 4096))
                    tail = fh.read(4096)
                raw_bytes = head + tail
                content = raw_bytes.decode("utf-8", errors="replace")
            else:
                content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        matches = _SOURCE_MAPPING_URL_RE.findall(content)
        if not matches:
            return []

        findings: list = []
        analyzer = SourceMapAnalyzer()
        scorer = RiskScorer()

        # Deduplicate URLs; a bundle should have at most one but be defensive.
        seen_urls: set[str] = set()
        for match in matches:
            url = match.strip()
            if url in seen_urls:
                continue
            seen_urls.add(url)

            analysis = analyzer.analyze_reference(
                url=url,
                referencing_file=relative_path,
            )
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
