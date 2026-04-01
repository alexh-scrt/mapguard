"""npm registry fetcher for mapguard.

Downloads published npm package tarballs from the npm registry (or a custom
registry URL) by package name and optional version specifier, saving them to
a temporary file for downstream scanning.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Optional

import httpx

# Default npm registry
_DEFAULT_REGISTRY = "https://registry.npmjs.org"

# Regex to parse optional @version suffix from package specifiers like
# "lodash@4.17.21" or "@scope/package@1.0.0"
_PACKAGE_VERSION_RE = re.compile(
    r"^(?P<name>(?:@[^/@]+/)?[^/@]+)(?:@(?P<version>[^/]+))?$"
)


class NpmFetchError(Exception):
    """Raised when an npm package cannot be fetched from the registry."""


class NpmFetcher:
    """Downloads npm package tarballs from a registry.

    Attributes:
        registry: Base URL of the npm registry to query.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        registry: str = _DEFAULT_REGISTRY,
        timeout: float = 30.0,
    ) -> None:
        """Initialize the NpmFetcher.

        Args:
            registry: Base URL of the npm registry (default: https://registry.npmjs.org).
            timeout: HTTP request timeout in seconds (default: 30.0).
        """
        self.registry = registry.rstrip("/")
        self.timeout = timeout

    def fetch(
        self,
        package_spec: str,
        dest_dir: Optional[str | Path] = None,
    ) -> Path:
        """Fetch an npm package tarball and save it to disk.

        Parses the package specifier to extract name and optional version,
        queries the registry metadata endpoint to resolve the tarball URL,
        then downloads and saves the tarball.

        Args:
            package_spec: Package name with optional version, e.g. "lodash" or
                "lodash@4.17.21" or "@scope/pkg@2.0.0".
            dest_dir: Optional directory to save the tarball. If None, a
                temporary directory is created (caller must manage cleanup).

        Returns:
            Path: Local path to the downloaded .tgz tarball.

        Raises:
            NpmFetchError: If the package cannot be found or downloaded.
            httpx.HTTPError: On network-level failures.
        """
        name, version = self._parse_spec(package_spec)
        tarball_url = self._resolve_tarball_url(name, version)
        return self._download(tarball_url, name, version, dest_dir)

    def _parse_spec(self, spec: str) -> tuple[str, Optional[str]]:
        """Parse a package specifier into name and optional version.

        Args:
            spec: Package specifier string.

        Returns:
            tuple[str, Optional[str]]: Package name and version (or None).

        Raises:
            NpmFetchError: If the specifier format is invalid.
        """
        match = _PACKAGE_VERSION_RE.match(spec.strip())
        if not match:
            raise NpmFetchError(f"Invalid package specifier: {spec!r}")
        return match.group("name"), match.group("version")

    def _resolve_tarball_url(self, name: str, version: Optional[str]) -> str:
        """Query the registry to resolve the tarball download URL.

        Args:
            name: npm package name.
            version: Optional version string. If None, uses the latest tag.

        Returns:
            str: Tarball URL from the registry metadata.

        Raises:
            NpmFetchError: If the registry response is unexpected.
        """
        # URL-encode scoped package names
        encoded_name = name.replace("/", "%2F")
        metadata_url = f"{self.registry}/{encoded_name}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    metadata_url,
                    headers={"Accept": "application/json"},
                    follow_redirects=True,
                )
        except httpx.HTTPError as exc:
            raise NpmFetchError(
                f"Network error fetching metadata for {name!r}: {exc}"
            ) from exc

        if response.status_code == 404:
            raise NpmFetchError(f"Package not found on registry: {name!r}")
        if response.status_code != 200:
            raise NpmFetchError(
                f"Registry returned HTTP {response.status_code} for {name!r}"
            )

        try:
            data = response.json()
        except Exception as exc:  # noqa: BLE001
            raise NpmFetchError(
                f"Failed to parse registry metadata for {name!r}: {exc}"
            ) from exc

        # Resolve version
        if version is None:
            dist_tags = data.get("dist-tags", {})
            version = dist_tags.get("latest")
            if not version:
                raise NpmFetchError(
                    f"Could not determine latest version for {name!r}"
                )

        versions = data.get("versions", {})
        version_data = versions.get(version)
        if not version_data:
            available = sorted(versions.keys())
            raise NpmFetchError(
                f"Version {version!r} not found for {name!r}. "
                f"Available: {available[-5:] if available else 'none'}"
            )

        tarball_url = version_data.get("dist", {}).get("tarball")
        if not tarball_url:
            raise NpmFetchError(
                f"No tarball URL found in registry metadata for {name!r}@{version}"
            )

        return tarball_url

    def _download(
        self,
        url: str,
        name: str,
        version: Optional[str],
        dest_dir: Optional[str | Path],
    ) -> Path:
        """Download a tarball from a URL and save it to disk.

        Args:
            url: Tarball download URL.
            name: Package name (used for filename).
            version: Package version (used for filename).
            dest_dir: Destination directory. If None, uses system temp dir.

        Returns:
            Path: Local path to the saved tarball.

        Raises:
            NpmFetchError: If the download fails.
        """
        safe_name = name.replace("/", "_").replace("@", "")
        filename = f"{safe_name}-{version or 'latest'}.tgz"

        if dest_dir is None:
            dest_dir = Path(tempfile.mkdtemp(prefix="mapguard_npm_"))
        else:
            dest_dir = Path(dest_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)

        dest_path = dest_dir / filename

        try:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream("GET", url, follow_redirects=True) as response:
                    if response.status_code != 200:
                        raise NpmFetchError(
                            f"Failed to download tarball: HTTP {response.status_code} "
                            f"from {url}"
                        )
                    with open(dest_path, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=65536):
                            f.write(chunk)
        except NpmFetchError:
            raise
        except httpx.HTTPError as exc:
            raise NpmFetchError(
                f"Network error downloading tarball for {name!r}: {exc}"
            ) from exc
        except OSError as exc:
            raise NpmFetchError(
                f"Failed to write tarball to {dest_path}: {exc}"
            ) from exc

        return dest_path
