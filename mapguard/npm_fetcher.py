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

# Default npm registry base URL.
_DEFAULT_REGISTRY: str = "https://registry.npmjs.org"

# Matches package specifiers in these forms:
#   lodash
#   lodash@4.17.21
#   @scope/package
#   @scope/package@1.0.0
#
# A scoped name starts with @<scope>/ and must not contain a bare @ in the
# scope or package segment.  The version, if present, follows the last @.
_PACKAGE_VERSION_RE = re.compile(
    r"^(?P<name>(?:@[^/@]+/)?[^/@]+)(?:@(?P<version>[^/]+))?$"
)


class NpmFetchError(Exception):
    """Raised when an npm package cannot be fetched from the registry.

    Wraps HTTP errors, missing package/version errors, and unexpected
    registry response format errors with a descriptive message.
    """


class NpmFetcher:
    """Downloads npm package tarballs from a registry.

    Queries the registry metadata endpoint to resolve a tarball URL for the
    requested package name and version, then streams the tarball to a local
    file.

    Attributes:
        registry: Base URL of the npm registry (no trailing slash).
        timeout: HTTP request timeout in seconds (applies to both metadata
            queries and tarball downloads).

    Example::

        fetcher = NpmFetcher()
        path = fetcher.fetch("lodash@4.17.21")
        # path is a Path to a .tgz file in a temp directory
    """

    def __init__(
        self,
        registry: str = _DEFAULT_REGISTRY,
        timeout: float = 60.0,
    ) -> None:
        """Initialise the NpmFetcher.

        Args:
            registry: Base URL of the npm registry.  Trailing slashes are
                stripped automatically.
            timeout: HTTP request timeout in seconds.  Applies to both the
                metadata fetch and the tarball download stream.
        """
        self.registry: str = registry.rstrip("/")
        self.timeout: float = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(
        self,
        package_spec: str,
        dest_dir: Optional[str | Path] = None,
    ) -> Path:
        """Fetch a published npm package tarball and save it to disk.

        Resolves the tarball URL from the registry metadata endpoint and
        downloads it.  If no *dest_dir* is provided, a temporary directory
        is created; the caller is responsible for cleaning it up (or simply
        letting the OS reclaim it).

        Args:
            package_spec: Package name with an optional version suffix, e.g.
                ``"lodash"``, ``"lodash@4.17.21"``, or
                ``"@babel/core@7.24.0"``.
            dest_dir: Optional directory path in which to store the downloaded
                tarball.  Created (including parents) if it does not exist.
                If ``None``, a new temporary directory is used.

        Returns:
            Path: Local filesystem path to the downloaded ``.tgz`` file.

        Raises:
            NpmFetchError: If the package specifier is invalid, the package
                or version is not found on the registry, or the download
                fails for any reason.
            httpx.HTTPError: On low-level network failures not caught
                internally (rare; most are wrapped in NpmFetchError).
        """
        name, version = self._parse_spec(package_spec)
        tarball_url, resolved_version = self._resolve_tarball_url(name, version)
        return self._download(tarball_url, name, resolved_version, dest_dir)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_spec(self, spec: str) -> tuple[str, Optional[str]]:
        """Parse a package specifier into a (name, version) pair.

        Handles plain names (``"lodash"``), versioned names
        (``"lodash@4.17.21"``), and scoped packages
        (``"@babel/core@7.24.0"`` or ``"@babel/core"``).

        Args:
            spec: Raw package specifier string from the user.

        Returns:
            tuple[str, Optional[str]]: ``(name, version)`` where *version*
                is ``None`` when not specified.

        Raises:
            NpmFetchError: If *spec* cannot be parsed as a valid specifier.
        """
        stripped = spec.strip()
        match = _PACKAGE_VERSION_RE.match(stripped)
        if not match:
            raise NpmFetchError(
                f"Invalid package specifier {spec!r}. "
                "Expected format: 'name', 'name@version', or '@scope/name@version'."
            )
        return match.group("name"), match.group("version") or None

    def _resolve_tarball_url(
        self, name: str, version: Optional[str]
    ) -> tuple[str, str]:
        """Query the registry to resolve the tarball URL for a package version.

        Fetches the package's full metadata document from the registry, then
        extracts the tarball URL for the requested (or latest) version.

        Args:
            name: npm package name (may be scoped, e.g. ``"@babel/core"``).
            version: Specific version string, or ``None`` to resolve the
                ``latest`` dist-tag.

        Returns:
            tuple[str, str]: ``(tarball_url, resolved_version)`` — the URL
                to download and the exact version string that was resolved.

        Raises:
            NpmFetchError: If the registry response is unexpected, the
                package is not found, or the requested version does not
                exist.
        """
        # Scoped package names must have the slash percent-encoded in the URL.
        encoded_name = name.replace("/", "%2F")
        metadata_url = f"{self.registry}/{encoded_name}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    metadata_url,
                    headers={"Accept": "application/json"},
                    follow_redirects=True,
                )
        except httpx.TimeoutException as exc:
            raise NpmFetchError(
                f"Timed out fetching registry metadata for {name!r}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise NpmFetchError(
                f"Network error fetching registry metadata for {name!r}: {exc}"
            ) from exc

        if response.status_code == 404:
            raise NpmFetchError(
                f"Package {name!r} was not found on the registry "
                f"({self.registry})."
            )
        if response.status_code != 200:
            raise NpmFetchError(
                f"Registry returned HTTP {response.status_code} for "
                f"{name!r} (URL: {metadata_url})."
            )

        try:
            data = response.json()
        except Exception as exc:  # noqa: BLE001
            raise NpmFetchError(
                f"Failed to parse registry JSON for {name!r}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise NpmFetchError(
                f"Unexpected registry response shape for {name!r}: "
                f"expected a JSON object, got {type(data).__name__}."
            )

        # Resolve version: use the provided version or fall back to 'latest'.
        resolved_version: str
        if version is None:
            dist_tags: dict = data.get("dist-tags") or {}
            latest = dist_tags.get("latest")
            if not latest:
                raise NpmFetchError(
                    f"Could not determine the latest version for {name!r}. "
                    "The registry response did not include a 'latest' dist-tag."
                )
            resolved_version = latest
        else:
            resolved_version = version

        versions: dict = data.get("versions") or {}
        version_data = versions.get(resolved_version)
        if not version_data:
            # Provide a helpful list of recent available versions.
            available = sorted(versions.keys())
            recent = available[-10:] if len(available) > 10 else available
            raise NpmFetchError(
                f"Version {resolved_version!r} not found for {name!r}. "
                f"Recent available versions: {recent}."
            )

        if not isinstance(version_data, dict):
            raise NpmFetchError(
                f"Unexpected version data shape for {name!r}@{resolved_version}."
            )

        dist: dict = version_data.get("dist") or {}
        tarball_url: Optional[str] = dist.get("tarball")
        if not tarball_url:
            raise NpmFetchError(
                f"No tarball URL in registry metadata for "
                f"{name!r}@{resolved_version}."
            )

        return tarball_url, resolved_version

    def _download(
        self,
        url: str,
        name: str,
        version: str,
        dest_dir: Optional[str | Path],
    ) -> Path:
        """Stream-download a tarball from *url* and write it to disk.

        Args:
            url: Full HTTPS URL of the tarball to download.
            name: Package name; used to derive the local filename.
            version: Resolved version string; used to derive the local
                filename.
            dest_dir: Directory to write the file into.  If ``None``, a
                temporary directory is created automatically.

        Returns:
            Path: Absolute path to the downloaded ``.tgz`` file.

        Raises:
            NpmFetchError: If the HTTP response indicates an error, or if
                the file cannot be written.
        """
        # Build a safe filename from the package name and version.
        # Replace characters that are illegal or awkward in filenames.
        safe_name = (
            name
            .lstrip("@")  # remove leading @ from scoped names
            .replace("/", "_")  # @scope/pkg  ->  scope_pkg
            .replace("\\", "_")
        )
        filename = f"{safe_name}-{version}.tgz"

        if dest_dir is None:
            dest_path = Path(tempfile.mkdtemp(prefix="mapguard_npm_")) / filename
        else:
            dest_dir = Path(dest_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / filename

        try:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream(
                    "GET", url, follow_redirects=True
                ) as response:
                    if response.status_code != 200:
                        raise NpmFetchError(
                            f"Failed to download tarball: HTTP "
                            f"{response.status_code} from {url}."
                        )
                    with open(dest_path, "wb") as fh:
                        for chunk in response.iter_bytes(chunk_size=65_536):
                            if chunk:
                                fh.write(chunk)
        except NpmFetchError:
            raise
        except httpx.TimeoutException as exc:
            raise NpmFetchError(
                f"Timed out downloading tarball for {name!r}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise NpmFetchError(
                f"Network error downloading tarball for {name!r}: {exc}"
            ) from exc
        except OSError as exc:
            raise NpmFetchError(
                f"Failed to write tarball to {dest_path}: {exc}"
            ) from exc

        return dest_path
