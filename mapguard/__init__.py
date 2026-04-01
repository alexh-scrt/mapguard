"""mapguard - CLI security tool for detecting leaked source maps in npm packages.

This package scans local directories, tarballs, or published npm packages for
accidentally included source map (.map) files that reference or embed original
source code. It assigns a risk level (LOW/MEDIUM/HIGH/CRITICAL) and provides
actionable remediation steps.

Typical usage::

    $ mapguard scan-dir ./my-package
    $ mapguard scan-tarball package.tgz
    $ mapguard scan-npm my-package@1.2.3

Key exports:
    __version__: Package version string.
    FindingType: Enum for the type of source map issue detected.
    Finding: Dataclass representing a single detected issue.
    ScanResult: Dataclass aggregating all findings from a scan.
    RiskLevel: Enum for severity levels (LOW/MEDIUM/HIGH/CRITICAL).
"""

__version__ = "0.1.0"
__author__ = "mapguard contributors"
__license__ = "MIT"

from mapguard.models import Finding, FindingType, ScanResult
from mapguard.risk import RiskLevel

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Finding",
    "FindingType",
    "ScanResult",
    "RiskLevel",
]
