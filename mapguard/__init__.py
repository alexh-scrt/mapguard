"""mapguard - CLI security tool for detecting leaked source maps in npm packages.

This package scans local directories, tarballs, or published npm packages for
accidentally included source map (.map) files that reference or embed original
source code. It assigns a risk level (LOW/MEDIUM/HIGH/CRITICAL) and provides
actionable remediation steps.

Typical usage:
    $ mapguard scan-dir ./my-package
    $ mapguard scan-tarball package.tgz
    $ mapguard scan-npm my-package@1.2.3
"""

__version__ = "0.1.0"
__author__ = "mapguard contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
