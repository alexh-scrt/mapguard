# mapguard

> **Don't ship your source code by accident — catch leaked source maps before they go public.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

mapguard is a CLI security tool that scans npm packages and JavaScript/TypeScript bundles for accidentally included source map (`.map`) files that expose your original source code. Inspired by real-world incidents like Anthropic's accidental Claude Code source leak via a `.map` file in their published npm package, mapguard assigns a risk level (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) to every finding and tells you exactly how to fix it.

---

## Quick Start

**Install:**

```bash
pip install mapguard
```

**Scan a local directory:**

```bash
mapguard scan-dir ./my-package
```

**Scan a published npm package:**

```bash
mapguard scan-npm my-package@1.2.3
```

**Scan a tarball:**

```bash
mapguard scan-tarball ./my-package-1.0.0.tgz
```

That's it. mapguard will print a color-coded findings table and tell you what to fix.

---

## Features

- **Three scan targets** — scan local directories, `.tgz` tarballs, or live npm packages fetched directly from the registry by name and optional version.
- **Deep source map analysis** — detects both embedded `sourcesContent` payloads (full source code baked into the map file) and external file path references within `.map` files.
- **Four-level risk scoring** — `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` based on content exposure, sensitive path patterns (e.g. `secrets`, `config`, `env`), and the number of exposed source files.
- **Rich terminal output** — color-coded risk badges and a structured findings table; add `--json` for machine-readable output in CI pipelines.
- **Actionable remediation** — per-finding advice including `.npmignore` snippets, webpack/rollup config changes, and `sourceMappingURL` stripping commands.

---

## Usage Examples

### Scan a local package directory

```bash
mapguard scan-dir ./dist
```

```
╔══════════════════════════════════════════════════════════════════╗
║  mapguard  ·  scan-dir  ·  ./dist                                ║
╚══════════════════════════════════════════════════════════════════╝

  File                   Type          Risk       Details
 ─────────────────────────────────────────────────────────────────
  dist/bundle.js.map     MAP_FILE      CRITICAL   5 sources embedded (incl. src/config/secrets.ts)
  dist/vendor.js         SOURCE_REF    MEDIUM     External ref → vendor.js.map

  2 findings  ·  highest risk: CRITICAL

  Remediation
  ───────────
  • Add *.map to .npmignore
  • Set devtool: false in webpack production config
  • Strip sourceMappingURL: sed -i 's|//# sourceMappingURL=.*||' dist/*.js
```

### Scan a published npm package

```bash
mapguard scan-npm some-library@2.0.1
```

```bash
# Pin to latest
mapguard scan-npm some-library
```

### Scan a tarball

```bash
npm pack          # produces some-library-2.0.1.tgz
mapguard scan-tarball some-library-2.0.1.tgz
```

### JSON output for CI

```bash
mapguard scan-npm my-package --json | jq '.findings[] | select(.risk == "CRITICAL")'
```

```json
{
  "file": "dist/bundle.js.map",
  "type": "MAP_FILE",
  "risk": "CRITICAL",
  "details": {
    "embedded_sources": 5,
    "sensitive_paths": ["src/config/secrets.ts"]
  }
}
```

### Exit codes (useful in CI)

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the minimum risk level |
| `1`  | One or more findings detected |
| `2`  | Argument / usage error |
| `3`  | Fatal runtime error (file not found, network failure, etc.) |

```bash
# Fail the build on any HIGH or CRITICAL finding
mapguard scan-npm my-package --min-risk HIGH || exit 1
```

---

## Risk Levels

| Level | Trigger |
|-------|---------|
| `CRITICAL` | `sourcesContent` is embedded — full source code is present in the map file |
| `HIGH` | Inline `data:` URL map, sensitive path patterns (`secrets`, `env`, `config`), or large source file count |
| `MEDIUM` | Source file paths are referenced externally but content is not embedded |
| `LOW` | A `.map` file is present but contains no meaningful source information |

---

## Project Structure

```
mapguard/
├── __init__.py          # Package init, version, and top-level exports
├── cli.py               # Argparse entry point; orchestrates all subcommands
├── scanner.py           # Walks directories/tarballs, collects raw findings
├── analyzer.py          # Parses source map JSON, extracts sourcesContent
├── risk.py              # Risk scoring engine (LOW → CRITICAL)
├── npm_fetcher.py       # Downloads npm package tarballs from the registry
├── reporter.py          # Rich terminal table + JSON output
├── remediation.py       # Context-aware fix recommendations
└── models.py            # Shared data models (Finding, ScanResult, etc.)
tests/
├── fixtures/
│   ├── sample.js.map    # Synthetic map with embedded sourcesContent
│   └── ref_only.js.map  # Synthetic map with path references only
├── test_scanner.py
├── test_analyzer.py
├── test_risk.py
├── test_remediation.py
├── test_reporter.py
└── test_models.py
pyproject.toml
README.md
```

---

## Configuration

mapguard is configured entirely via CLI flags — no config file required.

| Flag | Default | Description |
|------|---------|-------------|
| `--min-risk` | `LOW` | Minimum risk level to report. One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `--json` | off | Output results as JSON instead of the rich terminal table. |
| `--registry` | `https://registry.npmjs.org` | Custom npm registry URL (for `scan-npm`). |
| `--version` | — | Print mapguard version and exit. |

**Examples:**

```bash
# Only show HIGH and CRITICAL findings
mapguard scan-dir ./dist --min-risk HIGH

# Use a private registry
mapguard scan-npm my-private-pkg --registry https://npm.corp.internal

# JSON output for scripting
mapguard scan-tarball package.tgz --json > results.json
```

---

## Remediation Reference

**Add map files to `.npmignore`:**

```
# .npmignore
*.map
dist/**/*.map
```

**Disable source maps in webpack (production):**

```js
// webpack.config.js
module.exports = {
  mode: 'production',
  devtool: false,   // no source maps in the published bundle
};
```

**Disable source maps in Rollup:**

```js
// rollup.config.js
export default {
  output: {
    sourcemap: false,
  },
};
```

**Strip `sourceMappingURL` comments from existing bundles:**

```bash
sed -i 's|//# sourceMappingURL=.*||g' dist/*.js
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) — an AI agent that ships code daily.*
