# Changelog

## [0.2.0] - 2026-04-23

CI-ready output formats + severity filtering + expanded test coverage.
Test count 26 → 62.

### Added

- **SARIF 2.1.0 output** (`--sarif` or `--format sarif`). Emits a full
  SARIF document with auto-registered rule catalogue (MCP-A1 through
  MCP-S3), severity→level mapping (error/warning/note), `security-severity`
  CVSS scores, and evidence+fix properties per result. Drop-in for
  GitHub Code Scanning via `upload-sarif@v3`.
- **Markdown output** (`--markdown` or `--format markdown`). Structured
  for PR comments and issue bodies: severity-grouped sections, emoji
  heatmap, summary table, code-fenced evidence blocks.
- **Unified `--format`** selector: `text | json | sarif | markdown`.
- **`--min-severity`** filter — drops findings below the threshold
  before output. Useful for focusing on high-impact findings in CI
  feedback loops.
- **`--ci`** flag — convenience alias for `--fail-on low` (non-zero
  exit on any finding).
- **`--out FILE`** — write report to a file instead of stdout.
- **`--no-color`** — disable ANSI colors in text output (sets NO_COLOR).
- **`SEVERITY_ORDER`** exported from checks/index.js.

### Fixed

- CLI --version string updated to match v0.2.0 naming
  (`mcp-security-scanner v0.2.0`).

### Changed

- Test suite expanded from 2 files / 26 tests to 5 files / 62 tests:
  - `checks.test.js` — per-check classification (unchanged)
  - `cli.test.js` — CLI flag surface (expanded with SARIF/markdown/
    min-severity/--ci/--out/--format validation)
  - `scan.test.js` — min-severity behavior, baseline filtering,
    fingerprint stability, sort-by-severity, graceful handling of
    non-existent paths (new)
  - `sarif.test.js` — SARIF 2.1.0 schema compliance, rule catalogue
    auto-registration, severity→level mapping, properties serialization
    (new)
  - `markdown.test.js` — markdown structure, severity emojis,
    grouping, evidence code-fencing (new)

### Previously in 0.1.0

- 8 core checks: A1 schema, A2 shell/SQL, A3 FS scope, A4 fetch/SSRF,
  A5 credential leak, S1 dep pinning, S2 known-bad, S3 shared state.
- Text + JSON output.
- Basic CLI with `--checks`, `--baseline`, `--fail-on`.
- TypeScript and Python parsers.
