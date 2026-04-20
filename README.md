# valtik-mcp-security-scanner

Static audit tool for **Model Context Protocol (MCP)** server source code. Built by [Valtik Studios](https://valtikstudios.com) to catch the 5 attack patterns and supply-chain issues we keep finding on MCP audits.

Companion to the threat-model post: [MCP server security: the 2026 attack surface no one is auditing](https://valtikstudios.com/blog/mcp-server-security-2026).

## Install

```bash
# One-shot via npx
npx valtik-mcp-security-scanner ./my-mcp-server

# Global install
npm install -g valtik-mcp-security-scanner
mcp-security-scanner ./my-mcp-server
```

Requires Node.js 20 or later. No build step.

## Usage

```
Usage: valtik-mcp-security-scanner <path> [options]

Options:
  --language <lang>   Force language: ts | js | py | auto (default: auto)
  --json              Machine-readable output
  --checks <list>     Only run specific checks (comma-separated, e.g. A2,A4)
  --baseline <file>   Ignore findings present in this baseline JSON
  --fail-on <level>   Exit non-zero on severity >= (info|low|medium|high|critical)
                      Default: high
  --version           Print version
  --help              Show help
```

## What it detects

The scanner is purely static. It reads your source, never runs it.

| ID | Severity | Check |
|----|----------|-------|
| A1 | medium/high | **Tool arg validation absent** — tool registered without a schema, with `z.any()` / `z.unknown()`, or with raw `z.string()` lacking `.regex()` / `.max()` bounds. |
| A2 | critical/high | **Shell or SQL passthrough** — tool argument flows into `child_process.exec` / `subprocess.run(shell=True)` / raw SQL. |
| A3 | high | **Filesystem scope unbounded** — `fs.readFile` / `open()` on a tool-supplied path with no sandbox prefix check (`path.resolve` + `startsWith`). |
| A4 | high | **Fetch accepts private/metadata IPs** — HTTP tool accepts a URL with no blocklist of RFC 1918, 169.254.0.0/16, 127.0.0.1, or `metadata.google.internal`. |
| A5 | critical/high/info | **Credentials exposed via tool result** — `JSON.stringify(process.env)` or sensitive env var in a return path. |
| S1 | medium/high | **Dependencies unpinned** — `package.json` / `pyproject.toml` / `requirements.txt` has `^`, `~`, `*`, `>=` ranges. |
| S2 | critical | **Known-bad package** — dependency name matches the hand-curated typosquat/compromised list at `src/fixtures/known-bad.json`. |
| S3 | info/medium | **Shared module-level state** — top-level `let`/`Map`/`{}` that will leak across MCP sessions served by the same process. |

Every finding includes file path + line number and a link to the relevant section of the threat-model post.

## Example

```
$ npx valtik-mcp-security-scanner ./my-mcp-server

MCP SECURITY SCANNER  target: ./my-mcp-server

Parsed: 14 files (12 ts, 2 json)
Tools found: 8

  [CRITICAL]  A2  Shell passthrough in tool "run_command"
              src/tools/run_command.ts:12
              exec(cmd) — user-controlled input to shell
              Fix: Parameterize. Use `execFile` with an argv array.
              Ref: https://valtikstudios.com/blog/mcp-server-security-2026#1-prompt-injection-into-tool-arguments

  [HIGH]      A4  Fetch tool "fetch_url" accepts any URL (no allowlist/blocklist)
              src/tools/fetch_url.ts:8
              fetch(url) — no SSRF guard detected
              Fix: Resolve the hostname, reject private/link-local/loopback IPs.

Summary
  8 tools total, 6 findings (1 critical, 2 high, 1 medium, 2 info)

Exit: 1
```

## JSON output schema

`--json` emits a stable schema:

```jsonc
{
  "schema": "valtik.mcp-security-scanner/v1",
  "target": "/abs/path/to/scan",
  "fileCount": 14,
  "parseCounts": { "ts": 12, "js": 0, "py": 0, "json": 2, "toml": 0 },
  "toolCount": 8,
  "counts": { "critical": 1, "high": 2, "medium": 1, "low": 0, "info": 2 },
  "findings": [
    {
      "id": "A2",
      "severity": "critical",
      "title": "Shell passthrough in tool \"run_command\"",
      "file": "src/tools/run_command.ts",
      "line": 12,
      "evidence": "exec(cmd) — user-controlled input to shell",
      "detail": "Tool argument flows directly into child_process…",
      "fix": "Parameterize. Use `execFile` with an argv array…",
      "ref": "https://valtikstudios.com/blog/mcp-server-security-2026#1-prompt-injection-into-tool-arguments"
    }
  ]
}
```

## Baselines

To adopt the tool on an existing codebase without being blocked by historical findings, generate a baseline and commit it:

```bash
mcp-security-scanner . --json > .mcp-scan-baseline.json
mcp-security-scanner . --baseline .mcp-scan-baseline.json
```

Fingerprints are `{id}::{file}::{line}::{title}`. New findings fail CI; existing ones are skipped.

## CI integration

Exit codes:

- `0` — no findings at or above `--fail-on`
- `1` — at least one finding at or above `--fail-on`
- `2` — usage error

Example GitHub Action:

```yaml
- run: npx valtik-mcp-security-scanner ./src --fail-on high
```

## Supported source languages

- **TypeScript / JavaScript** — primary. Recognizes the official `@modelcontextprotocol/sdk` patterns (`server.tool(...)`, `server.registerTool(...)`).
- **Python** — secondary. Recognizes `mcp` / `FastMCP` decorators (`@mcp.tool()` / `@server.tool()`).

Language is auto-detected per file. No runtime dependency on TypeScript, Babel, or a Python interpreter — the scanner is regex-first for portability.

## What this tool does *not* catch

Static analysis has hard limits. We explicitly do *not* detect:

- Prompt injection resistance at runtime (requires a test harness, not a parser).
- Authentication / authorization gaps that depend on transport-layer config.
- Rate limiting and abuse detection (runtime behavior).
- Vulnerabilities in transitive dependencies — run `npm audit` / `pip-audit` alongside this.
- Secrets inside the source (use `gitleaks` or `trufflehog`).

For the full audit methodology including runtime checks, see the [threat-model post](https://valtikstudios.com/blog/mcp-server-security-2026).

## Professional MCP audits

Valtik Studios runs fixed-price MCP server audits:

- **$3,500** — single MCP server audit (all 10 categories from the post)
- **$8,500** — MCP deployment audit (up to 5 servers)

Deliverables: per-tool capability + risk matrix, prompt-injection test suite, supply-chain review, written report with proof-of-concept payloads.

Contact: **hello@valtikstudios.com**

## Disclaimer

This tool is static analysis. It will produce false positives on creative code patterns and false negatives on anything it cannot textually recognize. Use it as a tripwire, not as a sign-off. Serious MCP deployments still need a human auditor and a runtime test harness.

Not affiliated with Anthropic. "MCP" and "Model Context Protocol" are specifications by Anthropic.

## License

MIT. See [LICENSE](./LICENSE).

## Contributing

Issues and PRs welcome: https://github.com/TreRB/mcp-security-scanner

To add a known-bad package, edit `src/fixtures/known-bad.json`. To add a check, drop a module in `src/checks/` exporting `id`, `title`, `checkTs`, and/or `checkPy`, then register it in `src/checks/index.js`.
