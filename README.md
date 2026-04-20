# mcp-security-scanner

**Static audit for Model Context Protocol servers. The first MCP-specific source-code scanner.**

I ran it against Anthropic's own reference MCP servers as a calibration test. It fired on `server-memory`, flagging a schema gap that lets an attacker-influenced LLM write arbitrarily long strings and control characters into the knowledge graph. That finding is [written up here](https://valtikstudios.com/blog/auditing-the-anthropic-reference-mcp-server).

If it caught something in the reference implementation, it's catching things in yours too.

## Install and run

```bash
npx valtik-mcp-security-scanner ./your-mcp-server
```

That's it. Node 20+, no build step, no runtime deps.

## What it looks like

```
MCP SECURITY SCANNER  target: ./my-mcp-server

Parsed: 14 files (12 ts, 2 json)
Tools found: 8

  [CRITICAL]  A2  Shell passthrough in tool "run_command"
              src/tools/run_command.ts:12
              exec(cmd)  user-controlled input to shell
              Fix: Parameterize. Use execFile with an argv array.

  [HIGH]      A4  Fetch tool "fetch_url" accepts any URL
              src/tools/fetch_url.ts:8
              fetch(url)  no SSRF guard detected
              Fix: Resolve hostname, reject private/link-local/loopback IPs.

  [MEDIUM]    A1  Tool "create_entities" has permissive input schema
              src/tools/create_entities.ts:24
              observations: z.array(z.string())  no maxLength, no maxItems
              Fix: Add maxLength on stored strings, maxItems on arrays.

Summary
  8 tools total, 6 findings (1 critical, 2 high, 1 medium, 2 info)

Exit: 1
```

## Why this tool exists

MCP is the protocol Claude Desktop, Cursor, Windsurf, Cline, Zed, and every major AI IDE uses to talk to the outside world. Your MCP server is production infrastructure that an LLM will execute tool calls against. A protocol this new has almost no dedicated security tooling.

Five of the ten documented MCP attack patterns can be caught with static analysis. This tool catches those five, fast, with zero setup. No SaaS, no account, no rate limits.

## What it detects

The scanner is purely static. It reads your source. It never runs it.

| ID | Severity | Check |
|----|----------|-------|
| **A1** | medium/high | **Permissive tool input schema.** Tool registered without a schema, with `z.any()` / `z.unknown()`, or with raw `z.string()` lacking `.max()` / `.regex()`. The `server-memory` reference server fires here. |
| **A2** | critical/high | **Shell or SQL passthrough.** Tool argument flows into `child_process.exec` / `subprocess.run(shell=True)` / raw SQL concatenation. |
| **A3** | high | **Filesystem scope unbounded.** `fs.readFile` or `open()` on a tool-supplied path with no sandbox prefix check. |
| **A4** | high | **Fetch accepts private or metadata IPs.** HTTP tool accepts a URL with no block on RFC 1918 / 169.254 / loopback / `metadata.google.internal`. |
| **A5** | critical/high/info | **Credentials exposed via tool result.** `JSON.stringify(process.env)` or sensitive env var in a return path. |
| **S1** | medium/high | **Dependencies unpinned.** `package.json` / `pyproject.toml` / `requirements.txt` has `^`, `~`, `*`, `>=` ranges. |
| **S2** | critical | **Known-bad package.** Dependency name matches hand-curated typosquat / compromised list. |
| **S3** | info/medium | **Shared module-level state.** Top-level `let` / `Map` / `{}` that will leak across MCP sessions served by the same process. |

Every finding includes file path, line number, and a fix. Full JSON/SARIF output for CI.

## Supported source languages

- **TypeScript / JavaScript.** Recognizes `@modelcontextprotocol/sdk` patterns (`server.tool(...)`, `server.registerTool(...)`).
- **Python.** Recognizes `mcp` / `FastMCP` decorators (`@mcp.tool()` / `@server.tool()`).

Language auto-detected per file. Regex-first for portability, no runtime dependency on Babel or a Python interpreter.

## CI integration

```yaml
- run: npx valtik-mcp-security-scanner ./src --fail-on high
```

SARIF output for GitHub code scanning:

```yaml
- run: npx valtik-mcp-security-scanner ./src --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.

## Baselines

To adopt on an existing codebase without CI churn:

```bash
mcp-security-scanner . --json > .mcp-scan-baseline.json
mcp-security-scanner . --baseline .mcp-scan-baseline.json
```

New findings fail. Existing ones skip.

## CLI reference

```
Usage: valtik-mcp-security-scanner <path> [options]

Options:
  --language <lang>   Force: ts | js | py | auto (default: auto)
  --json              JSON output
  --sarif             SARIF 2.1.0 output for GitHub code scanning
  --checks <list>     Comma-separated check IDs (e.g. A2,A4)
  --baseline <file>   Ignore findings present in this baseline JSON
  --fail-on <level>   info | low | medium | high | critical (default: high)
  --version
  --help
```

## Companion tool

Where this tool audits MCP **servers**, [`mcp-client-inspector`](https://github.com/TreRB/mcp-client-inspector) audits MCP **clients**. It spins up a deliberately-malicious MCP server that hits your IDE with ten attack scenarios (name collision, bidi unicode, oversized responses, config-file write attempts, `tools/list_changed` flooding). Companion coverage for the other half of the protocol.

## What it does not catch

Static analysis has hard limits. The scanner does not detect:

- Prompt-injection resistance at runtime (needs a test harness, not a parser)
- Authentication / authorization gaps that depend on transport config
- Rate limiting and abuse detection (runtime behavior)
- Vulnerabilities in transitive dependencies (run `npm audit` / `pip-audit` alongside)
- Secrets inside the source (use `gitleaks` or `trufflehog`)

For a full audit including runtime test battery, see the [MCP threat-model post](https://valtikstudios.com/blog/mcp-server-security-2026) or contact [hello@valtikstudios.com](mailto:hello@valtikstudios.com).

## Paid audits

If you ship production MCP infrastructure, Valtik runs fixed-price audits:

- **$3,500** single MCP server (all 10 attack categories, per-tool capability + risk matrix, prompt-injection test suite, written report with proof-of-concept payloads)
- **$8,500** MCP deployment audit, up to 5 servers

## License and attribution

MIT. Not affiliated with Anthropic. "MCP" and "Model Context Protocol" are specifications by Anthropic.

Issues and PRs welcome. To add a check, drop a module in `src/checks/` exporting `id`, `title`, `checkTs`, and/or `checkPy`, then register it in `src/checks/index.js`. To extend the known-bad package list, edit `src/fixtures/known-bad.json`.
