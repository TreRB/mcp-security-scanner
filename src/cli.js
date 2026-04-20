#!/usr/bin/env node
// valtik-mcp-security-scanner CLI entrypoint.

import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

import { scan } from './scan.js';
import { renderHuman, renderJson, countSeverities } from './report.js';
import { CHECK_IDS, sevRank } from './checks/index.js';

const VERSION = '0.1.0';

const HELP = `Usage: valtik-mcp-security-scanner <path> [options]

Static audit of an MCP (Model Context Protocol) server source
for the five known MCP attack patterns + supply chain issues.

Arguments:
  path                Path to MCP server source directory

Options:
  --language <lang>   Force language: ts | js | py | auto (default: auto)
  --json              Machine-readable output
  --checks <list>     Only run specific checks (comma-separated)
  --baseline <file>   Ignore findings present in this baseline
  --fail-on <level>   Exit non-zero on severity >= (info|low|medium|high|critical)
                      Default: high
  --version           Print version
  --help              Show help

Checks (by ID):
  A1  Tool arg validation absent
  A2  Shell or SQL passthrough
  A3  Filesystem scope unbounded
  A4  Fetch accepts private/metadata IPs
  A5  Credentials exposed via tool result
  S1  Dependencies unpinned
  S2  Known-bad package detected
  S3  Shared module-level state

Docs: https://valtikstudios.com/blog/mcp-server-security-2026
`;

function parseArgs(argv) {
  const opts = {
    path: null,
    language: 'auto',
    json: false,
    checks: null,
    baseline: null,
    failOn: 'high',
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-v') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--language') opts.language = argv[++i];
    else if (a === '--checks') opts.checks = argv[++i];
    else if (a === '--baseline') opts.baseline = argv[++i];
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a.startsWith('--')) {
      throw new Error(`Unknown option: ${a}`);
    } else if (!opts.path) {
      opts.path = a;
    } else {
      throw new Error(`Unexpected positional: ${a}`);
    }
  }
  return opts;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n\n${HELP}`);
    process.exit(2);
  }
  if (opts.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  if (opts.version) {
    process.stdout.write(`valtik-mcp-security-scanner v${VERSION}\n`);
    process.exit(0);
  }
  if (!opts.path) {
    process.stderr.write(`error: <path> required\n\n${HELP}`);
    process.exit(2);
  }
  const absPath = resolve(opts.path);
  if (!existsSync(absPath) || !statSync(absPath).isDirectory()) {
    process.stderr.write(`error: not a directory: ${absPath}\n`);
    process.exit(2);
  }

  let checks = CHECK_IDS;
  if (opts.checks) {
    checks = opts.checks
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter((id) => CHECK_IDS.includes(id));
    if (checks.length === 0) {
      process.stderr.write(
        `error: --checks must include at least one valid ID (${CHECK_IDS.join(', ')})\n`
      );
      process.exit(2);
    }
  }

  const failOnRank = sevRank(opts.failOn);
  if (failOnRank === -1) {
    process.stderr.write(
      `error: --fail-on must be one of info|low|medium|high|critical\n`
    );
    process.exit(2);
  }

  const result = scan(absPath, {
    checks,
    baseline: opts.baseline,
    language: opts.language,
  });

  if (opts.json) {
    process.stdout.write(renderJson(result) + '\n');
  } else {
    process.stdout.write(renderHuman(result) + '\n');
  }

  // Exit code:
  const counts = countSeverities(result.findings);
  const worstRank = Math.max(
    ...Object.entries(counts)
      .filter(([, c]) => c > 0)
      .map(([sev]) => sevRank(sev)),
    -1
  );
  if (worstRank >= failOnRank) {
    process.exit(1);
  }
  process.exit(0);
}

main(process.argv.slice(2));
