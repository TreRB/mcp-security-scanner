#!/usr/bin/env node
// valtik-mcp-security-scanner CLI entrypoint.

import { existsSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { scan } from './scan.js';
import { renderHuman, renderJson, countSeverities } from './report.js';
import { renderSarif } from './sarif.js';
import { renderMarkdown } from './markdown.js';
import { CHECK_IDS, sevRank, SEVERITY_ORDER } from './checks/index.js';

const VERSION = '0.2.0';

const FORMATS = new Set(['text', 'json', 'sarif', 'markdown']);

const HELP = `Usage: mcp-security-scanner <path> [options]

Static audit of an MCP (Model Context Protocol) server source for known
MCP attack patterns plus supply-chain issues.

Arguments:
  path                  Path to MCP server source directory

Scan options:
  --language LANG       Force language: ts | js | py | auto (default: auto)
  --checks LIST         Only run specific checks (comma-separated IDs)
  --min-severity LEVEL  Drop findings below LEVEL (info|low|medium|high|critical)
  --baseline FILE       Ignore findings present in this baseline JSON

Output options:
  --format FORMAT       text | json | sarif | markdown (default: text)
  --json                Alias for --format json
  --sarif               Alias for --format sarif
  --markdown            Alias for --format markdown
  --out FILE            Write report to FILE instead of stdout
  --no-color            Disable ANSI colors in text output

Exit:
  --fail-on LEVEL       Exit non-zero on severity >= LEVEL
                        (info|low|medium|high|critical) — default: high
  --ci                  Alias for --fail-on low (any finding = failure)

  --version, -V         Print version
  --help, -h            Show help

Checks (by ID):
  A1  Tool arg validation absent
  A2  Shell or SQL passthrough
  A3  Filesystem scope unbounded
  A4  Fetch accepts private/metadata IPs
  A5  Credentials exposed via tool result
  S1  Dependencies unpinned
  S2  Known-bad package detected
  S3  Shared module-level state

Examples:
  mcp-security-scanner ./my-mcp-server
  mcp-security-scanner ./server --format sarif --out findings.sarif --ci
  mcp-security-scanner ./server --checks A2,A3 --min-severity medium
  mcp-security-scanner ./server --format markdown --out pr-comment.md

Docs:
  https://valtikstudios.com/blog/mcp-server-security-2026
`;

function parseArgs(argv) {
  const opts = {
    path: null,
    language: 'auto',
    format: 'text',
    out: null,
    checks: null,
    baseline: null,
    minSeverity: null,
    failOn: 'high',
    noColor: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') opts.help = true;
    else if (a === '--version' || a === '-V' || a === '-v') opts.version = true;
    else if (a === '--json') opts.format = 'json';
    else if (a === '--sarif') opts.format = 'sarif';
    else if (a === '--markdown') opts.format = 'markdown';
    else if (a === '--format') opts.format = argv[++i];
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--language') opts.language = argv[++i];
    else if (a === '--checks') opts.checks = argv[++i];
    else if (a === '--baseline') opts.baseline = argv[++i];
    else if (a === '--min-severity') opts.minSeverity = argv[++i];
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--ci') opts.failOn = 'low';
    else if (a === '--no-color') opts.noColor = true;
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

function validateOpts(opts) {
  if (!FORMATS.has(opts.format)) {
    throw new Error(
      `--format must be one of ${[...FORMATS].join(', ')} (got ${opts.format})`
    );
  }
  if (opts.minSeverity && sevRank(opts.minSeverity) === -1) {
    throw new Error(
      `--min-severity must be one of ${SEVERITY_ORDER.join(', ')} (got ${opts.minSeverity})`
    );
  }
  if (sevRank(opts.failOn) === -1) {
    throw new Error(
      `--fail-on must be one of ${SEVERITY_ORDER.join(', ')} (got ${opts.failOn})`
    );
  }
  if (opts.noColor) {
    process.env.NO_COLOR = '1';
  }
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
    if (opts.help) {
      process.stdout.write(HELP);
      process.exit(0);
    }
    if (opts.version) {
      process.stdout.write(`mcp-security-scanner v${VERSION}\n`);
      process.exit(0);
    }
    validateOpts(opts);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n\n${HELP}`);
    process.exit(2);
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

  const result = scan(absPath, {
    checks,
    baseline: opts.baseline,
    language: opts.language,
    minSeverity: opts.minSeverity,
  });

  let report;
  switch (opts.format) {
    case 'json':
      report = renderJson(result);
      break;
    case 'sarif':
      report = renderSarif(result);
      break;
    case 'markdown':
      report = renderMarkdown(result);
      break;
    default:
      report = renderHuman(result);
  }

  if (opts.out) {
    writeFileSync(opts.out, report + (report.endsWith('\n') ? '' : '\n'));
  } else {
    process.stdout.write(report + '\n');
  }

  // Exit code
  const counts = countSeverities(result.findings);
  const worstRank = Math.max(
    ...Object.entries(counts)
      .filter(([, c]) => c > 0)
      .map(([sev]) => sevRank(sev)),
    -1
  );
  const failOnRank = sevRank(opts.failOn);
  if (worstRank >= failOnRank) {
    process.exit(1);
  }
  process.exit(0);
}

main(process.argv.slice(2));
