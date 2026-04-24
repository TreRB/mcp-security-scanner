import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'src', 'cli.js');
const VULN_DIR = join(__dirname, 'fixtures', 'vulnerable');
const SAFE_DIR = join(__dirname, 'fixtures', 'safe');

test('CLI --help exits 0', () => {
  const r = spawnSync('node', [CLI, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /MCP \(Model Context Protocol\)/);
  assert.match(r.stdout, /A1  Tool arg validation absent/);
});

test('CLI --version exits 0', () => {
  const r = spawnSync('node', [CLI, '--version'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /mcp-security-scanner v\d+\.\d+/);
});

test('CLI exits 1 on vulnerable fixture (critical present)', () => {
  const r = spawnSync('node', [CLI, VULN_DIR], { encoding: 'utf8' });
  assert.equal(r.status, 1, `expected exit 1, got ${r.status}. stderr:\n${r.stderr}`);
  assert.match(r.stdout, /CRITICAL/);
  assert.match(r.stdout, /A2/);
});

test('CLI exits 0 on safe fixture with default --fail-on high', () => {
  const r = spawnSync('node', [CLI, SAFE_DIR], { encoding: 'utf8' });
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}. stdout:\n${r.stdout}`);
});

test('CLI --json produces valid stable JSON', () => {
  const r = spawnSync('node', [CLI, VULN_DIR, '--json'], { encoding: 'utf8' });
  // exit 1 expected (findings present), but stdout should be valid JSON
  const data = JSON.parse(r.stdout);
  assert.equal(data.schema, 'valtik.mcp-security-scanner/v1');
  assert.ok(Array.isArray(data.findings));
  assert.ok(data.findings.length > 0);
  for (const f of data.findings) {
    assert.ok(f.id);
    assert.ok(f.severity);
    assert.ok(f.file);
    assert.ok(typeof f.line === 'number');
  }
});

test('CLI --fail-on critical allows medium findings without non-zero exit', () => {
  // Safe fixture may have S3 info-level; use safe
  const r = spawnSync('node', [CLI, SAFE_DIR, '--fail-on', 'critical'], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 0);
});

test('CLI rejects unknown option', () => {
  const r = spawnSync('node', [CLI, '--no-such-flag', VULN_DIR], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Unknown option/);
});

test('CLI --checks A2 only reports A2', () => {
  const r = spawnSync('node', [CLI, VULN_DIR, '--checks', 'A2', '--json'], {
    encoding: 'utf8',
  });
  const data = JSON.parse(r.stdout);
  for (const f of data.findings) assert.equal(f.id, 'A2');
});

// ───────────── v0.2.0 new flags ─────────────

test('CLI --sarif produces valid SARIF 2.1.0 document', () => {
  const r = spawnSync('node', [CLI, VULN_DIR, '--sarif'], { encoding: 'utf8' });
  const data = JSON.parse(r.stdout);
  assert.equal(data.version, '2.1.0');
  assert.ok(data.$schema.includes('sarif-2.1.0'));
  assert.ok(Array.isArray(data.runs));
  assert.equal(data.runs.length, 1);
  const run = data.runs[0];
  assert.equal(run.tool.driver.name, 'mcp-security-scanner');
  assert.ok(run.tool.driver.rules.length > 0);
  assert.ok(run.results.length > 0);
  // Every result should reference an existing rule
  const ruleIds = new Set(run.tool.driver.rules.map((r) => r.id));
  for (const res of run.results) {
    assert.ok(ruleIds.has(res.ruleId), `unknown ruleId: ${res.ruleId}`);
    assert.ok(['error', 'warning', 'note'].includes(res.level));
  }
});

test('CLI --format sarif == --sarif', () => {
  const a = spawnSync('node', [CLI, VULN_DIR, '--sarif'], { encoding: 'utf8' });
  const b = spawnSync('node', [CLI, VULN_DIR, '--format', 'sarif'], {
    encoding: 'utf8',
  });
  // Same top-level $schema (timestamps differ, so don't compare full body)
  const ad = JSON.parse(a.stdout);
  const bd = JSON.parse(b.stdout);
  assert.equal(ad.$schema, bd.$schema);
  assert.equal(ad.runs[0].results.length, bd.runs[0].results.length);
});

test('CLI --markdown renders valid markdown with severity section', () => {
  const r = spawnSync('node', [CLI, VULN_DIR, '--markdown'], { encoding: 'utf8' });
  assert.match(r.stdout, /^# mcp-security-scanner report/m);
  assert.match(r.stdout, /## Summary/);
  assert.match(r.stdout, /### A2 —/);  // at least one A2 finding
  // Severity emoji (critical) should appear for this fixture
  assert.match(r.stdout, /🔴/);
});

test('CLI --min-severity critical drops everything below', () => {
  const r = spawnSync(
    'node',
    [CLI, VULN_DIR, '--min-severity', 'critical', '--json'],
    { encoding: 'utf8' }
  );
  const data = JSON.parse(r.stdout);
  for (const f of data.findings) {
    assert.equal(f.severity, 'critical');
  }
});

test('CLI --min-severity high keeps critical and high, drops medium/low/info', () => {
  const r = spawnSync(
    'node',
    [CLI, VULN_DIR, '--min-severity', 'high', '--json'],
    { encoding: 'utf8' }
  );
  const data = JSON.parse(r.stdout);
  const allowed = new Set(['critical', 'high']);
  for (const f of data.findings) {
    assert.ok(allowed.has(f.severity), `unexpected severity: ${f.severity}`);
  }
});

test('CLI --ci is alias for --fail-on low', () => {
  // Safe fixture: no critical/high, but may have low/info. --ci should fail.
  const withCi = spawnSync('node', [CLI, SAFE_DIR, '--ci'], { encoding: 'utf8' });
  const withFailOnLow = spawnSync(
    'node',
    [CLI, SAFE_DIR, '--fail-on', 'low'],
    { encoding: 'utf8' }
  );
  assert.equal(withCi.status, withFailOnLow.status);
});

test('CLI --out writes to file', () => {
  const tmp = join(__dirname, 'tmp-out.json');
  try {
    const r = spawnSync(
      'node',
      [CLI, VULN_DIR, '--json', '--out', tmp],
      { encoding: 'utf8' }
    );
    assert.equal(r.stdout, '');  // nothing on stdout
    const data = JSON.parse(readFileSync(tmp, 'utf8'));
    assert.ok(Array.isArray(data.findings));
  } finally {
    try { unlinkSync(tmp); } catch {}
  }
});

test('CLI --format invalid rejects with exit 2', () => {
  const r = spawnSync('node', [CLI, VULN_DIR, '--format', 'xml'], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--format must be one of/);
});

test('CLI --min-severity invalid rejects with exit 2', () => {
  const r = spawnSync(
    'node',
    [CLI, VULN_DIR, '--min-severity', 'bogus'],
    { encoding: 'utf8' }
  );
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--min-severity must be one of/);
});
