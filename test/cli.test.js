import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
  assert.match(r.stdout, /valtik-mcp-security-scanner v/);
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
