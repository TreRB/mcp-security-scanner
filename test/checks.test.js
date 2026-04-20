import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../src/scan.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VULN_DIR = join(__dirname, 'fixtures', 'vulnerable');
const SAFE_DIR = join(__dirname, 'fixtures', 'safe');

test('A1: flags loose schemas (z.any, z.string w/o bounds)', () => {
  const r = scan(VULN_DIR, { checks: ['A1'] });
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('A1'), 'expected A1 findings');
  const files = r.findings.map((f) => f.file);
  assert.ok(
    files.some((f) => f.includes('a1_loose.ts')),
    'A1 should trigger on a1_loose.ts'
  );
});

test('A2: flags shell passthrough (critical)', () => {
  const r = scan(VULN_DIR, { checks: ['A2'] });
  const shell = r.findings.find(
    (f) => f.id === 'A2' && f.file.includes('a2_shell.ts')
  );
  assert.ok(shell, 'expected A2 finding on a2_shell.ts');
  assert.equal(shell.severity, 'critical');
  assert.match(shell.title, /run_command/);
});

test('A2: flags raw SQL with arg concatenation', () => {
  const r = scan(VULN_DIR, { checks: ['A2'] });
  const sql = r.findings.find(
    (f) => f.id === 'A2' && f.file.includes('a2_sql.ts')
  );
  assert.ok(sql, 'expected A2 finding on a2_sql.ts');
  // Template-literal SQL triggers at least high severity
  assert.ok(['critical', 'high'].includes(sql.severity));
});

test('A3: flags unbounded fs.readFile on tool arg', () => {
  const r = scan(VULN_DIR, { checks: ['A3'] });
  const fs = r.findings.find(
    (f) => f.id === 'A3' && f.file.includes('a3_fs.ts')
  );
  assert.ok(fs, 'expected A3 finding');
  assert.equal(fs.severity, 'high');
});

test('A3: does NOT flag when sandbox check is present', () => {
  const r = scan(SAFE_DIR, { checks: ['A3'] });
  const fs = r.findings.find((f) => f.id === 'A3');
  assert.equal(fs, undefined, 'safe fixture should have no A3 findings');
});

test('A4: flags fetch() of user-controlled URL with no SSRF guard', () => {
  const r = scan(VULN_DIR, { checks: ['A4'] });
  const fetchF = r.findings.find(
    (f) => f.id === 'A4' && f.file.includes('a4_fetch.ts')
  );
  assert.ok(fetchF, 'expected A4 finding');
  assert.equal(fetchF.severity, 'high');
});

test('A5: critical when returning process.env', () => {
  const r = scan(VULN_DIR, { checks: ['A5'] });
  const envDump = r.findings.find(
    (f) =>
      f.id === 'A5' &&
      f.file.includes('a5_env.ts') &&
      f.severity === 'critical'
  );
  assert.ok(envDump, 'expected A5 critical finding for JSON.stringify(process.env)');
});

test('S1: flags unpinned deps in package.json', () => {
  const r = scan(VULN_DIR, { checks: ['S1'] });
  const s1 = r.findings.find(
    (f) => f.id === 'S1' && f.file.endsWith('package.json')
  );
  assert.ok(s1, 'expected S1 finding');
  assert.match(s1.evidence, /unpinned|semver|ranges|dependencies/i);
});

test('S2: flags known-bad typosquat package', () => {
  const r = scan(VULN_DIR, { checks: ['S2'] });
  const s2 = r.findings.find((f) => f.id === 'S2');
  assert.ok(s2, 'expected S2 finding for typosquat');
  assert.equal(s2.severity, 'critical');
  assert.match(s2.title, /modelcontextprotocol-server-filesystem/);
});

test('S3: flags module-level Map named sessionTokens as medium', () => {
  const r = scan(VULN_DIR, { checks: ['S3'] });
  const s3 = r.findings.find(
    (f) =>
      f.id === 'S3' &&
      f.file.includes('s3_state.ts') &&
      f.title.includes('sessionTokens')
  );
  assert.ok(s3, 'expected S3 finding for sessionTokens');
  assert.equal(s3.severity, 'medium');
});

test('Python: A2 flags subprocess with shell=True', () => {
  const r = scan(VULN_DIR, { checks: ['A2'] });
  const py = r.findings.find(
    (f) => f.id === 'A2' && f.file.includes('vuln_py.py')
  );
  assert.ok(py, 'expected A2 Python finding');
  assert.equal(py.severity, 'critical');
});

test('Python: A5 flags os.environ dump', () => {
  const r = scan(VULN_DIR, { checks: ['A5'] });
  const py = r.findings.find(
    (f) => f.id === 'A5' && f.file.includes('vuln_py.py')
  );
  assert.ok(py, 'expected A5 Python finding');
  assert.equal(py.severity, 'critical');
});

test('Python: A3 flags open(path) on tool arg', () => {
  const r = scan(VULN_DIR, { checks: ['A3'] });
  const py = r.findings.find(
    (f) => f.id === 'A3' && f.file.includes('vuln_py.py')
  );
  assert.ok(py, 'expected A3 Python finding');
});

test('Python: A4 flags requests.get(url) without SSRF guard', () => {
  const r = scan(VULN_DIR, { checks: ['A4'] });
  const py = r.findings.find(
    (f) => f.id === 'A4' && f.file.includes('vuln_py.py')
  );
  assert.ok(py, 'expected A4 Python finding');
});

test('Safe fixture produces no critical findings', () => {
  const r = scan(SAFE_DIR);
  const crit = r.findings.filter((f) => f.severity === 'critical');
  assert.equal(
    crit.length,
    0,
    `safe fixture should have 0 critical findings, got ${crit.length}: ${crit.map((f) => f.title).join('; ')}`
  );
});

test('Every finding has file path + line number', () => {
  const r = scan(VULN_DIR);
  for (const f of r.findings) {
    assert.ok(f.file, `finding missing file: ${JSON.stringify(f)}`);
    assert.ok(
      typeof f.line === 'number',
      `finding missing line: ${JSON.stringify(f)}`
    );
  }
});

test('--checks filter only runs chosen check', () => {
  const r = scan(VULN_DIR, { checks: ['A2'] });
  for (const f of r.findings) {
    assert.equal(f.id, 'A2', 'non-A2 finding leaked through filter');
  }
});

test('Tool count is reported', () => {
  const r = scan(VULN_DIR);
  assert.ok(r.toolCount >= 7, `expected many tools, got ${r.toolCount}`);
});
