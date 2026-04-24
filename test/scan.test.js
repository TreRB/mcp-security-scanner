// Scan layer tests: min-severity filter, baseline, fingerprint.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import { scan, fingerprint } from '../src/scan.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VULN_DIR = join(__dirname, 'fixtures', 'vulnerable');

test('scan minSeverity=critical drops non-critical findings', () => {
  const r = scan(VULN_DIR, { minSeverity: 'critical' });
  for (const f of r.findings) {
    assert.equal(f.severity, 'critical');
  }
  assert.ok(r.findings.length > 0);
});

test('scan minSeverity=high keeps high + critical', () => {
  const r = scan(VULN_DIR, { minSeverity: 'high' });
  const allowed = new Set(['critical', 'high']);
  for (const f of r.findings) {
    assert.ok(allowed.has(f.severity), `unexpected: ${f.severity}`);
  }
});

test('scan minSeverity=info keeps everything', () => {
  const r = scan(VULN_DIR, { minSeverity: 'info' });
  const baseline = scan(VULN_DIR);
  assert.equal(r.findings.length, baseline.findings.length);
});

test('scan minSeverity=low drops only info-level findings', () => {
  const r = scan(VULN_DIR, { minSeverity: 'low' });
  for (const f of r.findings) {
    assert.notEqual(f.severity, 'info');
  }
});

test('scan minSeverity=invalid is ignored (no-op)', () => {
  const baseline = scan(VULN_DIR);
  const r = scan(VULN_DIR, { minSeverity: 'bogus' });
  assert.equal(r.findings.length, baseline.findings.length);
});

test('scan fingerprint is stable across runs', () => {
  const r1 = scan(VULN_DIR);
  const r2 = scan(VULN_DIR);
  const fps1 = r1.findings.map(fingerprint).sort();
  const fps2 = r2.findings.map(fingerprint).sort();
  assert.deepEqual(fps1, fps2);
});

test('scan baseline file filters out known findings', () => {
  const r1 = scan(VULN_DIR);
  const first = r1.findings[0];
  const tmpdir_ = mkdtempSync(join(tmpdir(), 'mcp-sec-'));
  try {
    const baselinePath = join(tmpdir_, 'baseline.json');
    writeFileSync(
      baselinePath,
      JSON.stringify({ findings: [first] }),
    );
    const r2 = scan(VULN_DIR, { baseline: baselinePath });
    // The baselined finding should be excluded
    const stillPresent = r2.findings.some(
      (f) => fingerprint(f) === fingerprint(first)
    );
    assert.equal(stillPresent, false);
  } finally {
    rmSync(tmpdir_, { recursive: true });
  }
});

test('scan sorts findings critical-first', () => {
  const r = scan(VULN_DIR);
  const sevs = r.findings.map((f) => f.severity);
  // critical/high should come before medium/low
  const firstMedIdx = sevs.findIndex((s) => s === 'medium');
  const lastHighIdx = sevs.lastIndexOf('high');
  const lastCritIdx = sevs.lastIndexOf('critical');
  if (firstMedIdx !== -1 && lastCritIdx !== -1) {
    assert.ok(lastCritIdx < firstMedIdx,
      'all critical should come before first medium');
  }
  if (firstMedIdx !== -1 && lastHighIdx !== -1) {
    assert.ok(lastHighIdx < firstMedIdx,
      'all high should come before first medium');
  }
});

test('scan reports parseCounts by extension', () => {
  const r = scan(VULN_DIR);
  assert.ok(typeof r.parseCounts === 'object');
  assert.ok(r.parseCounts.ts >= 1 || r.parseCounts.js >= 1 ||
            r.parseCounts.py >= 1,
            'expected at least one ts/js/py file parsed');
});

test('scan returns empty findings for non-existent root gracefully', () => {
  const r = scan('/nonexistent/path/xxxxx');
  assert.equal(r.findings.length, 0);
  assert.equal(r.fileCount, 0);
});
