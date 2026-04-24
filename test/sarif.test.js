// Unit tests for the SARIF reporter.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderSarif, SARIF_SCHEMA_URL } from '../src/sarif.js';
import { CHECK_IDS } from '../src/checks/index.js';

function mockScan(findings = []) {
  return {
    root: '/tmp/fake',
    fileCount: 10,
    parseCounts: { ts: 5, js: 2, py: 3, json: 1, toml: 0 },
    toolCount: 7,
    findings,
  };
}

test('renderSarif produces a valid SARIF 2.1.0 document', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  assert.equal(doc.version, '2.1.0');
  assert.equal(doc.$schema, SARIF_SCHEMA_URL);
  assert.ok(Array.isArray(doc.runs));
  assert.equal(doc.runs.length, 1);
});

test('renderSarif includes driver metadata', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  const driver = doc.runs[0].tool.driver;
  assert.equal(driver.name, 'mcp-security-scanner');
  assert.match(driver.version, /^\d+\.\d+\.\d+/);
  assert.ok(driver.informationUri.includes('github.com'));
});

test('renderSarif auto-registers every CHECK_ID as a rule', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  const rules = doc.runs[0].tool.driver.rules;
  const ruleIds = new Set(rules.map((r) => r.id));
  for (const id of CHECK_IDS) {
    assert.ok(
      ruleIds.has(`MCP-${id}`),
      `rule MCP-${id} missing from SARIF driver`
    );
  }
});

test('renderSarif every rule has text+markdown help', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  for (const r of doc.runs[0].tool.driver.rules) {
    assert.ok(r.help, `rule ${r.id} missing help`);
    assert.ok(r.help.text, `rule ${r.id} missing help.text`);
    assert.ok(r.help.markdown, `rule ${r.id} missing help.markdown`);
  }
});

test('renderSarif every rule has security-severity tag', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  for (const r of doc.runs[0].tool.driver.rules) {
    assert.ok(r.properties, `rule ${r.id} missing properties`);
    assert.ok(Array.isArray(r.properties.tags));
    assert.ok(r.properties.tags.includes('security'));
    assert.ok(r.properties.tags.includes('mcp'));
  }
});

test('renderSarif maps severity → level correctly', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1,
      title: 't', detail: 'd' },
    { id: 'A1', severity: 'high', file: 'x.ts', line: 2,
      title: 't', detail: 'd' },
    { id: 'A3', severity: 'medium', file: 'x.ts', line: 3,
      title: 't', detail: 'd' },
    { id: 'S3', severity: 'low', file: 'x.ts', line: 4,
      title: 't', detail: 'd' },
    { id: 'S1', severity: 'info', file: 'x.ts', line: 5,
      title: 't', detail: 'd' },
  ];
  const doc = JSON.parse(renderSarif(mockScan(findings)));
  const levels = doc.runs[0].results.map((r) => r.level);
  assert.deepEqual(levels, ['error', 'error', 'warning', 'note', 'note']);
});

test('renderSarif result has physicalLocation with startLine', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'src/tool.ts', line: 42,
      title: 't', detail: 'd', evidence: 'e', fix: 'f' },
  ];
  const doc = JSON.parse(renderSarif(mockScan(findings)));
  const loc = doc.runs[0].results[0].locations[0];
  assert.equal(loc.physicalLocation.artifactLocation.uri, 'src/tool.ts');
  assert.equal(loc.physicalLocation.region.startLine, 42);
});

test('renderSarif result properties include evidence and fix', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1,
      title: 't', detail: 'd',
      evidence: 'shell concat', fix: 'use execFile' },
  ];
  const doc = JSON.parse(renderSarif(mockScan(findings)));
  const props = doc.runs[0].results[0].properties;
  assert.equal(props.evidence, 'shell concat');
  assert.equal(props.fix, 'use execFile');
  assert.equal(props.severity, 'critical');
  assert.equal(props['security-severity'], '9.1');
});

test('renderSarif includes invocation timestamp', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  const inv = doc.runs[0].invocations[0];
  assert.equal(inv.executionSuccessful, true);
  assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(inv.endTimeUtc));
});

test('renderSarif run.properties carries scan totals', () => {
  const doc = JSON.parse(renderSarif(mockScan()));
  const props = doc.runs[0].properties;
  assert.equal(props.target, '/tmp/fake');
  assert.equal(props.fileCount, 10);
  assert.equal(props.toolCount, 7);
  assert.ok(props.counts);
});

test('renderSarif handles finding with no line number (manifest)', () => {
  const findings = [
    { id: 'S1', severity: 'medium', file: 'package.json', line: 0,
      title: 't', detail: 'd' },
  ];
  const doc = JSON.parse(renderSarif(mockScan(findings)));
  const loc = doc.runs[0].results[0].locations[0];
  // line=0 should not emit a region
  assert.equal(loc.physicalLocation.region, undefined);
});
