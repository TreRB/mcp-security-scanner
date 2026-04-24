// Markdown reporter tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { renderMarkdown } from '../src/markdown.js';

function mockScan(findings = []) {
  return {
    root: '/tmp/fake',
    fileCount: 5,
    toolCount: 3,
    findings,
  };
}

test('renderMarkdown emits report header and summary', () => {
  const md = renderMarkdown(mockScan());
  assert.match(md, /^# mcp-security-scanner report/m);
  assert.match(md, /\*\*Target:\*\* `\/tmp\/fake`/);
  assert.match(md, /\*\*Files parsed:\*\* 5/);
  assert.match(md, /\*\*Tools detected:\*\* 3/);
});

test('renderMarkdown shows "No findings" when empty', () => {
  const md = renderMarkdown(mockScan());
  assert.match(md, /\*\*No findings\.\*\*/);
});

test('renderMarkdown groups findings by severity', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1,
      title: 'Shell', detail: 'bad', evidence: 'exec', fix: 'use argv' },
    { id: 'A1', severity: 'high', file: 'y.ts', line: 2,
      title: 'Schema', detail: 'bad', evidence: 'e', fix: 'f' },
    { id: 'S3', severity: 'medium', file: 'z.ts', line: 3,
      title: 'State', detail: 'bad', evidence: 'e', fix: 'f' },
  ];
  const md = renderMarkdown(mockScan(findings));
  assert.match(md, /## .+ Critical findings/);
  assert.match(md, /## .+ High findings/);
  assert.match(md, /## .+ Medium findings/);
  // Critical should come before High in the output
  const critIdx = md.indexOf('Critical findings');
  const highIdx = md.indexOf('High findings');
  assert.ok(critIdx < highIdx);
});

test('renderMarkdown emits severity emojis', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1, title: 't', detail: 'd' },
    { id: 'A1', severity: 'high', file: 'x.ts', line: 1, title: 't', detail: 'd' },
    { id: 'S3', severity: 'medium', file: 'x.ts', line: 1, title: 't', detail: 'd' },
    { id: 'S1', severity: 'low', file: 'x.ts', line: 1, title: 't', detail: 'd' },
  ];
  const md = renderMarkdown(mockScan(findings));
  assert.match(md, /🔴/);
  assert.match(md, /🟠/);
  assert.match(md, /🟡/);
  assert.match(md, /🔵/);
});

test('renderMarkdown wraps evidence in code fence', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1,
      title: 't', detail: 'd', evidence: 'exec(args.cmd)', fix: 'f' },
  ];
  const md = renderMarkdown(mockScan(findings));
  assert.match(md, /```\nexec\(args\.cmd\)\n```/);
});

test('renderMarkdown summary table counts all severities', () => {
  const findings = [
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 1, title: 't', detail: 'd' },
    { id: 'A2', severity: 'critical', file: 'x.ts', line: 2, title: 't', detail: 'd' },
    { id: 'A1', severity: 'high', file: 'x.ts', line: 1, title: 't', detail: 'd' },
  ];
  const md = renderMarkdown(mockScan(findings));
  assert.match(md, /Critical \| 2/);
  assert.match(md, /High \| 1/);
});
