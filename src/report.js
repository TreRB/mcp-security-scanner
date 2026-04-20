// Report formatting. Both human-readable and JSON outputs.

import chalk from 'chalk';

const SEV_COLOR = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan,
  info: chalk.gray,
};

const SEV_LABEL = {
  critical: '[CRITICAL]',
  high: '[HIGH]    ',
  medium: '[MEDIUM]  ',
  low: '[LOW]     ',
  info: '[INFO]    ',
};

const BLOG_BASE = 'https://valtikstudios.com/blog/mcp-server-security-2026';

export function renderHuman(scan) {
  const lines = [];
  lines.push('');
  lines.push(
    chalk.bold.cyan('MCP SECURITY SCANNER') +
      chalk.dim('  target: ') +
      scan.root
  );
  lines.push('');
  const parsed = [
    scan.parseCounts.ts > 0 && `${scan.parseCounts.ts} ts`,
    scan.parseCounts.js > 0 && `${scan.parseCounts.js} js`,
    scan.parseCounts.py > 0 && `${scan.parseCounts.py} py`,
    scan.parseCounts.json > 0 && `${scan.parseCounts.json} json`,
    scan.parseCounts.toml > 0 && `${scan.parseCounts.toml} toml`,
  ]
    .filter(Boolean)
    .join(', ');
  lines.push(chalk.dim('Parsed: ') + `${scan.fileCount} files (${parsed || 'none'})`);
  lines.push(chalk.dim('Tools found: ') + `${scan.toolCount}`);
  lines.push('');

  if (scan.findings.length === 0) {
    lines.push(chalk.green.bold('  No findings. '));
  } else {
    for (const f of scan.findings) {
      lines.push(...renderFinding(f));
      lines.push('');
    }
  }

  // Summary
  const counts = countSeverities(scan.findings);
  lines.push(chalk.bold('Summary'));
  lines.push(
    chalk.dim('  ') +
      `${scan.toolCount} tools total, ${scan.findings.length} findings` +
      (scan.findings.length > 0 ? ` (${describe(counts)})` : '')
  );
  lines.push(chalk.dim('  Docs: ') + BLOG_BASE);

  return lines.join('\n');
}

function renderFinding(f) {
  const col = SEV_COLOR[f.severity] || chalk.white;
  const label = SEV_LABEL[f.severity] || '[?]';
  const head = `  ${col(label)}  ${f.id}  ${f.title}`;
  const lines = [head];
  lines.push(`              ${chalk.dim(`${f.file}:${f.line || '?'}`)}`);
  if (f.evidence) lines.push(`              ${f.evidence}`);
  if (f.detail && f.detail !== f.evidence)
    for (const line of wrap(f.detail, 76)) lines.push(`              ${chalk.dim(line)}`);
  if (f.fix) lines.push(`              ${chalk.green('Fix:')} ${f.fix}`);
  if (f.blogAnchor)
    lines.push(
      `              ${chalk.blue('Ref:')} ${BLOG_BASE}${f.blogAnchor}`
    );
  return lines;
}

function wrap(text, width) {
  const words = text.split(/\s+/);
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (!cur.length) cur = w;
    else if (cur.length + 1 + w.length <= width) cur += ' ' + w;
    else {
      lines.push(cur);
      cur = w;
    }
  }
  if (cur.length) lines.push(cur);
  return lines;
}

export function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

function describe(c) {
  const parts = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  if (c.info) parts.push(`${c.info} info`);
  return parts.join(', ');
}

export function renderJson(scan) {
  return JSON.stringify(
    {
      schema: 'valtik.mcp-security-scanner/v1',
      target: scan.root,
      fileCount: scan.fileCount,
      parseCounts: scan.parseCounts,
      toolCount: scan.toolCount,
      counts: countSeverities(scan.findings),
      findings: scan.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
        file: f.file,
        line: f.line,
        evidence: f.evidence,
        detail: f.detail,
        fix: f.fix,
        ref: f.blogAnchor ? `${BLOG_BASE}${f.blogAnchor}` : null,
      })),
    },
    null,
    2
  );
}
