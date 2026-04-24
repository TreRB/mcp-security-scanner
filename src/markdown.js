// Markdown report — for PR comments and issue bodies.

import { countSeverities } from './report.js';

const SEV_EMOJI = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

export function renderMarkdown(scan) {
  const lines = [];
  lines.push('# mcp-security-scanner report');
  lines.push('');
  lines.push(`- **Target:** \`${scan.root}\``);
  lines.push(`- **Files parsed:** ${scan.fileCount}`);
  lines.push(`- **Tools detected:** ${scan.toolCount}`);
  lines.push(`- **Findings:** ${scan.findings.length}`);
  lines.push('');

  const counts = countSeverities(scan.findings);
  lines.push('## Summary');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|------:|');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    if (counts[sev] > 0) {
      lines.push(`| ${SEV_EMOJI[sev]} ${cap(sev)} | ${counts[sev]} |`);
    }
  }
  lines.push('');

  if (scan.findings.length === 0) {
    lines.push('**No findings.**');
    return lines.join('\n');
  }

  // Group findings by severity
  const groups = groupBySeverity(scan.findings);
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const items = groups[sev] || [];
    if (items.length === 0) continue;
    lines.push(`## ${SEV_EMOJI[sev]} ${cap(sev)} findings`);
    lines.push('');
    for (const f of items) {
      lines.push(`### ${f.id} — ${f.title}`);
      lines.push('');
      lines.push(`**Location:** \`${f.file}:${f.line || '?'}\``);
      lines.push('');
      if (f.evidence) {
        lines.push('**Evidence:**');
        lines.push('```');
        lines.push(f.evidence);
        lines.push('```');
        lines.push('');
      }
      if (f.detail && f.detail !== f.title) {
        lines.push(f.detail);
        lines.push('');
      }
      if (f.fix) {
        lines.push(`**Fix:** ${f.fix}`);
        lines.push('');
      }
    }
  }
  return lines.join('\n');
}

function groupBySeverity(findings) {
  const out = {};
  for (const f of findings) {
    if (!out[f.severity]) out[f.severity] = [];
    out[f.severity].push(f);
  }
  return out;
}

function cap(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
