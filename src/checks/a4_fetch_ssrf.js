// A4 — Fetch tools accept private IPs / cloud metadata.
// Flags tools that call fetch / http.request / requests.get with a URL built
// from tool args, where there's no evidence of SSRF protection (blocklist of
// RFC 1918, 169.254.0.0/16, 127.0.0.1, metadata.google.internal, etc.).

import {
  findTools,
  findFetchCalls,
  findToolArgRefs,
  lineOf,
} from '../parse/ts.js';
import {
  findPyTools,
  findPyFetchCalls,
  lineOf as pyLineOf,
} from '../parse/py.js';

export const id = 'A4';
export const title = 'Fetch accepts private/metadata IPs';
export const blogAnchor = '#4-server-side-request-forgery-via-mcp-fetch-tools';

const SSRF_SIGNALS = [
  '169.254',
  '127.0.0.1',
  '10\\.',
  '192.168',
  '172.16',
  'metadata.google.internal',
  'metadata.azure',
  'localhost',
  'isPrivateIP',
  'blockPrivate',
  'allowlist',
  'URL_ALLOWLIST',
  'is_private',
  'ip_is_private',
  'isLoopback',
  'private_ip',
  'rfc1918',
];

export function checkTs({ src, file }) {
  const findings = [];
  const tools = findTools(src);
  for (const tool of tools) {
    const argRefs = findToolArgRefs(tool.inner);
    const argNames = [...argRefs.destructured];
    if (argRefs.argName) argNames.push(argRefs.argName);
    const fetchCalls = findFetchCalls(tool.inner);
    if (fetchCalls.length === 0) continue;

    const hasSsrfGuard = SSRF_SIGNALS.some((sig) =>
      new RegExp(sig).test(tool.inner)
    );

    for (const call of fetchCalls) {
      const references =
        argNames.some((n) =>
          new RegExp(`\\b${escape(n)}\\b`).test(call.firstArg || '')
        ) ||
        /\burl\b/i.test(call.firstArg || '');
      if (!references) continue;
      if (hasSsrfGuard) continue;
      findings.push({
        id,
        severity: 'high',
        title: `Fetch tool "${tool.name}" accepts any URL (no allowlist/blocklist)`,
        file,
        line: lineOf(src, tool.callStart + 1 + call.index),
        evidence: `${call.fn}(${(call.firstArg || '').slice(0, 80)}) — no SSRF guard detected`,
        detail:
          'Tool forwards a model-controlled URL to an outbound fetch without evidence of blocking RFC 1918, 169.254.x.x, 127.0.0.1, or cloud metadata hostnames.',
        fix: 'Resolve the hostname, reject private/link-local/loopback IPs. Prefer an explicit allowlist of external hosts. Enforce IMDSv2 on AWS hosts.',
        blogAnchor,
      });
    }
  }
  return findings;
}

function escape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function checkPy({ src, file }) {
  const findings = [];
  const tools = findPyTools(src);
  for (const tool of tools) {
    const paramNames = tool.params.map((p) => p.name);
    const fetchCalls = findPyFetchCalls(tool.body);
    if (fetchCalls.length === 0) continue;
    const hasGuard = SSRF_SIGNALS.some((sig) =>
      new RegExp(sig).test(tool.body)
    );
    for (const call of fetchCalls) {
      const references =
        paramNames.some((p) =>
          new RegExp(`\\b${p}\\b`).test(call.firstArg || call.args)
        ) || /\burl\b/.test(call.firstArg || '');
      if (!references || hasGuard) continue;
      findings.push({
        id,
        severity: 'high',
        title: `Fetch tool "${tool.name}" accepts any URL`,
        file,
        line: pyLineOf(src, tool.bodyStart + call.index),
        evidence: `${call.fn}(${(call.firstArg || '').slice(0, 80)})`,
        detail:
          'Python tool forwards model-controlled URL to HTTP library without SSRF guard.',
        fix: 'Use `ipaddress.ip_address(socket.gethostbyname(host)).is_private` check, plus explicit allowlist.',
        blogAnchor,
      });
    }
  }
  return findings;
}
