// S3 — Shared module-level state.
// Flags module-level mutable state that could leak between sessions. Heuristic:
// top-level `let`/`var` declarations or `const x = new Map()`, `const x = {}`
// at module scope. A single MCP server instance reused across sessions inherits
// this state.

import { findTopLevelMutables, lineOf } from '../parse/ts.js';
import { findPyTopLevelMutables } from '../parse/py.js';

export const id = 'S3';
export const title = 'Shared module-level state';
export const blogAnchor = '#5-session-hijack-via-long-lived-connections';

export function checkTs({ src, file }) {
  const findings = [];
  const mutables = findTopLevelMutables(src);
  // Heuristic: name contains a suspicious token OR it's `let/var` and not a
  // simple constant. We avoid flagging every single import constant.
  const suspicious = mutables.filter((m) => {
    if (m.kind === 'let' || m.kind === 'var') return true;
    // const new Map/Set/{}/[]
    return /new\s+(Map|Set|WeakMap|WeakSet)|\{\s*\}|\[\s*\]/.test(m.text);
  });
  if (suspicious.length === 0) return findings;

  for (const m of suspicious) {
    // Only flag if name suggests state: cache, store, sessions, state, tokens,
    // credentials, users, auth, context, db, etc. Otherwise emit info-level.
    const stateTokens =
      /cache|store|sessions?|state|tokens?|creds?|credentials?|users?|auth|context|connections?|pool/i;
    const sev = stateTokens.test(m.name) ? 'medium' : 'info';
    findings.push({
      id,
      severity: sev,
      title: `Module-level mutable state: ${m.name}`,
      file,
      line: m.line,
      evidence: m.text,
      detail:
        'Module-level mutable state is shared by every session served from this process. Session A can read or poison state set by session B.',
      fix: 'Move state into per-session storage (SessionState keyed by sessionId). Treat module globals as read-only config.',
      blogAnchor,
    });
  }
  return findings;
}

export function checkPy({ src, file }) {
  const findings = [];
  const mutables = findPyTopLevelMutables(src);
  const stateTokens =
    /cache|store|sessions?|state|tokens?|creds?|credentials?|users?|auth|context|connections?|pool/i;
  for (const m of mutables) {
    const sev = stateTokens.test(m.name) ? 'medium' : 'info';
    findings.push({
      id,
      severity: sev,
      title: `Module-level mutable state: ${m.name}`,
      file,
      line: m.line,
      evidence: m.text,
      detail: 'Module globals are shared across MCP sessions.',
      fix: 'Move into per-session state.',
      blogAnchor,
    });
  }
  return findings;
}
