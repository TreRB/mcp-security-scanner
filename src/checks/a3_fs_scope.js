// A3 — Filesystem scope unbounded.
// Flags read_file / write_file tools that forward a user-supplied path directly
// into `fs.readFile` / `fs.writeFile` (or Python equivalents) without a sandbox
// check (path.resolve + prefix test, startsWith(rootDir), etc.).

import {
  findTools,
  findFsCalls,
  findToolArgRefs,
  lineOf,
  snippetAt,
} from '../parse/ts.js';
import {
  findPyTools,
  findPyFileCalls,
  lineOf as pyLineOf,
  snippetAt as pySnippet,
} from '../parse/py.js';

export const id = 'A3';
export const title = 'Filesystem scope unbounded';
export const blogAnchor = '#2-credential-theft-via-exposed-resources';

export function checkTs({ src, file }) {
  const findings = [];
  const tools = findTools(src);
  for (const tool of tools) {
    const argRefs = findToolArgRefs(tool.inner);
    const argNames = [...argRefs.destructured];
    if (argRefs.argName) argNames.push(argRefs.argName);
    if (argNames.length === 0) continue;

    const fsCalls = findFsCalls(tool.inner);
    if (fsCalls.length === 0) continue;

    const hasSandboxCheck = detectSandbox(tool.inner);

    for (const call of fsCalls) {
      const referencesArg = argNames.some((n) =>
        new RegExp(`\\b${escape(n)}\\b`).test(call.firstArg || '')
      );
      if (!referencesArg) continue;
      if (hasSandboxCheck) continue;

      findings.push({
        id,
        severity: 'high',
        title: `Unbounded filesystem access in tool "${tool.name}"`,
        file,
        line: lineOf(src, tool.callStart + 1 + call.index),
        evidence: `${call.fnName}(${call.firstArg}) — no sandbox check`,
        detail:
          'Tool argument flows into an fs.* call without evidence of a sandbox prefix check. A prompt injection can escape to read/write arbitrary files.',
        fix: 'Resolve the path via `path.resolve(ROOT, args.path)` then assert `resolved.startsWith(ROOT + path.sep)`. Reject symlinks that escape.',
        blogAnchor,
      });
    }
  }
  return findings;
}

function detectSandbox(body) {
  // Heuristics: presence of path.resolve + startsWith, or a configured ROOT check,
  // or normalize-path-plus-prefix, or use of realpath + comparison.
  if (/path\.resolve\([^)]*\)[\s\S]{0,200}startsWith\(/.test(body)) return true;
  if (/\bnormalize\([^)]*\)[\s\S]{0,120}startsWith\(/.test(body)) return true;
  if (/\brealpath(?:Sync)?\s*\([^)]*\)[\s\S]{0,200}startsWith\(/.test(body))
    return true;
  if (/\bisAbsolute\s*\(/.test(body) && /startsWith\(/.test(body)) return true;
  if (/sandbox|allowedRoots|rootDir|ROOT_DIR|baseDir/i.test(body) && /startsWith|includes/.test(body))
    return true;
  return false;
}

function escape(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function checkPy({ src, file }) {
  const findings = [];
  const tools = findPyTools(src);
  for (const tool of tools) {
    const paramNames = tool.params.map((p) => p.name);
    if (paramNames.length === 0) continue;
    const fileCalls = findPyFileCalls(tool.body);
    if (fileCalls.length === 0) continue;
    const hasSandbox = detectPySandbox(tool.body);
    for (const call of fileCalls) {
      const references = paramNames.some((p) =>
        new RegExp(`\\b${p}\\b`).test(call.firstArg || call.args || '')
      );
      if (!references || hasSandbox) continue;
      findings.push({
        id,
        severity: 'high',
        title: `Unbounded filesystem access in tool "${tool.name}"`,
        file,
        line: pyLineOf(src, tool.bodyStart + call.index),
        evidence: `${call.fn}(${(call.firstArg || call.args || '').slice(0, 80)}) — no sandbox check`,
        detail:
          'Python tool opens a path derived from its arg without a sandbox prefix check.',
        fix: 'Use `Path(ROOT).resolve() / user_path` and assert `resolved.is_relative_to(root)`.',
        blogAnchor,
      });
    }
  }
  return findings;
}

function detectPySandbox(body) {
  if (/\.is_relative_to\(/.test(body)) return true;
  if (/\.resolve\(\)/.test(body) && /startswith\(/.test(body)) return true;
  if (/os\.path\.realpath\(/.test(body) && /startswith\(/.test(body)) return true;
  if (/commonpath\(/.test(body)) return true;
  return false;
}
