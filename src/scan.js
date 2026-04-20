// File walker + dispatcher.
// Walks the target directory, dispatches per-file-type checks, aggregates
// findings, counts tools.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, basename, relative } from 'node:path';

import { CHECKS, CHECK_IDS, sevRank } from './checks/index.js';
import { stripComments as stripTsComments, findTools } from './parse/ts.js';
import { stripPyComments, findPyTools } from './parse/py.js';

const DEFAULT_IGNORE = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.cache',
  '__pycache__',
  '.venv',
  'venv',
  'env',
  '.tox',
  'coverage',
  '.pytest_cache',
  '.mypy_cache',
]);

const TS_EXT = new Set(['.ts', '.tsx', '.mts', '.cts']);
const JS_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs']);
const PY_EXT = new Set(['.py']);

export function walk(root, { maxFiles = 5000 } = {}) {
  const out = { source: [], manifests: [] };
  const stack = [root];
  let count = 0;
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const path = join(cur, entry.name);
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORE.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;
        stack.push(path);
      } else if (entry.isFile()) {
        count++;
        if (count > maxFiles) break;
        const ext = extname(entry.name).toLowerCase();
        const base = basename(entry.name);
        if (TS_EXT.has(ext) || JS_EXT.has(ext) || PY_EXT.has(ext)) {
          out.source.push(path);
        } else if (
          base === 'package.json' ||
          base === 'pyproject.toml' ||
          base === 'requirements.txt'
        ) {
          out.manifests.push(path);
        }
      }
    }
  }
  return out;
}

export function detectLanguage(auto, files) {
  if (auto !== 'auto') return auto;
  let ts = 0;
  let js = 0;
  let py = 0;
  for (const f of files.source) {
    const ext = extname(f).toLowerCase();
    if (TS_EXT.has(ext)) ts++;
    else if (JS_EXT.has(ext)) js++;
    else if (PY_EXT.has(ext)) py++;
  }
  // Mixed is fine — runner decides per-file.
  return 'auto';
}

export function scan(root, opts = {}) {
  const {
    checks = CHECK_IDS,
    baseline = null,
    language = 'auto',
  } = opts;

  const files = walk(root);
  const findings = [];
  const parseCounts = { ts: 0, js: 0, py: 0, json: 0, toml: 0 };
  let toolCount = 0;

  // Source checks
  for (const file of files.source) {
    const ext = extname(file).toLowerCase();
    const rel = relative(root, file);
    let raw;
    try {
      raw = readFileSync(file, 'utf8');
    } catch {
      continue;
    }
    const isPy = PY_EXT.has(ext);
    const isTsJs = TS_EXT.has(ext) || JS_EXT.has(ext);
    if (!isPy && !isTsJs) continue;

    const stripped = isPy ? stripPyComments(raw) : stripTsComments(raw);
    if (TS_EXT.has(ext)) parseCounts.ts++;
    else if (JS_EXT.has(ext)) parseCounts.js++;
    else if (PY_EXT.has(ext)) parseCounts.py++;

    if (isPy) {
      toolCount += findPyTools(stripped).length;
    } else {
      toolCount += findTools(stripped).length;
    }

    for (const checkId of checks) {
      const check = CHECKS[checkId];
      if (!check) continue;
      if (isPy && typeof check.checkPy === 'function') {
        try {
          const out = check.checkPy({ src: stripped, file: rel });
          if (out) findings.push(...out);
        } catch (err) {
          findings.push(makeError(checkId, rel, err));
        }
      } else if (isTsJs && typeof check.checkTs === 'function') {
        try {
          const out = check.checkTs({ src: stripped, file: rel });
          if (out) findings.push(...out);
        } catch (err) {
          findings.push(makeError(checkId, rel, err));
        }
      }
    }
  }

  // Manifest checks
  for (const manifest of files.manifests) {
    const rel = relative(root, manifest);
    if (basename(manifest) === 'package.json') parseCounts.json++;
    else if (basename(manifest) === 'pyproject.toml') parseCounts.toml++;
    for (const checkId of checks) {
      const check = CHECKS[checkId];
      if (!check || typeof check.checkManifest !== 'function') continue;
      try {
        const out = check.checkManifest(manifest);
        if (out) {
          for (const f of out) {
            f.file = relative(root, f.file);
            findings.push(f);
          }
        }
      } catch (err) {
        findings.push(makeError(checkId, rel, err));
      }
    }
  }

  // Apply baseline filter
  const baselineSet = loadBaseline(baseline);
  const filtered = findings.filter((f) => !baselineSet.has(fingerprint(f)));

  // Sort by severity descending, then file/line
  filtered.sort((a, b) => {
    const s = sevRank(b.severity) - sevRank(a.severity);
    if (s !== 0) return s;
    if (a.file < b.file) return -1;
    if (a.file > b.file) return 1;
    return (a.line || 0) - (b.line || 0);
  });

  return {
    root,
    parseCounts,
    fileCount:
      parseCounts.ts +
      parseCounts.js +
      parseCounts.py +
      parseCounts.json +
      parseCounts.toml,
    toolCount,
    findings: filtered,
  };
}

function makeError(checkId, file, err) {
  return {
    id: checkId,
    severity: 'info',
    title: `Internal scanner error in check ${checkId}`,
    file,
    line: 0,
    evidence: String(err && err.message ? err.message : err),
    detail: 'The scanner hit an unexpected condition. Please report.',
    fix: 'Open an issue at https://github.com/TreRB/mcp-security-scanner/issues',
    blogAnchor: '',
  };
}

export function fingerprint(f) {
  return [f.id, f.file, f.line, f.title].join('::');
}

function loadBaseline(path) {
  if (!path) return new Set();
  try {
    const raw = readFileSync(path, 'utf8');
    const data = JSON.parse(raw);
    const entries = (data.findings || []).map(fingerprint);
    return new Set(entries);
  } catch {
    return new Set();
  }
}
