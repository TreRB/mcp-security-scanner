// S1 — Dependencies unpinned.
// Parses package.json, pyproject.toml, requirements.txt and flags
// ranges that don't resolve to an exact version.

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

export const id = 'S1';
export const title = 'Dependencies unpinned';
export const blogAnchor = '#3-supply-chain-compromise-of-mcp-servers';

export function checkManifest(manifestPath) {
  const findings = [];
  const name = basename(manifestPath);
  let content;
  try {
    content = readFileSync(manifestPath, 'utf8');
  } catch {
    return findings;
  }

  if (name === 'package.json') {
    findings.push(...checkPackageJson(content, manifestPath));
  } else if (name === 'requirements.txt') {
    findings.push(...checkRequirementsTxt(content, manifestPath));
  } else if (name === 'pyproject.toml') {
    findings.push(...checkPyproject(content, manifestPath));
  }
  return findings;
}

function checkPackageJson(content, file) {
  const findings = [];
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return findings;
  }
  const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  const unpinned = [];
  for (const section of sections) {
    const deps = pkg[section];
    if (!deps) continue;
    for (const [name, version] of Object.entries(deps)) {
      if (typeof version !== 'string') continue;
      if (isUnpinned(version)) {
        unpinned.push({ name, version, section });
      }
    }
  }
  if (unpinned.length > 0) {
    findings.push({
      id,
      severity: unpinned.length >= 5 ? 'high' : 'medium',
      title: 'Unpinned dependencies',
      file,
      line: 1,
      evidence: `${unpinned.length} dependencies use semver ranges (^, ~, *, >=). Pin to exact versions.`,
      detail: unpinned
        .slice(0, 15)
        .map((u) => `  ${u.section}.${u.name}: ${u.version}`)
        .join('\n') +
        (unpinned.length > 15 ? `\n  … and ${unpinned.length - 15} more` : ''),
      fix: 'Replace `^x.y.z` and `~x.y.z` with exact `x.y.z`. Commit package-lock.json and enforce `npm ci` in CI.',
      blogAnchor,
      dataset: { unpinned },
    });
  }
  return findings;
}

function isUnpinned(ver) {
  const v = ver.trim();
  if (v === '' || v === '*' || v === 'latest') return true;
  if (v.startsWith('^') || v.startsWith('~')) return true;
  if (v.startsWith('>') || v.startsWith('<')) return true;
  if (v.includes(' - ')) return true;
  if (v.includes('||')) return true;
  if (v.startsWith('git+') || v.startsWith('http')) return false; // different problem
  if (v.startsWith('file:') || v.startsWith('workspace:')) return false;
  return false;
}

function checkRequirementsTxt(content, file) {
  const findings = [];
  const lines = content.split('\n');
  const unpinned = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/#.*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('-')) continue;
    // Package specifier: `name==x.y.z` is pinned, everything else is not.
    if (!/==/.test(line)) {
      const pkgName = line.split(/[<>=!~]/)[0].trim();
      if (pkgName) unpinned.push({ name: pkgName, version: line, line: i + 1 });
    }
  }
  if (unpinned.length > 0) {
    findings.push({
      id,
      severity: unpinned.length >= 5 ? 'high' : 'medium',
      title: 'Unpinned dependencies (requirements.txt)',
      file,
      line: unpinned[0].line,
      evidence: `${unpinned.length} Python deps not pinned with ==. Use exact versions + hashes.`,
      detail: unpinned
        .slice(0, 15)
        .map((u) => `  ${u.name}: ${u.version}`)
        .join('\n'),
      fix: 'Use `pip-compile` to generate a locked requirements.txt with `==` pins and `--generate-hashes`.',
      blogAnchor,
      dataset: { unpinned },
    });
  }
  return findings;
}

function checkPyproject(content, file) {
  const findings = [];
  // Very simple TOML-ish scan: look for `[tool.poetry.dependencies]` or
  // `dependencies = [...]` and flag ^, ~, or > bounds.
  const unpinned = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Poetry form: `foo = "^1.2.3"` or `foo = "~1.2.3"`
    const m = line.match(/^\s*([a-zA-Z0-9_\-]+)\s*=\s*["']([\^~*][^"']*)["']/);
    if (m) unpinned.push({ name: m[1], version: m[2], line: i + 1 });
    // PEP 621 form: `"foo >= 1.0"`
    const m2 = line.match(/^\s*["']([a-zA-Z0-9_\-]+)\s*(\^|~|>|<|>=|<=)/);
    if (m2) unpinned.push({ name: m2[1], version: line.trim(), line: i + 1 });
  }
  if (unpinned.length > 0) {
    findings.push({
      id,
      severity: unpinned.length >= 5 ? 'high' : 'medium',
      title: 'Unpinned dependencies (pyproject.toml)',
      file,
      line: unpinned[0].line,
      evidence: `${unpinned.length} Python deps not pinned.`,
      detail: unpinned
        .slice(0, 15)
        .map((u) => `  ${u.name}: ${u.version}`)
        .join('\n'),
      fix: 'Pin to exact versions. Maintain `poetry.lock` / `uv.lock` and install with `--frozen`.',
      blogAnchor,
      dataset: { unpinned },
    });
  }
  return findings;
}
