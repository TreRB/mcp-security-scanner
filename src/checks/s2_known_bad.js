// S2 — Known-bad package detected.
// Cross-references declared dependencies against a hand-curated list.

import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const KNOWN_BAD_PATH = join(__dirname, '..', 'fixtures', 'known-bad.json');

export const id = 'S2';
export const title = 'Known-bad package detected';
export const blogAnchor = '#3-supply-chain-compromise-of-mcp-servers';

let knownBadCache = null;
function loadKnownBad() {
  if (knownBadCache) return knownBadCache;
  try {
    const raw = JSON.parse(readFileSync(KNOWN_BAD_PATH, 'utf8'));
    knownBadCache = raw.packages || [];
  } catch {
    knownBadCache = [];
  }
  return knownBadCache;
}

export function checkManifest(manifestPath) {
  const findings = [];
  const name = basename(manifestPath);
  let content;
  try {
    content = readFileSync(manifestPath, 'utf8');
  } catch {
    return findings;
  }
  const knownBad = loadKnownBad();
  if (knownBad.length === 0) return findings;

  if (name === 'package.json') {
    const pkg = safeJson(content);
    if (!pkg) return findings;
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {}),
    };
    for (const depName of Object.keys(allDeps)) {
      const match = knownBad.find(
        (k) => k.ecosystem === 'npm' && k.name === depName
      );
      if (match) {
        findings.push({
          id,
          severity: 'critical',
          title: `Known-bad npm package: ${depName}`,
          file: manifestPath,
          line: 1,
          evidence: `${depName}@${allDeps[depName]}`,
          detail: match.reason,
          fix:
            'Remove this dependency immediately. Rotate any credentials reachable from the install host. If your lockfile references it, scrub it out and reinstall fresh.',
          blogAnchor,
        });
      }
    }
  } else if (name === 'requirements.txt' || name === 'pyproject.toml') {
    for (const kb of knownBad) {
      if (kb.ecosystem !== 'pypi') continue;
      const re = new RegExp(
        `(^|\\s|["'\\[])${kb.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[=<>~!\\s]|$|["'])`
      );
      if (re.test(content)) {
        findings.push({
          id,
          severity: 'critical',
          title: `Known-bad PyPI package: ${kb.name}`,
          file: manifestPath,
          line: 1,
          evidence: `${kb.name} referenced in ${name}`,
          detail: kb.reason,
          fix: 'Remove immediately. Rotate credentials.',
          blogAnchor,
        });
      }
    }
  }
  return findings;
}

function safeJson(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
