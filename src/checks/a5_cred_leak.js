// A5 — Credentials exposed via tool result.
// Flags tools whose body references `process.env` and also returns the result
// of JSON.stringify(process.env) / returns an env var value as the tool output.

import { findTools, lineOf, snippetAt } from '../parse/ts.js';
import { findPyTools, lineOf as pyLineOf, snippetAt as pySnippet } from '../parse/py.js';

export const id = 'A5';
export const title = 'Credentials exposed via tool result';
export const blogAnchor = '#2-credential-theft-via-exposed-resources';

const SENSITIVE_ENV_PATTERNS = [
  'API_KEY',
  'SECRET',
  'TOKEN',
  'PASSWORD',
  'AWS_',
  'GITHUB_TOKEN',
  'OPENAI',
  'ANTHROPIC',
  'STRIPE',
  'DATABASE_URL',
  'PRIVATE',
];

export function checkTs({ src, file }) {
  const findings = [];
  const tools = findTools(src);
  for (const tool of tools) {
    // Direct dump:
    //   JSON.stringify(process.env)
    //   return { text: process.env.FOO }
    //   return process.env
    const hasEnvRef = /\bprocess\.env\b/.test(tool.inner);
    if (!hasEnvRef) continue;

    // Critical: stringify process.env / spreading it into result
    if (
      /JSON\.stringify\s*\(\s*process\.env\s*\)/.test(tool.inner) ||
      /\.\.\.\s*process\.env/.test(tool.inner) ||
      /return\s+process\.env\b/.test(tool.inner) ||
      /Object\.(keys|entries|values)\s*\(\s*process\.env\s*\)/.test(tool.inner)
    ) {
      const idx = tool.inner.search(
        /JSON\.stringify\s*\(\s*process\.env|\.\.\.\s*process\.env|return\s+process\.env|Object\.(?:keys|entries|values)\s*\(\s*process\.env/
      );
      findings.push({
        id,
        severity: 'critical',
        title: `Tool "${tool.name}" returns process.env to the model`,
        file,
        line: lineOf(src, tool.callStart + 1 + idx),
        evidence: snippetAt(src, tool.callStart + 1 + idx),
        detail:
          'Tool output includes the entire env dictionary — any secret (AWS keys, tokens, database URLs) becomes visible to the model and flows into its response.',
        fix: 'Never return process.env. Return only the specific values the tool is meant to expose, and redact known secret patterns before returning.',
        blogAnchor,
      });
      continue;
    }

    // Check for specific sensitive var reference reaching the return path
    const envRefReg = /process\.env\.(\w+)/g;
    let m;
    const refs = [];
    while ((m = envRefReg.exec(tool.inner)) !== null) {
      refs.push({ key: m[1], index: m.index });
    }
    const sensitive = refs.filter((r) =>
      SENSITIVE_ENV_PATTERNS.some((p) => r.key.includes(p))
    );
    if (sensitive.length === 0) continue;

    // Is any sensitive ref appearing on a `return`/`text:` path?
    for (const s of sensitive) {
      // Crude: look at surrounding 120 chars for `return` or `text:`/`content:` or `result.push`
      const ctxStart = Math.max(0, s.index - 120);
      const ctxEnd = Math.min(tool.inner.length, s.index + 120);
      const ctx = tool.inner.slice(ctxStart, ctxEnd);
      if (/\b(return|text\s*:|content\s*:|result\.push|yield)\b/.test(ctx)) {
        findings.push({
          id,
          severity: 'high',
          title: `Tool "${tool.name}" may return secret env var ${s.key}`,
          file,
          line: lineOf(src, tool.callStart + 1 + s.index),
          evidence: `process.env.${s.key} referenced within return path`,
          detail:
            'A sensitive environment variable name is referenced in the same scope as the tool\'s return statement. Manual review required.',
          fix: 'Never place secret env values directly into tool output. If the model needs a capability that requires the secret, build the capability server-side and return only a result.',
          blogAnchor,
        });
      } else {
        findings.push({
          id,
          severity: 'info',
          title: `Tool "${tool.name}" references sensitive env var ${s.key}`,
          file,
          line: lineOf(src, tool.callStart + 1 + s.index),
          evidence: `process.env.${s.key}`,
          detail:
            'Sensitive env var reference in tool body. Audit to confirm it is not leaked in the tool result.',
          fix: 'Audit manually. Redact secrets before returning anything to the model.',
          blogAnchor,
        });
      }
    }
  }
  return findings;
}

export function checkPy({ src, file }) {
  const findings = [];
  const tools = findPyTools(src);
  for (const tool of tools) {
    const envReg = /\bos\.(?:environ(?:\.get)?\s*\(\s*['"`]([^'"`]+)['"`]|environ\s*\[\s*['"`]([^'"`]+)['"`]\s*\]|getenv\s*\(\s*['"`]([^'"`]+)['"`])/g;
    let m;
    const refs = [];
    while ((m = envReg.exec(tool.body)) !== null) {
      const key = m[1] || m[2] || m[3];
      refs.push({ key, index: m.index });
    }
    const hasDump =
      /json\.dumps\s*\(\s*(?:dict\()?os\.environ/.test(tool.body) ||
      /return\s+os\.environ/.test(tool.body);
    if (hasDump) {
      findings.push({
        id,
        severity: 'critical',
        title: `Tool "${tool.name}" returns os.environ to the model`,
        file,
        line: pyLineOf(src, tool.bodyStart),
        evidence: pySnippet(src, tool.bodyStart),
        detail: 'Tool returns the full environment — all secrets leaked.',
        fix: 'Never return os.environ. Redact before returning.',
        blogAnchor,
      });
      continue;
    }
    for (const r of refs) {
      if (
        !SENSITIVE_ENV_PATTERNS.some((p) => r.key && r.key.includes(p))
      )
        continue;
      const ctx = tool.body.slice(
        Math.max(0, r.index - 120),
        Math.min(tool.body.length, r.index + 120)
      );
      if (/\breturn\b/.test(ctx)) {
        findings.push({
          id,
          severity: 'high',
          title: `Tool "${tool.name}" may return secret env var ${r.key}`,
          file,
          line: pyLineOf(src, tool.bodyStart + r.index),
          evidence: `os.environ[${r.key}] in return path`,
          detail: 'Sensitive env var in the same scope as the tool return.',
          fix: 'Audit. Never return the raw secret.',
          blogAnchor,
        });
      }
    }
  }
  return findings;
}
