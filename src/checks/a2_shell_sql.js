// A2 — Shell / SQL passthrough.
// Flags tools whose body passes a tool argument directly into child_process
// shell APIs, raw SQL via `db.query(args.x)`, or equivalent Python sinks.

import {
  findTools,
  findChildProcessCalls,
  findToolArgRefs,
  lineOf,
  snippetAt,
} from '../parse/ts.js';
import {
  findPyTools,
  findPyShellCalls,
  lineOf as pyLineOf,
  snippetAt as pySnippet,
} from '../parse/py.js';

export const id = 'A2';
export const title = 'Shell or SQL passthrough';
export const blogAnchor = '#1-prompt-injection-into-tool-arguments';

export function checkTs({ src, file }) {
  const findings = [];
  const tools = findTools(src);
  for (const tool of tools) {
    const argRefs = findToolArgRefs(tool.inner);
    const argNames = collectArgNames(argRefs);

    // Shell calls inside this tool's inner
    const shellCalls = findChildProcessCalls(tool.inner);
    for (const sc of shellCalls) {
      if (referencesArg(sc.firstArg, argNames)) {
        findings.push({
          id,
          severity: 'critical',
          title: `Shell passthrough in tool "${tool.name}"`,
          file,
          line: lineOf(src, tool.callStart + 1 + sc.index),
          evidence: `${sc.fn}(${sc.firstArg}) — user-controlled input to shell`,
          detail:
            'Tool argument flows directly into child_process shell API. Any LLM-influenced input executes as a shell command.',
          fix: 'Parameterize. Use `execFile` with an argv array. Reject shell metacharacters at schema level. Prefer a fixed allowlist of commands.',
          blogAnchor,
        });
      } else if (
        /`.*\$\{.*\}.*`/.test(sc.firstArg || '') ||
        /\+/.test(sc.firstArg || '')
      ) {
        findings.push({
          id,
          severity: 'high',
          title: `String-concatenated shell command in tool "${tool.name}"`,
          file,
          line: lineOf(src, tool.callStart + 1 + sc.index),
          evidence: `${sc.fn}(${sc.firstArg})`,
          detail:
            'Shell command assembled with template literal or string concat — likely sink for injection.',
          fix: 'Use argv form (`execFile(cmd, [arg1, arg2])`). Never interpolate user input into a shell string.',
          blogAnchor,
        });
      }
    }

    // Raw SQL: look for `.query(...)` / `.execute(...)` / `.exec(...)` calls whose
    // first argument references an arg.
    const sqlReg = /\b(\w+)\s*\.\s*(query|execute|exec|run|all|get)\s*\(([^)]*)\)/g;
    let m;
    while ((m = sqlReg.exec(tool.inner)) !== null) {
      const sqlArg = m[3] || '';
      // Heuristic: the call text includes a SQL keyword (SELECT/INSERT/...) or the
      // first arg is an argument reference, and there's no `?` parameter placeholder.
      const hasSqlKeyword =
        /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT|REVOKE)\b/i.test(
          sqlArg
        );
      const hasPlaceholder = /[?$]\d?/.test(sqlArg);
      const refs = referencesArg(sqlArg, argNames);
      if (hasSqlKeyword && refs && !hasPlaceholder) {
        findings.push({
          id,
          severity: 'critical',
          title: `Raw SQL built from tool args in tool "${tool.name}"`,
          file,
          line: lineOf(src, tool.callStart + 1 + m.index),
          evidence: `${m[1]}.${m[2]}(${sqlArg.slice(0, 120)}${sqlArg.length > 120 ? '…' : ''})`,
          detail:
            'Tool argument concatenated into SQL string. LLM-influenced input becomes SQL — classic injection.',
          fix: 'Use parameterized queries (`db.query(sql, [args.id])`). Ship a tool that takes `{table, filters}` and assemble SQL server-side.',
          blogAnchor,
        });
      } else if (hasSqlKeyword && /`.*\$\{/.test(sqlArg)) {
        findings.push({
          id,
          severity: 'high',
          title: `Template-literal SQL in tool "${tool.name}"`,
          file,
          line: lineOf(src, tool.callStart + 1 + m.index),
          evidence: `${m[1]}.${m[2]}(...)`,
          detail: 'SQL built via template literal — high injection risk.',
          fix: 'Use parameter placeholders, not template literals.',
          blogAnchor,
        });
      }
    }
  }
  return findings;
}

function collectArgNames({ argName, destructured }) {
  const names = [...destructured];
  if (argName) names.push(argName);
  return names;
}

function referencesArg(expr, argNames) {
  if (!expr) return false;
  for (const n of argNames) {
    if (!n) continue;
    const re = new RegExp(`\\b${escapeRegExp(n)}\\b(?:\\.\\w+|\\[|\\s*\\)|\\s*,|\\s*\\+|\\s*$|\\s*})`);
    if (re.test(expr)) return true;
    // Also match `args.cmd` if n === 'args'
  }
  return false;
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function checkPy({ src, file }) {
  const findings = [];
  const tools = findPyTools(src);
  for (const tool of tools) {
    const paramNames = tool.params.map((p) => p.name);
    const shellCalls = findPyShellCalls(tool.body);
    for (const sc of shellCalls) {
      const references = paramNames.some((p) =>
        new RegExp(`\\b${p}\\b`).test(sc.args)
      );
      if (references && (sc.shellTrue || sc.fn.startsWith('os.'))) {
        findings.push({
          id,
          severity: 'critical',
          title: `Shell passthrough in tool "${tool.name}"`,
          file,
          line: pyLineOf(src, tool.bodyStart + sc.index),
          evidence: `${sc.fn}(...) with shell=True / os.system — input: ${sc.args.slice(0, 100)}`,
          detail:
            'Python tool forwards LLM-controlled argument into a shell. Prompt injection → RCE.',
          fix: 'Use `subprocess.run([...], shell=False)` with an argv list. Reject shell metacharacters in the schema.',
          blogAnchor,
        });
      } else if (references) {
        findings.push({
          id,
          severity: 'medium',
          title: `User-controlled input to subprocess in tool "${tool.name}"`,
          file,
          line: pyLineOf(src, tool.bodyStart + sc.index),
          evidence: `${sc.fn}(${sc.args.slice(0, 100)})`,
          detail:
            'Tool argument flows into subprocess call (shell=False is default). Audit command assembly for injection.',
          fix: 'Ensure argv form, strict allowlist for executables, schema-validated parameters.',
          blogAnchor,
        });
      }
    }

    // SQL: cursor.execute(f"...") or cursor.execute("SELECT ..." + x)
    const sqlReg =
      /\b(\w+)\s*\.\s*(execute|executemany|executescript)\s*\(\s*(f?['"`])/g;
    let m;
    while ((m = sqlReg.exec(tool.body)) !== null) {
      const isFString = m[3].startsWith('f');
      const referencesParam = paramNames.some((p) =>
        new RegExp(`\\{[^}]*\\b${p}\\b`).test(tool.body.slice(m.index, m.index + 200))
      );
      if (isFString && referencesParam) {
        findings.push({
          id,
          severity: 'critical',
          title: `f-string SQL from tool args in tool "${tool.name}"`,
          file,
          line: pyLineOf(src, tool.bodyStart + m.index),
          evidence: `${m[1]}.${m[2]}(f"...{param}...")`,
          detail:
            'SQL built via f-string embedding tool arg — SQL injection.',
          fix: 'Use parameterized execute: `cursor.execute("... WHERE id = ?", (args.id,))`.',
          blogAnchor,
        });
      }
    }
  }
  return findings;
}
