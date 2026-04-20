// Light TypeScript/JavaScript scanner.
// Zero external deps: regex-first with brace-balancing for body extraction.
// Designed for MCP server SDK usage patterns, not as a general TS parser.

// Strip // line comments and /* block */ comments, preserving line count by
// turning comment chars into spaces. This lets later regex-based extraction
// still report correct line numbers.
export function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let inString = null; // '"', "'", or '`'
  while (i < n) {
    const c = src[i];
    const c2 = src[i + 1];
    if (inString) {
      out += c;
      if (c === '\\' && i + 1 < n) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (c === inString) inString = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      inString = c;
      out += c;
      i++;
      continue;
    }
    if (c === '/' && c2 === '/') {
      // line comment
      while (i < n && src[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (c === '/' && c2 === '*') {
      // block comment — preserve newlines
      i += 2;
      out += '  ';
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      if (i < n) {
        out += '  ';
        i += 2;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

export function lineOf(src, index) {
  let line = 1;
  for (let i = 0; i < index && i < src.length; i++) {
    if (src[i] === '\n') line++;
  }
  return line;
}

export function snippetAt(src, index, maxLen = 160) {
  const start = src.lastIndexOf('\n', index) + 1;
  let end = src.indexOf('\n', index);
  if (end === -1) end = src.length;
  const s = src.slice(start, end).trim();
  return s.length > maxLen ? s.slice(0, maxLen) + '…' : s;
}

// Match forward from index in `src` to find the matching closing bracket
// for an opening bracket `open` (one of '(', '{', '['). Returns -1 if not found.
export function matchBracket(src, openIndex) {
  const open = src[openIndex];
  const pairs = { '(': ')', '{': '}', '[': ']' };
  const close = pairs[open];
  if (!close) return -1;
  let depth = 0;
  let inString = null;
  for (let i = openIndex; i < src.length; i++) {
    const c = src[i];
    if (inString) {
      if (c === '\\') {
        i++;
        continue;
      }
      if (c === inString) inString = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      inString = c;
      continue;
    }
    if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Detect MCP tool registrations. We recognize a few patterns:
//   server.tool("name", schema, async (args) => { ... })
//   server.registerTool("name", { inputSchema: ... }, async ({args}) => { ... })
//   server.setRequestHandler(CallToolRequestSchema, async (req) => { ... })
//   mcp.tool("name", ...)
// Returns [{name, nameIndex, bodyStart, bodyEnd, argsList, schemaText}]
export function findTools(src) {
  const tools = [];
  // Pattern A: server.tool("name" | 'name' | `name`, ...)  or server.registerTool
  const reg = /\b(?:\w+)\.(tool|registerTool)\s*\(\s*(['"`])([^'"`]+)\2\s*,/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const name = m[3];
    const nameIndex = m.index + m[0].indexOf(m[2]);
    const openParen = src.lastIndexOf('(', reg.lastIndex - 1);
    const closeParen = openParen === -1 ? -1 : matchBracket(src, openParen);
    if (closeParen === -1) continue;
    const inner = src.slice(openParen + 1, closeParen);
    tools.push({
      name,
      nameIndex,
      callStart: openParen,
      callEnd: closeParen,
      inner,
      method: m[1],
    });
  }
  return tools;
}

// Locate all `fs.readFile`, `fs.writeFile`, `fs.promises.readFile`, `readFileSync`,
// etc. occurrences with their first-argument expression (best-effort).
export function findFsCalls(src) {
  const results = [];
  const reg =
    /\b(?:fs(?:\.promises)?\.)?((?:read|write|append)File(?:Sync)?|readdir(?:Sync)?|stat(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|createReadStream|createWriteStream|open(?:Sync)?)\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const fnName = m[1];
    const openParen = reg.lastIndex - 1;
    const closeParen = matchBracket(src, openParen);
    if (closeParen === -1) continue;
    const firstArg = extractFirstArg(src, openParen, closeParen);
    results.push({
      fnName,
      index: m.index,
      openParen,
      closeParen,
      firstArg: firstArg?.trim(),
    });
  }
  return results;
}

function extractFirstArg(src, openParen, closeParen) {
  const argsStr = src.slice(openParen + 1, closeParen);
  let depth = 0;
  let inString = null;
  for (let i = 0; i < argsStr.length; i++) {
    const c = argsStr[i];
    if (inString) {
      if (c === '\\') {
        i++;
        continue;
      }
      if (c === inString) inString = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      inString = c;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) return argsStr.slice(0, i);
  }
  return argsStr;
}

export function findChildProcessCalls(src) {
  const results = [];
  const reg =
    /\b(?:child_process\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const fn = m[1];
    const openParen = reg.lastIndex - 1;
    const closeParen = matchBracket(src, openParen);
    if (closeParen === -1) continue;
    const firstArg = extractFirstArg(src, openParen, closeParen);
    results.push({
      fn,
      index: m.index,
      openParen,
      closeParen,
      firstArg: firstArg?.trim(),
      fullArgs: src.slice(openParen + 1, closeParen),
    });
  }
  return results;
}

export function findFetchCalls(src) {
  const results = [];
  const reg =
    /\b(?:(?:axios|got|ky|undici|request)\.(?:get|post|put|delete|patch|request)|axios|fetch|http\.request|https\.request|http\.get|https\.get)\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const openParen = reg.lastIndex - 1;
    const closeParen = matchBracket(src, openParen);
    if (closeParen === -1) continue;
    const firstArg = extractFirstArg(src, openParen, closeParen);
    results.push({
      fn: m[0].replace(/\s*\($/, ''),
      index: m.index,
      openParen,
      closeParen,
      firstArg: firstArg?.trim(),
    });
  }
  return results;
}

// Detect references like process.env.FOO, process.env['FOO']
export function findProcessEnvRefs(src) {
  const results = [];
  const reg = /\bprocess\.env\b(?:\.(\w+)|\[\s*['"`]([^'"`]+)['"`]\s*\])?/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    results.push({
      index: m.index,
      key: m[1] || m[2] || null,
    });
  }
  return results;
}

// Find module-level let/var mutable declarations (not const) in the top-level scope.
// Very heuristic: brace-depth tracking on the stripped source.
export function findTopLevelMutables(src) {
  const results = [];
  let depth = 0;
  let inString = null;
  const lines = src.split('\n');
  let offset = 0;
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];
    const trimmed = line.trim();
    if (
      depth === 0 &&
      (/^(export\s+)?(let|var)\s+\w+/.test(trimmed) ||
        /^(export\s+)?const\s+\w+\s*(?::\s*[A-Za-z<>[\]{}|,\s]+)?\s*=\s*(new\s+(Map|Set|WeakMap|WeakSet)\b|\{\s*\}|\[\s*\])/.test(
          trimmed
        ))
    ) {
      const m = trimmed.match(
        /^(?:export\s+)?(let|var|const)\s+(\w+)/
      );
      if (m) {
        results.push({
          kind: m[1],
          name: m[2],
          line: li + 1,
          text: trimmed,
        });
      }
    }
    // Update depth by counting braces outside strings
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inString) {
        if (c === '\\') {
          i++;
          continue;
        }
        if (c === inString) inString = null;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') {
        inString = c;
        continue;
      }
      if (c === '{') depth++;
      else if (c === '}') depth--;
    }
    offset += line.length + 1;
  }
  return results;
}

// Extract arg destructure in a tool body: `async ({path, content}) => {...}`
// or `async (args) => { args.path }`. Returns { argName: 'args' | null, destructured: ['path'] }.
export function findToolArgRefs(inner) {
  // Look for arrow fn with destructured params: `({foo, bar})` or `(args)`.
  const destructure = inner.match(/\(\s*\{([^}]*)\}\s*(?::\s*[^)]+)?\)\s*=>/);
  if (destructure) {
    const names = destructure[1]
      .split(',')
      .map((s) => s.trim().split(/[:=]/)[0].trim())
      .filter(Boolean);
    return { argName: null, destructured: names };
  }
  const simple = inner.match(/\(\s*(\w+)\s*(?::\s*[^)]+)?\)\s*=>/);
  if (simple) {
    return { argName: simple[1], destructured: [] };
  }
  const simpleAsync = inner.match(
    /async\s*\(\s*(\w+)\s*(?::\s*[^)]+)?\)\s*=>/
  );
  if (simpleAsync) {
    return { argName: simpleAsync[1], destructured: [] };
  }
  return { argName: null, destructured: [] };
}
