// Python parser — regex-first. Targets the official `mcp` SDK's decorator
// style plus raw FastMCP usage.

export function stripPyComments(src) {
  // Strip # comments (preserve newlines). Docstrings left intact because the
  // rules we care about don't fire inside them.
  let out = '';
  let inString = null;
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (inString) {
      out += c;
      if (c === '\\' && i + 1 < src.length) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (c === inString) inString = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'") {
      // triple-quote
      if (src.slice(i, i + 3) === c.repeat(3)) {
        out += src.slice(i, i + 3);
        const close = src.indexOf(c.repeat(3), i + 3);
        if (close === -1) {
          out += src.slice(i + 3);
          return out;
        }
        out += src.slice(i + 3, close + 3);
        i = close + 3;
        continue;
      }
      inString = c;
      out += c;
      i++;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') {
        out += ' ';
        i++;
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

// Find MCP tool definitions.
// Supports:
//   @mcp.tool()
//   def run_command(cmd: str) -> str: ...
//   @server.tool("name")
//   @mcp.tool(name="run_command")
export function findPyTools(src) {
  const tools = [];
  const reg =
    /@(\w+)\.tool\s*\(([^)]*)\)\s*\r?\n\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*[^:]+)?:/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const decoratorArgs = m[2];
    const fnName = m[3];
    const paramList = m[4];
    // Extract tool "name" if present, else function name
    let name = fnName;
    const nameMatch = decoratorArgs.match(/['"]([^'"]+)['"]/);
    if (nameMatch) name = nameMatch[1];
    const params = paramList
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => {
        const parts = p.split(':');
        return {
          name: parts[0].trim(),
          type: parts[1]?.trim() || null,
        };
      });
    // Extract function body by indentation — find next non-indented line
    const defStart = src.indexOf(`def ${fnName}`, m.index);
    const bodyStart = src.indexOf('\n', src.indexOf(':', defStart)) + 1;
    let bodyEnd = src.length;
    const lines = src.slice(bodyStart).split('\n');
    let baseIndent = null;
    let offset = bodyStart;
    for (const line of lines) {
      if (line.trim() === '') {
        offset += line.length + 1;
        continue;
      }
      const indent = line.match(/^(\s*)/)[1].length;
      if (baseIndent === null) {
        baseIndent = indent;
      } else if (indent < baseIndent && line.trim() !== '') {
        bodyEnd = offset;
        break;
      }
      offset += line.length + 1;
    }
    tools.push({
      name,
      fnName,
      params,
      decoratorIndex: m.index,
      defStart,
      bodyStart,
      bodyEnd,
      body: src.slice(bodyStart, bodyEnd),
    });
  }
  return tools;
}

export function findPyShellCalls(src) {
  const results = [];
  const reg =
    /\b(?:subprocess\.)?(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const openParen = reg.lastIndex - 1;
    // Look for shell=True in the full call
    const close = findMatchingParen(src, openParen);
    if (close === -1) continue;
    const args = src.slice(openParen + 1, close);
    const shellTrue = /\bshell\s*=\s*True\b/.test(args);
    results.push({
      fn: m[1],
      index: m.index,
      openParen,
      closeParen: close,
      args,
      shellTrue,
    });
  }
  // Also os.system / os.popen
  const osReg = /\bos\.(system|popen)\s*\(/g;
  while ((m = osReg.exec(src)) !== null) {
    const openParen = osReg.lastIndex - 1;
    const close = findMatchingParen(src, openParen);
    if (close === -1) continue;
    const args = src.slice(openParen + 1, close);
    results.push({
      fn: `os.${m[1]}`,
      index: m.index,
      openParen,
      closeParen: close,
      args,
      shellTrue: true,
    });
  }
  return results;
}

export function findPyFileCalls(src) {
  const results = [];
  // open(...) at module/function scope — treat as file op
  const reg = /\bopen\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const openParen = reg.lastIndex - 1;
    const close = findMatchingParen(src, openParen);
    if (close === -1) continue;
    const args = src.slice(openParen + 1, close);
    results.push({
      fn: 'open',
      index: m.index,
      openParen,
      closeParen: close,
      args,
      firstArg: extractFirstPyArg(args),
    });
  }
  // pathlib.Path(x).read_text() / .read_bytes() / .write_text()
  const pathlibReg =
    /\bPath\s*\(([^)]+)\)\s*\.\s*(read_text|read_bytes|write_text|write_bytes)\s*\(/g;
  while ((m = pathlibReg.exec(src)) !== null) {
    results.push({
      fn: `Path.${m[2]}`,
      index: m.index,
      firstArg: m[1]?.trim(),
      args: m[1],
    });
  }
  return results;
}

export function findPyFetchCalls(src) {
  const results = [];
  const reg =
    /\b(?:requests|httpx|urllib\.request|urllib3|aiohttp\.ClientSession)(?:\.(?:get|post|put|delete|patch|request|urlopen))?\s*\(/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    const openParen = reg.lastIndex - 1;
    const close = findMatchingParen(src, openParen);
    if (close === -1) continue;
    const args = src.slice(openParen + 1, close);
    results.push({
      fn: m[0].replace(/\s*\($/, ''),
      index: m.index,
      firstArg: extractFirstPyArg(args),
      args,
    });
  }
  return results;
}

export function findPyEnvRefs(src) {
  const results = [];
  const reg =
    /\bos\.environ(?:\.get\s*\(\s*['"`]([^'"`]+)['"`]|\[\s*['"`]([^'"`]+)['"`]\s*\])?/g;
  let m;
  while ((m = reg.exec(src)) !== null) {
    results.push({
      index: m.index,
      key: m[1] || m[2] || null,
    });
  }
  // getenv
  const getenvReg = /\bos\.getenv\s*\(\s*['"`]([^'"`]+)['"`]/g;
  while ((m = getenvReg.exec(src)) !== null) {
    results.push({
      index: m.index,
      key: m[1],
    });
  }
  return results;
}

export function findPyTopLevelMutables(src) {
  const results = [];
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Must have zero leading whitespace for module-level
    if (/^\s/.test(line)) continue;
    // Match `name = {}` or `name = []` or `name: Type = {}` etc.
    const m = line.match(
      /^([A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)\s*(?::\s*[A-Za-z0-9\[\]\.,\s]+)?\s*=\s*(\{.*\}|\[.*\]|dict\(.*\)|list\(.*\)|set\(.*\)|\{.*|\[.*)/
    );
    if (m) {
      const name = m[1];
      // Skip upper-case constants unless they're dict/list literals (those still mutable)
      // but still flag them — consumer can filter if it's actually constant
      results.push({
        name,
        line: i + 1,
        text: line.trim(),
      });
    }
  }
  return results;
}

function findMatchingParen(src, openIndex) {
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
    if (c === '"' || c === "'") {
      inString = c;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function extractFirstPyArg(argsStr) {
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
    if (c === '"' || c === "'") {
      inString = c;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) return argsStr.slice(0, i).trim();
  }
  return argsStr.trim();
}
