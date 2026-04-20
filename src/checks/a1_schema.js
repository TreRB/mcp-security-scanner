// A1 — Tool arg validation absent.
// Flags MCP tool registrations that have no JSON schema or use a loose
// schema (`z.any()`, `z.unknown()`, `z.string()` without `.regex()` or
// `.max()` bounds, raw `string`/`any` type annotations).

import { findTools, lineOf, snippetAt } from '../parse/ts.js';
import { findPyTools, lineOf as pyLineOf, snippetAt as pySnippet } from '../parse/py.js';

export const id = 'A1';
export const title = 'Tool arg validation absent';
export const blogAnchor = '#1-prompt-injection-into-tool-arguments';

export function checkTs({ src, file }) {
  const findings = [];
  const tools = findTools(src);
  for (const tool of tools) {
    const problem = classifySchema(tool.inner);
    if (problem) {
      findings.push({
        id,
        severity: problem.severity,
        title: `Tool "${tool.name}" ${problem.summary}`,
        file,
        line: lineOf(src, tool.nameIndex),
        evidence: snippetAt(src, tool.nameIndex),
        detail: problem.detail,
        fix:
          'Define a strict JSON schema for tool arguments. Constrain string types with regex/maxLength, use enums for fixed sets, reject extra properties.',
        blogAnchor,
      });
    }
  }
  return findings;
}

function classifySchema(inner) {
  // Strip the handler body so we only look at the schema spot (the 2nd arg).
  // Common SDK signatures:
  //   server.tool("name", zodSchemaObj, handler)
  //   server.tool("name", { description, inputSchema: zodSchemaObj }, handler)
  //   server.registerTool("name", { title, inputSchema }, handler)
  // We take everything between the first comma and the last `, async` or `, (` (handler arrow).
  const firstComma = inner.indexOf(',');
  if (firstComma === -1)
    return {
      severity: 'high',
      summary: 'registered with no schema (single-arg form)',
      detail: 'Tool registered with no arguments schema at all.',
    };
  // Find the handler start — last arrow function beginning.
  const handlerMatch = inner.match(/,\s*(?:async\s*)?(\([^)]*\)|\w+)\s*=>/);
  const handlerStart =
    handlerMatch && handlerMatch.index !== undefined
      ? handlerMatch.index
      : inner.length;
  const schemaBlob = inner.slice(firstComma + 1, handlerStart).trim();

  if (!schemaBlob || schemaBlob === ',') {
    return {
      severity: 'high',
      summary: 'has no argument schema',
      detail: 'Tool has no inputSchema — any argument shape accepted.',
    };
  }
  if (/z\.any\s*\(\)/.test(schemaBlob) || /z\.unknown\s*\(\)/.test(schemaBlob)) {
    return {
      severity: 'medium',
      summary: 'uses z.any() / z.unknown()',
      detail:
        'Schema accepts arbitrary data — equivalent to no validation for LLM-driven inputs.',
    };
  }
  if (/:\s*z\.string\s*\(\s*\)\s*(?:[,}]|$)/.test(schemaBlob)) {
    // z.string() with no modifiers
    return {
      severity: 'medium',
      summary: 'has loose string schema (z.string() with no bounds)',
      detail:
        'At least one field is z.string() with no pattern, length cap, or enum. LLM can produce adversarial values.',
    };
  }
  if (/type\s*:\s*['"]string['"]/.test(schemaBlob) && !/pattern|maxLength|enum/.test(schemaBlob)) {
    return {
      severity: 'medium',
      summary: 'raw JSON schema string type with no pattern/maxLength/enum',
      detail: 'JSON schema accepts free-form strings.',
    };
  }
  if (/inputSchema\s*:\s*\{\s*\}/.test(schemaBlob)) {
    return {
      severity: 'high',
      summary: 'has empty inputSchema',
      detail: 'inputSchema is {} — every argument accepted.',
    };
  }
  return null;
}

export function checkPy({ src, file }) {
  const findings = [];
  const tools = findPyTools(src);
  for (const tool of tools) {
    // Look for untyped params or `str` without further validation
    const weak = tool.params.filter((p) => p.name !== 'self');
    const untyped = weak.filter((p) => !p.type);
    const strs = weak.filter((p) => p.type === 'str');
    if (weak.length > 0 && untyped.length === weak.length) {
      findings.push({
        id,
        severity: 'medium',
        title: `Tool "${tool.name}" has no type annotations`,
        file,
        line: pyLineOf(src, tool.defStart),
        evidence: pySnippet(src, tool.defStart),
        detail:
          'Python MCP tool parameters have no type annotations — FastMCP cannot derive a schema, any value is accepted.',
        fix: 'Annotate every parameter with a precise type. Use `Literal`/`Enum` for fixed sets, `Annotated[str, constr(max_length=...)]` for bounded strings.',
        blogAnchor,
      });
    } else if (strs.length > 0 && !tool.body.includes('Field(')) {
      findings.push({
        id,
        severity: 'low',
        title: `Tool "${tool.name}" uses raw str parameters without Field() constraints`,
        file,
        line: pyLineOf(src, tool.defStart),
        evidence: pySnippet(src, tool.defStart),
        detail: `${strs.length} parameter(s) typed as bare str with no Pydantic Field() or Annotated constraints.`,
        fix: 'Wrap sensitive params with `Annotated[str, Field(max_length=N, pattern=...)]`.',
        blogAnchor,
      });
    }
  }
  return findings;
}
