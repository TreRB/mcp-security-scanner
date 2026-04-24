// SARIF 2.1.0 output for GitHub Code Scanning + Azure DevOps.

import { countSeverities } from './report.js';
import { CHECKS } from './checks/index.js';

export const SARIF_SCHEMA_URL =
  'https://json.schemastore.org/sarif-2.1.0.json';

const SEV_TO_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

const SEV_TO_CVSS = {
  critical: 9.1,
  high: 7.5,
  medium: 5.3,
  low: 3.5,
  info: 0.0,
};

// Rule catalogue: one entry per check ID. Populated at render time from
// the CHECKS registry so adding a new check doesn't require touching
// this module.
function buildRules() {
  const rules = [];
  for (const [id, mod] of Object.entries(CHECKS)) {
    rules.push({
      id: `MCP-${id}`,
      name: mod.title ? mod.title.replace(/\W+/g, '') : id,
      shortDescription: {
        text: mod.title || `MCP check ${id}`,
      },
      fullDescription: {
        text: mod.description || buildDefaultDescription(id),
      },
      help: {
        text: mod.help || buildDefaultHelp(id),
        markdown: mod.helpMarkdown || buildDefaultMarkdown(id, mod),
      },
      defaultConfiguration: {
        level: 'warning',
      },
      properties: {
        tags: ['security', 'mcp', 'model-context-protocol',
               'static-analysis', id.startsWith('S') ? 'supply-chain' : 'application'],
      },
    });
  }
  return rules;
}

function buildDefaultDescription(id) {
  const descriptions = {
    A1: 'Tool accepts input without validated schema (no Zod / Pydantic / JSON-schema). ' +
        'Enables prompt-injection-driven argument manipulation.',
    A2: 'Tool passes LLM-influenced input directly into a shell or SQL sink. ' +
        'Prompt injection → command / SQL injection.',
    A3: 'Filesystem tool operates outside an allowed root, enabling path traversal ' +
        'to arbitrary file read or write.',
    A4: 'Tool fetches arbitrary URLs including private IP / metadata endpoints. ' +
        'SSRF risk — LLM can coerce the server into internal-network requests.',
    A5: 'Tool returns raw credentials, API keys, or tokens in its output. ' +
        'LLM context and downstream logs become a credential-exposure surface.',
    S1: 'Dependency versions are unpinned. Supply chain confusion / compromise risk.',
    S2: 'Known-bad / typosquatted package detected in manifest.',
    S3: 'Module-level mutable state shared across tool calls. ' +
        'Cross-conversation data leakage.',
  };
  return descriptions[id] || `MCP security check ${id}`;
}

function buildDefaultHelp(id) {
  const help = {
    A1: 'Use Zod (TypeScript) or Pydantic (Python) to validate every tool argument. ' +
        'Reject unexpected keys. Limit string length and character classes.',
    A2: 'Use parameterized queries for SQL. Use execFile / subprocess.run with argv ' +
        'arrays, not shell=true. Allowlist exec targets by name.',
    A3: 'Resolve every path against a fixed base directory. Reject `..` and absolute ' +
        'paths. Canonicalize before access.',
    A4: 'Block private IP ranges (10./172.16-31./192.168./127./169.254./::1/fc00::/fe80::) ' +
        'before calling fetch. Deny cloud-metadata endpoints.',
    A5: 'Never return credentials in tool results. Scrub secrets from logs. Return ' +
        'redacted summaries.',
    S1: 'Pin exact versions in package.json / requirements.txt. Use lockfiles in CI.',
    S2: 'Audit and remove known-bad packages. Check recently-added deps against ' +
        'typosquat databases.',
    S3: 'Scope state per-invocation. Use request-local storage, not module globals.',
  };
  return help[id] || 'See Valtik Studios MCP security guide for guidance.';
}

function buildDefaultMarkdown(id, mod) {
  const title = mod.title || `MCP check ${id}`;
  const help = buildDefaultHelp(id);
  return [
    `### ${title}`,
    '',
    buildDefaultDescription(id),
    '',
    '**Remediation:**',
    '',
    help,
    '',
    mod.blogAnchor
      ? `See [Valtik MCP server security guide](https://valtikstudios.com/blog/mcp-server-security-2026${mod.blogAnchor})`
      : '',
  ]
    .filter(Boolean)
    .join('\n');
}

export function renderSarif(scan) {
  const rules = buildRules();
  const results = scan.findings.map((f) => ({
    ruleId: `MCP-${f.id}`,
    level: SEV_TO_LEVEL[f.severity] || 'note',
    message: {
      text: f.detail || f.title,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file,
          },
          region:
            f.line && f.line > 0
              ? { startLine: f.line }
              : undefined,
        },
      },
    ],
    properties: {
      severity: f.severity,
      'security-severity': String(SEV_TO_CVSS[f.severity] || 0),
      evidence: f.evidence || '',
      fix: f.fix || '',
    },
  }));

  return JSON.stringify(
    {
      $schema: SARIF_SCHEMA_URL,
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'mcp-security-scanner',
              version: '0.2.0',
              informationUri:
                'https://github.com/TreRB/mcp-security-scanner',
              rules,
            },
          },
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: new Date().toISOString(),
            },
          ],
          properties: {
            target: scan.root,
            fileCount: scan.fileCount,
            toolCount: scan.toolCount,
            counts: countSeverities(scan.findings),
          },
          results,
        },
      ],
    },
    null,
    2
  );
}
