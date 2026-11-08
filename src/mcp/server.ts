/**
 * vibe-shield :: Model Context Protocol server
 * -------------------------------------------
 * A zero-dependency MCP server over stdio, so Claude Code, Claude Desktop,
 * Cursor and Codex can call the scanner as a tool instead of shelling out and
 * parsing console output.
 *
 * Transport is newline-delimited JSON-RPC 2.0. Requests are handled in arrival
 * order and every response carries the matching `id`; notifications (no `id`)
 * are never answered, per the JSON-RPC spec.
 *
 * Three tools are exposed:
 *   - `vibe_shield_scan`          run the 60-rule scanner over a project
 *   - `vibe_shield_audit_skills`  audit the agent surface for poisoning
 *   - `vibe_shield_explain_rule`  full CWE + remediation detail for one rule
 *
 * Deliberate design constraints:
 *   - stdout is protocol-only. Diagnostics go to stderr, because a stray
 *     `console.log` corrupts the stream and breaks the client session.
 *   - No request is ever executed against a path outside the client's `roots`
 *     or the server's own cwd tree without an absolute path being explicit.
 *   - Every tool returns `isError` on failure rather than throwing, so a bad
 *     argument degrades one call instead of killing the session.
 */

import * as path from 'node:path';

import { auditSkills } from '../mcp-guard/skill-auditor';
import { scanProject } from '../scanner/engine';
import { ALL_RULES, getRule } from '../scanner/rules';
import { isSeverity, type Finding, type Rule, type ScanResult, type Severity } from '../scanner/types';

/** JSON-RPC 2.0 error codes used by this server. */
export const RpcError = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
} as const;

export const MCP_PROTOCOL_VERSION = '2025-06-18';
export const SERVER_NAME = 'vibe-shield';

/** The subset of `InitializeResult` this server advertises. */
export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: { tools: { listChanged: boolean } };
  serverInfo: { name: string; version: string; title: string };
  instructions: string;
}

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: string | number | null;
  result: unknown;
}

export interface JsonRpcFailure {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string; data?: unknown };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

/** A single MCP tool description, as returned by `tools/list`. */
export interface McpToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export interface McpTextContent {
  type: 'text';
  text: string;
}

export interface McpToolResult {
  content: McpTextContent[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

const TOOL_SCAN = 'vibe_shield_scan';
const TOOL_AUDIT = 'vibe_shield_audit_skills';
const TOOL_EXPLAIN = 'vibe_shield_explain_rule';

/**
 * Tool catalogue. Descriptions are written for a model deciding *whether* to
 * call, not for a human reading docs — they say when to reach for the tool.
 */
export const MCP_TOOLS: readonly McpToolDefinition[] = [
  {
    name: TOOL_SCAN,
    title: 'Scan a project for AI-introduced security bugs',
    description:
      'Runs the 60-rule vibe-shield scanner over a project directory or a set of paths and returns the grade, score and every finding with its exact file, line, CWE and remediation steps. Call this after writing or modifying application code — API routes, server actions, database migrations, auth logic, environment variables, LLM calls or webhook handlers — and before reporting a task as complete. Also call it when the user asks for a security review or audit.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description:
            'Directory or file to scan. Relative paths resolve against the server working directory. Default: the working directory.',
        },
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Explicit files or directories to scan, instead of the whole project.',
        },
        severity: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
          description: 'Only return findings at or above this severity.',
        },
        rules: {
          type: 'array',
          items: { type: 'string' },
          description: 'Restrict to these rule ids or prefixes, e.g. ["VSB-CLIENT-001"] or ["VSB-DB-*"].',
        },
        includeTests: { type: 'boolean', description: 'Include test, spec and fixture files.' },
        includeDocs: { type: 'boolean', description: 'Include Markdown and documentation files.' },
        limit: {
          type: 'integer',
          description: 'Maximum findings to return in the text summary. Default 25, 0 for all.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: TOOL_AUDIT,
    title: 'Audit agent skills and MCP configuration for poisoning',
    description:
      'Audits .claude/skills, .cursor rules, .cursorrules, AGENTS.md, CLAUDE.md and MCP config files (mcp.json, .mcp.json) for agent-poisoning: hidden Unicode instructions, credential exfiltration commands, reads of .env or ~/.ssh, unpinned MCP servers, literal credentials and safety-override language. Call this whenever you add or modify an agent instruction file, a skill, a Cursor rule or an MCP server config.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Project root to audit. Default: the server working directory.',
        },
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Specific agent files or directories to audit.',
        },
        limit: { type: 'integer', description: 'Maximum findings to return. Default 25.' },
      },
      additionalProperties: false,
    },
  },
  {
    name: TOOL_EXPLAIN,
    title: 'Explain a detection rule',
    description:
      'Returns the full documentation for one rule id or slug: severity, confidence, CWE, why it is exploitable, the vulnerable code shape, the fixed code shape, ordered remediation steps and references. Use this when you need to understand a finding before fixing it, or when the user asks what a rule means.',
    inputSchema: {
      type: 'object',
      required: ['ruleId'],
      properties: {
        ruleId: {
          type: 'string',
          description: 'Rule id or slug, e.g. "VSB-CLIENT-001" or "public-env-secret-exposure".',
        },
      },
      additionalProperties: false,
    },
  },
];

/* -------------------------------------------------------------------------- */
/* Argument helpers                                                           */
/* -------------------------------------------------------------------------- */

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim().length ? value.trim() : undefined;

const asBoolean = (value: unknown): boolean | undefined => (typeof value === 'boolean' ? value : undefined);

const asStringArray = (value: unknown): string[] | undefined =>
  Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : undefined;

const asLimit = (value: unknown, fallback: number): number => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return fallback;
  return Math.floor(value);
};

/* -------------------------------------------------------------------------- */
/* Result rendering                                                           */
/* -------------------------------------------------------------------------- */

const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const atOrAbove = (severity: Severity, minimum: Severity): boolean =>
  SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(minimum);

/** Compact, model-readable rendering of one finding. */
const renderFinding = (finding: Finding): string => {
  const lines = [
    `${finding.severity.toUpperCase()} ${finding.filePath}:${finding.line}:${finding.column} ${finding.ruleId} — ${finding.title}`,
    `  ${finding.message}`,
    `  CWE: ${finding.cwe.id} ${finding.cwe.name}`,
  ];
  if (finding.snippet) lines.push(`  > ${finding.snippet}`);
  return lines.join('\n');
};

/** The scorecard header shared by `scan` and `audit-skills` output. */
const renderVerdict = (result: ScanResult, command: 'scan' | 'audit-skills'): string => {
  const counts = result.score.counts;
  const parts = SEVERITY_ORDER.filter((severity) => counts[severity] > 0).map(
    (severity) => `${counts[severity]} ${severity}`,
  );
  const verb = command === 'scan' ? 'Scanned' : 'Audited';
  return [
    `vibe-shield ${result.version} — ${verb} ${result.stats.filesScanned} file(s) in ${result.stats.durationMs}ms`,
    `Grade ${result.score.grade} — ${result.score.score}/100${parts.length ? ` · ${parts.join(', ')}` : ' · no findings'}`,
  ].join('\n');
};

/** Serialise a scan for the model: verdict, findings, then machine fields. */
const toToolResult = (
  result: ScanResult,
  options: { limit: number; minimumSeverity?: Severity; command: 'scan' | 'audit-skills' },
): McpToolResult => {
  const filtered = options.minimumSeverity
    ? result.findings.filter((finding) => atOrAbove(finding.severity, options.minimumSeverity as Severity))
    : result.findings;

  const shown = options.limit > 0 ? filtered.slice(0, options.limit) : filtered;
  const sections: string[] = [renderVerdict(result, options.command)];

  if (result.stats.filesScanned === 0) {
    // Silence is not a pass — say so rather than returning an empty, green result.
    sections.push('', 'No files were scanned. Check `target`, and whether an ignore file excludes it.');
  } else if (filtered.length === 0) {
    sections.push('', 'No findings at or above the requested severity.');
  } else {
    sections.push('', 'Findings (highest severity first):', '');
    for (const finding of shown) sections.push(renderFinding(finding), '');
    if (filtered.length > shown.length) {
      sections.push(`… and ${filtered.length - shown.length} more. Raise \`limit\` or filter by \`rules\`.`);
    }
    sections.push(
      'Fix the root cause: do not delete the auth check, disable RLS or suppress the finding to make it disappear.',
    );
  }

  if (result.notices.length) sections.push('', ...result.notices.map((notice) => `note: ${notice}`));

  return {
    content: [{ type: 'text', text: sections.join('\n').trimEnd() }],
    structuredContent: {
      score: result.score.score,
      grade: result.score.grade,
      counts: result.score.counts,
      total: filtered.length,
      filesScanned: result.stats.filesScanned,
      durationMs: result.stats.durationMs,
      rootDir: result.rootDir,
      findings: shown.map((finding) => ({
        ruleId: finding.ruleId,
        slug: finding.slug,
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        title: finding.title,
        message: finding.message,
        filePath: finding.filePath,
        line: finding.line,
        column: finding.column,
        snippet: finding.snippet,
        cwe: finding.cwe,
        remediation: finding.remediation,
        secureExample: finding.secureExample,
        references: finding.references,
      })),
      notices: result.notices,
    },
  };
};

/** Full rule documentation as text + structured content. */
const explainRuleResult = (rule: Rule): McpToolResult => {
  const text = [
    `${rule.id} — ${rule.title}`,
    `${rule.category} · ${rule.severity} severity · ${rule.confidence} confidence · ${rule.cwe.id} ${rule.cwe.name}`,
    '',
    rule.description,
    '',
    'Vulnerable',
    rule.insecureExample,
    '',
    'Fixed',
    rule.secureExample,
    '',
    'Remediation',
    ...rule.remediation.map((step, index) => `${index + 1}. ${step}`),
    '',
    'References',
    ...rule.references.map((reference) => `- ${reference}`),
  ].join('\n');

  return {
    content: [{ type: 'text', text }],
    structuredContent: {
      id: rule.id,
      slug: rule.slug,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      confidence: rule.confidence,
      cwe: rule.cwe,
      description: rule.description,
      insecureExample: rule.insecureExample,
      secureExample: rule.secureExample,
      remediation: rule.remediation,
      references: rule.references,
    },
  };
};

const errorResult = (message: string): McpToolResult => ({
  content: [{ type: 'text', text: message }],
  isError: true,
});

/* -------------------------------------------------------------------------- */
/* Tool dispatch                                                              */
/* -------------------------------------------------------------------------- */

/** Resolve a client-supplied target against the server's working directory. */
const resolveTarget = (target: string | undefined, cwd: string): string =>
  target ? path.resolve(cwd, target) : cwd;

export interface McpServerOptions {
  /** Directory that relative `target` values resolve against. */
  cwd?: string;
  /** Version string reported in `initialize` and scan results. */
  version?: string;
}

/** Execute one tool by name. Never throws: failures become `isError` results. */
export async function callTool(
  name: string,
  args: Record<string, unknown>,
  options: McpServerOptions = {},
): Promise<McpToolResult> {
  const cwd = options.cwd ?? process.cwd();
  try {
    if (name === TOOL_SCAN) {
      const minimumSeverity = asString(args.severity);
      if (minimumSeverity && !isSeverity(minimumSeverity)) {
        return errorResult(`Unknown severity "${minimumSeverity}". Use one of: ${SEVERITY_ORDER.join(', ')}.`);
      }
      const selection = asStringArray(args.rules);
      const result = await scanProject({
        rootDir: resolveTarget(asString(args.target), cwd),
        paths: asStringArray(args.paths),
        includeTests: asBoolean(args.includeTests),
        includeDocs: asBoolean(args.includeDocs),
        rules: selection?.length ? selection.flatMap((selector) => rulesFor(selector)) : undefined,
        useGitIndex: false,
      });
      return toToolResult(result, {
        limit: asLimit(args.limit, 25),
        minimumSeverity: minimumSeverity as Severity | undefined,
        command: 'scan',
      });
    }

    if (name === TOOL_AUDIT) {
      const result = await auditSkills(resolveTarget(asString(args.target), cwd), {
        paths: asStringArray(args.paths),
      });
      return toToolResult(result, { limit: asLimit(args.limit, 25), command: 'audit-skills' });
    }

    if (name === TOOL_EXPLAIN) {
      const ruleId = asString(args.ruleId);
      if (!ruleId) return errorResult('`ruleId` is required, e.g. "VSB-CLIENT-001".');
      const rule = getRule(ruleId);
      if (!rule) return errorResult(`Unknown rule "${ruleId}". Call tools/list or \`npx github:avivgerz-hue/vibe-shield rules\` for the catalogue.`);
      return explainRuleResult(rule);
    }

    return errorResult(`Unknown tool "${name}".`);
  } catch (error) {
    return errorResult(`vibe-shield failed: ${error instanceof Error ? error.message : String(error)}`);
  }
};

/** Expand a rule selector (`VSB-DB-*`, exact id or slug) against the catalogue. */
const rulesFor = (selector: string): Rule[] => {
  const exact = getRule(selector);
  if (exact) return [exact];
  const normalized = selector.trim().toUpperCase();
  if (normalized.endsWith('*')) {
    const prefix = normalized.slice(0, -1);
    return ALL_RULES.filter((rule) => rule.id.startsWith(prefix));
  }
  return [];
};

/* -------------------------------------------------------------------------- */
/* JSON-RPC layer                                                             */
/* -------------------------------------------------------------------------- */

const isRequest = (value: unknown): value is JsonRpcRequest => {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return candidate.jsonrpc === '2.0' && typeof candidate.method === 'string';
};

/** True when the message is a notification and must not receive a reply. */
const isNotification = (value: JsonRpcRequest): boolean => !('id' in value) || value.id === undefined;

/**
 * Handle one decoded JSON-RPC message.
 * Returns `null` for notifications, which the spec forbids answering.
 */
export async function handleMessage(
  message: unknown,
  options: McpServerOptions = {},
): Promise<JsonRpcResponse | null> {
  if (!isRequest(message)) {
    // A malformed message still gets a parse/invalid-request error with a null id.
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: RpcError.invalidRequest, message: 'Invalid JSON-RPC 2.0 request.' },
    };
  }

  const id = message.id ?? null;
  const notification = isNotification(message);
  const params = (message.params ?? {}) as Record<string, unknown>;

  const reply = (result: unknown): JsonRpcResponse | null =>
    notification ? null : { jsonrpc: '2.0', id, result };

  const fail = (code: number, errorMessage: string): JsonRpcResponse | null =>
    notification ? null : { jsonrpc: '2.0', id, error: { code, message: errorMessage } };

  switch (message.method) {
    case 'initialize':
      return reply({
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: {
          name: SERVER_NAME,
          title: 'vibe-shield',
          version: options.version ?? '1.1.0',
        },
        instructions:
          'vibe-shield finds security bugs that AI coding agents ship: leaked secrets, unguarded API routes, missing Postgres RLS, SQL injection, prompt injection and poisoned agent skills. Call vibe_shield_scan after writing application code and before reporting a task as done, and vibe_shield_audit_skills after touching any agent instruction or MCP config file.',
      } satisfies McpInitializeResult);

    // Notifications the client sends that need no reply.
    case 'notifications/initialized':
    case 'notifications/cancelled':
    case 'initialized':
      return null;

    case 'ping':
      return reply({});

    case 'tools/list':
      return reply({ tools: MCP_TOOLS });

    case 'tools/call': {
      const name = asString(params.name);
      if (!name) return fail(RpcError.invalidParams, '`name` is required.');
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      const result = await callTool(name, args, options);
      return reply(result);
    }

    case 'resources/list':
      return reply({ resources: [] });

    case 'prompts/list':
      return reply({ prompts: [] });

    default:
      return fail(RpcError.methodNotFound, `Method not found: ${message.method}`);
  }
}

/* -------------------------------------------------------------------------- */
/* stdio transport                                                            */
/* -------------------------------------------------------------------------- */

export interface McpServerIo {
  stdin: NodeJS.ReadableStream;
  stdout: { write(chunk: string): unknown };
  stderr: { write(chunk: string): unknown };
}

export interface McpServeOptions extends McpServerOptions {
  /** Called after the transport stops, with the number of messages handled. */
  onClose?: (handled: number) => void;
}

/**
 * Serve MCP over newline-delimited JSON-RPC until stdin closes.
 *
 * Messages are processed sequentially so responses preserve request order and a
 * slow scan cannot interleave with a later `tools/call`.
 */
export function serveMcp(io: McpServerIo, options: McpServeOptions = {}): Promise<number> {
  let buffer = '';
  let handled = 0;
  let queue: Promise<void> = Promise.resolve();

  return new Promise<number>((resolve) => {
    const finish = (): void => {
      void queue.then(() => {
        options.onClose?.(handled);
        resolve(handled);
      });
    };

    io.stdin.on('data', (chunk: Buffer | string) => {
      buffer += chunk.toString();
      let newline = buffer.indexOf('\n');
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        newline = buffer.indexOf('\n');
        if (!line) continue;

        queue = queue.then(async () => {
          let parsed: unknown;
          try {
            parsed = JSON.parse(line);
          } catch {
            io.stdout.write(`${JSON.stringify({
              jsonrpc: '2.0',
              id: null,
              error: { code: RpcError.parseError, message: 'Parse error: invalid JSON.' },
            })}\n`);
            handled += 1;
            return;
          }
          const response = await handleMessage(parsed, options);
          if (response) io.stdout.write(`${JSON.stringify(response)}\n`);
          handled += 1;
        });
      }
    });

    io.stdin.on('end', finish);
    io.stdin.on('close', finish);
  });
}

/** Convenience wrapper used by `vibe-shield mcp`. */
export const startMcpServer = (options: McpServerOptions = {}): Promise<number> =>
  serveMcp({ stdin: process.stdin, stdout: process.stdout, stderr: process.stderr }, options);

export const MCP_TOOL_NAMES = [TOOL_SCAN, TOOL_AUDIT, TOOL_EXPLAIN] as const;
