#!/usr/bin/env node
/**
 * vibe-shield :: command line
 * ---------------------------
 *   vibe-shield scan [paths]          scan a project (default: `.`)
 *   vibe-shield audit-skills [paths]  audit agent skills / MCP config
 *   vibe-shield init                  install the Agent Skill + CI gate
 *   vibe-shield rules                 list every rule
 *   vibe-shield explain <RULE_ID>     full documentation for one rule
 *   vibe-shield version | help
 *
 * The module exports `run(argv, io)` and only executes when invoked directly,
 * which is what lets the test suite drive the real CLI without a build step.
 */

import { existsSync, statSync } from 'node:fs';
import * as path from 'node:path';

import { auditSkills } from '../src/mcp-guard/skill-auditor';
import { serveMcp } from '../src/mcp/server';
import { installScaffold } from '../src/init/scaffold';
import { reportConsole, createColorizer } from '../src/reporter/console-reporter';
import { formatResult, isOutputFormat, OUTPUT_FORMATS, type OutputFormat } from '../src/reporter/formatters';
import { writePatchPrompt, PATCH_PROMPT_FILENAME } from '../src/reporter/patch-prompt-writer';
import { hasFindingsAtOrAbove, packageVersion, scanProject } from '../src/scanner/engine';
import { ALL_RULES, getRule, rulesByCategory, selectRules } from '../src/scanner/rules';
import { CATEGORY_TITLES, RULE_CATEGORIES, isSeverity, type Severity } from '../src/scanner/types';

/** Everything the CLI needs from the outside world (injectable for tests). */
export interface CliIo {
  stdout: { write(chunk: string): unknown; isTTY?: boolean; columns?: number };
  stderr: { write(chunk: string): unknown; isTTY?: boolean; columns?: number };
  cwd: string;
  env: NodeJS.ProcessEnv;
}

export const defaultIo = (): CliIo => ({
  stdout: process.stdout,
  stderr: process.stderr,
  cwd: process.cwd(),
  env: process.env,
});

/** Exit codes: 0 clean, 1 findings at/above `--fail-on`, 2 usage error. */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;

const HELP = `vibe-shield — security scanner for AI-generated code

USAGE
  vibe-shield <command> [options]

COMMANDS
  scan [paths...]        Scan the project (default: current directory).
  audit-skills [paths...]  Audit agent skills, Cursor rules, AGENTS.md and MCP configs.
  init                   Install the Agent Skill, AGENTS.md section and CI workflow.
  rules                  List every detection rule.
  explain <RULE_ID>      Show full documentation for a rule.
  mcp                    Serve the Model Context Protocol tools over stdio.
  version                Print the version.
  help                   Print this help.

SCAN OPTIONS
  --format <fmt>         console | compact | summary | json | sarif | github | markdown | html
  --out <file>           Write the report to a file.
  --report <file>        Write a report (format inferred from extension).
  --patch-prompt <file>  Write a remediation prompt to this file.
  --fix-prompt           Write ${PATCH_PROMPT_FILENAME} with exact fix instructions.
  --fail-on <severity>   Exit 1 when a finding at/above this severity exists. (critical)
  --severity <severity>  Only report findings at/above this severity.
  --rules <ids>          Comma-separated rule ids/slugs (supports VSB-DB-*).
  --ignore <glob>        Extra gitignore-style pattern (repeatable).
  --include-tests        Include test, spec and fixture files.
  --include-docs         Include Markdown and docs/.
  --cache                Reuse .vibe-shield-cache.json between runs.
  --max-findings <n>     Limit the console list (0 = all).   (50)
  --quiet                Print only the verdict line and the exit code.
  --no-color             Disable ANSI colour.
  --no-shield-ignore     Ignore .vibe-shieldignore (e.g. to scan excluded fixtures).
  --json                 Shorthand for --format json.

INIT OPTIONS
  --target <dir>         Repository to install into.          (cwd)
  --agent <kind>         claude | cursor | generic | all.      (all)
  --no-workflow          Skip the GitHub Actions workflow.
  --force                Overwrite existing files.
  --yes                  Accepted for non-interactive CI use (init never prompts).

EXAMPLES
  npx -y @vibefoundry/vibe-shield scan
  npx -y @vibefoundry/vibe-shield scan --fail-on high --format github
  npx -y @vibefoundry/vibe-shield scan --fix-prompt
  npx -y @vibefoundry/vibe-shield init
  npx -y @vibefoundry/vibe-shield explain VSB-DB-001
  npx -y @vibefoundry/vibe-shield audit-skills .claude
`;

/* -------------------------------------------------------------------------- */
/* Argument parsing                                                           */
/* -------------------------------------------------------------------------- */

interface ParsedArgs {
  command: string;
  positionals: string[];
  flags: Map<string, string | boolean>;
  unknown: string[];
}

const BOOLEAN_FLAGS = new Set([
  // `--mcp` is an alias for the `mcp` subcommand, so `npx -y
  // @vibefoundry/vibe-shield --mcp` works the way most MCP clients expect.
  'mcp',
  'version',
  'fix-prompt',
  'include-tests',
  'include-docs',
  'cache',
  'quiet',
  'no-shield-ignore',
  'no-color',
  'json',
  'no-workflow',
  'force',
  'yes',
  'list-rules',
  'help',
  'verbose',
  'strict-gitignore',
  'no-gitignore',
]);

const VALUE_FLAGS = new Set([
  'format',
  'out',
  'report',
  'patch-prompt',
  'fail-on',
  'severity',
  'rules',
  'ignore',
  'max-findings',
  'target',
  'agent',
  'category',
]);

const SHORT_FLAGS: Record<string, string> = {
  '-h': 'help',
  '-v': 'version',
  '-f': 'format',
  '-o': 'out',
  '-q': 'quiet',
};

/** Parse `argv` without any dependency. Supports `--flag=value` and repeats. */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();
  const unknown: string[] = [];
  let command = '';

  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i] ?? '';
    if (raw.startsWith('-')) {
      const eq = raw.indexOf('=');
      const name = (eq === -1 ? raw : raw.slice(0, eq)).replace(/^--?/, '');
      const normalised = SHORT_FLAGS[raw] ?? name;
      const inlineValue = eq === -1 ? undefined : raw.slice(eq + 1);
      if (BOOLEAN_FLAGS.has(normalised)) {
        flags.set(normalised, inlineValue === undefined ? true : inlineValue !== 'false');
        continue;
      }
      if (VALUE_FLAGS.has(normalised)) {
        const value = inlineValue ?? argv[i + 1];
        if (inlineValue === undefined && value !== undefined) i += 1;
        if (value === undefined) {
          unknown.push(raw);
          continue;
        }
        // Repeatable flag: keep every value.
        const existing = flags.get(normalised);
        if (normalised === 'ignore' && typeof existing === 'string') {
          flags.set(normalised, `${existing}\n${value}`);
        } else {
          flags.set(normalised, value);
        }
        continue;
      }
      unknown.push(raw);
      continue;
    }
    if (!command && !raw.includes(path.sep) && /^[a-z][a-z-]*$/i.test(raw) && !raw.endsWith('.ts')) {
      command = raw;
      continue;
    }
    positionals.push(raw);
  }
  return { command, positionals, flags, unknown };
}

const flagString = (parsed: ParsedArgs, name: string): string | undefined => {
  const value = parsed.flags.get(name);
  return typeof value === 'string' ? value : undefined;
};

const flagBool = (parsed: ParsedArgs, name: string): boolean => parsed.flags.get(name) === true;

const flagNumber = (parsed: ParsedArgs, name: string, fallback: number): number => {
  const raw = flagString(parsed, name);
  if (raw === undefined) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) ? value : fallback;
};

/* -------------------------------------------------------------------------- */
/* Output helpers                                                             */
/* -------------------------------------------------------------------------- */

const write = (io: CliIo, stream: 'stdout' | 'stderr', text: string): void => {
  io[stream].write(text);
};

/* -------------------------------------------------------------------------- */
/* scan / audit-skills                                                        */
/* -------------------------------------------------------------------------- */

interface ReportCommandOptions {
  fixPrompt: boolean;
  format: OutputFormat;
  out?: string;
  quiet: boolean;
  maxFindings: number;
}

async function emitReport(
  result: Awaited<ReturnType<typeof scanProject>>,
  io: CliIo,
  options: ReportCommandOptions,
  parsed: ParsedArgs,
): Promise<void> {
  const noColor = flagBool(parsed, 'no-color') || io.env.NO_COLOR !== undefined;
  const color = createColorizer(io.stdout);
  if (noColor) color.enabled = false;

  let patchPath: string | null = null;
  if (options.fixPrompt || flagString(parsed, 'patch-prompt')) {
    patchPath = await writePatchPrompt(result, {
      outDir: io.cwd,
      fileName: flagString(parsed, 'patch-prompt'),
      minSeverity: (isSeverity(flagString(parsed, 'severity')) ? (flagString(parsed, 'severity') as Severity) : 'info'),
    });
  }

  if (options.quiet) {
    // One line: verdict + counts. Machine-friendly and CI-log friendly.
    const counts = result.score.counts;
    const files = `${result.stats.filesScanned} ${result.stats.filesScanned === 1 ? 'file' : 'files'}`;
    const verdict = result.stats.filesScanned === 0 ? '0 files scanned — not a pass' : `${result.score.score}/100 ${result.score.grade}`;
    write(
      io,
      'stdout',
      `${verdict} — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low (${files})\n`,
    );
  } else if (options.format === 'console') {
    reportConsole(result, io.stdout, {
      color,
      maxFindings: options.maxFindings,
      width: Math.min(io.stdout.columns ?? 100, 140),
    });
  } else {
    write(io, 'stdout', formatResult(result, options.format));
  }

  if (patchPath) {
    write(
      io,
      'stderr',
      `\n📝 Wrote ${path.relative(io.cwd, patchPath) || patchPath} — hand it to your agent, or run \`npx -y @vibefoundry/vibe-shield scan\` after fixing.\n`,
    );
  }

  const reportPath = flagString(parsed, 'report');
  const outputPath = reportPath ?? options.out;
  if (outputPath) {
    const target = path.resolve(io.cwd, outputPath);
    const { promises: fs } = await import('node:fs');
    const inferred = ({ '.md': 'markdown', '.markdown': 'markdown', '.html': 'html', '.sarif': 'sarif', '.json': 'json' } as const)[path.extname(outputPath).toLowerCase() as '.md'];
    const fileFormat = reportPath && !flagString(parsed, 'format') ? inferred : options.format === 'console' ? 'json' : options.format;
    if (!fileFormat) throw new Error('Cannot infer report format from extension; use --format.');
    await fs.writeFile(target, formatResult(result, fileFormat), 'utf8');
    write(io, 'stderr', `📄 Report written to ${outputPath}\n`);
  }
}

/* -------------------------------------------------------------------------- */
/* Commands                                                                   */
/* -------------------------------------------------------------------------- */

async function commandScan(parsed: ParsedArgs, io: CliIo): Promise<number> {
  const format = (flagString(parsed, 'format') ?? (flagBool(parsed, 'json') ? 'json' : 'console')).toLowerCase();
  if (!isOutputFormat(format)) {
    write(io, 'stderr', `vibe-shield: unknown --format "${format}". Choose one of: ${OUTPUT_FORMATS.join(', ')}\n`);
    return EXIT_USAGE;
  }
  const failOn = (flagString(parsed, 'fail-on') ?? 'critical').toLowerCase();
  if (!isSeverity(failOn)) {
    write(io, 'stderr', `vibe-shield: --fail-on expects one of: critical, high, medium, low, info\n`);
    return EXIT_USAGE;
  }
  const severity = flagString(parsed, 'severity');
  if (severity && !isSeverity(severity)) {
    write(io, 'stderr', `vibe-shield: --severity expects one of: critical, high, medium, low, info\n`);
    return EXIT_USAGE;
  }

  const ruleSelectors = (flagString(parsed, 'rules') ?? '').split(',').map((entry) => entry.trim()).filter(Boolean);
  const rules = ruleSelectors.length ? selectRules(ruleSelectors) : undefined;
  if (ruleSelectors.length && (!rules || rules.length === 0)) {
    write(io, 'stderr', `vibe-shield: no rules matched --rules "${ruleSelectors.join(',')}"\n`);
    return EXIT_USAGE;
  }

  // A typo in the path must not look like a clean pass.
  const missing = parsed.positionals.filter((target) => !existsSync(path.resolve(io.cwd, target)));
  if (missing.length) {
    write(io, 'stderr', `vibe-shield: no such file or directory: ${missing.join(', ')}\n`);
    return EXIT_USAGE;
  }

  // For a single directory outside cwd, report paths relative to that project,
  // and discover its own config, middleware and migrations.
  const target = parsed.positionals.length === 1 ? path.resolve(io.cwd, parsed.positionals[0]!) : '';
  const outside = target && (path.relative(io.cwd, target) === '..' || path.relative(io.cwd, target).startsWith(`..${path.sep}`));
  const externalRoot = outside ? (statSync(target).isDirectory() ? target : path.dirname(target)) : undefined;
  const externalPaths = externalRoot ? [path.relative(externalRoot, target) || '.'] : undefined;
  const result = await scanProject({
    rootDir: externalRoot ?? io.cwd,
    paths: externalPaths ?? (parsed.positionals.length ? parsed.positionals : undefined),
    rules,
    ignorePatterns: (flagString(parsed, 'ignore') ?? '').split('\n').filter(Boolean),
    // `undefined` means "use the engine default" (which is: include everything
    // the user named explicitly, exclude tests/docs on an implicit whole-tree walk).
    includeTests: flagBool(parsed, 'include-tests') ? true : undefined,
    includeDocs: flagBool(parsed, 'include-docs') ? true : undefined,
    cache: flagBool(parsed, 'cache'),
    useGitignore: !flagBool(parsed, 'no-gitignore'),
    useShieldIgnore: flagBool(parsed, 'no-shield-ignore') ? false : undefined,
  });

  const filtered: typeof result =
    severity && isSeverity(severity)
      ? {
          ...result,
          findings: result.findings.filter((finding) => hasFindingsAtOrAbove({ ...result, findings: [finding] }, severity)),
        }
      : result;

  await emitReport(filtered, io, {
    fixPrompt: flagBool(parsed, 'fix-prompt'),
    format: format as OutputFormat,
    out: flagString(parsed, 'out'),
    quiet: flagBool(parsed, 'quiet'),
    maxFindings: flagNumber(parsed, 'max-findings', 50),
  }, parsed);

  // An explicit target that matched nothing is a configuration error, not a
  // pass: a CI gate pointed at a path excluded by an ignore file would
  // otherwise report success forever without scanning a single file.
  if (parsed.positionals.length > 0 && filtered.stats.filesScanned === 0) {
    write(io, 'stderr', `vibe-shield: no scannable files matched ${parsed.positionals.join(', ')} (check ignore files, or pass --no-shield-ignore)\n`);
    return EXIT_USAGE;
  }

  return hasFindingsAtOrAbove(filtered, failOn) ? EXIT_FINDINGS : EXIT_OK;
}

async function commandAuditSkills(parsed: ParsedArgs, io: CliIo): Promise<number> {
  const format = (flagString(parsed, 'format') ?? (flagBool(parsed, 'json') ? 'json' : 'console')).toLowerCase();
  if (!isOutputFormat(format)) {
    write(io, 'stderr', `vibe-shield: unknown --format "${format}".\n`);
    return EXIT_USAGE;
  }
  const failOn = (flagString(parsed, 'fail-on') ?? 'high').toLowerCase();
  if (!isSeverity(failOn)) {
    write(io, 'stderr', `vibe-shield: --fail-on expects one of: critical, high, medium, low, info\n`);
    return EXIT_USAGE;
  }

  const target = parsed.positionals.length === 1 ? path.resolve(io.cwd, parsed.positionals[0]!) : '';
  const relative = target ? path.relative(io.cwd, target) : '';
  const outside = relative === '..' || relative.startsWith(`..${path.sep}`);
  const externalRoot = outside && existsSync(target) && statSync(target).isDirectory() ? target : undefined;
  const result = await auditSkills(externalRoot ?? io.cwd, {
    paths: externalRoot ? undefined : parsed.positionals.length ? parsed.positionals : undefined,
    version: await packageVersion(),
  });

  await emitReport(result, io, {
    fixPrompt: flagBool(parsed, 'fix-prompt'),
    format: format as OutputFormat,
    out: flagString(parsed, 'out'),
    quiet: flagBool(parsed, 'quiet'),
    maxFindings: flagNumber(parsed, 'max-findings', 50),
  }, parsed);

  return hasFindingsAtOrAbove(result, failOn) ? EXIT_FINDINGS : EXIT_OK;
}

async function commandInit(parsed: ParsedArgs, io: CliIo): Promise<number> {
  const target = path.resolve(io.cwd, flagString(parsed, 'target') ?? '.');
  const agent = (flagString(parsed, 'agent') ?? 'all').toLowerCase();
  if (!['claude', 'cursor', 'generic', 'all'].includes(agent)) {
    write(io, 'stderr', 'vibe-shield: --agent expects claude, cursor, generic or all\n');
    return EXIT_USAGE;
  }

  const result = await installScaffold({
    rootDir: target,
    agents: agent as 'claude' | 'cursor' | 'generic' | 'all',
    workflow: !flagBool(parsed, 'no-workflow'),
    force: flagBool(parsed, 'force'),
    dryRun: false,
    env: io.env,
  });

  const color = createColorizer(io.stdout);
  if (flagBool(parsed, 'no-color')) color.enabled = false;

  write(io, 'stdout', `\n${color.bold(color.cyan('🛡️  vibe-shield init'))} ${color.dim(target)}\n\n`);
  for (const file of result.written) write(io, 'stdout', `  ${color.green('created')}  ${file}\n`);
  for (const file of result.appended) write(io, 'stdout', `  ${color.green('updated')}  ${file}\n`);
  for (const file of result.blocked) write(io, 'stdout', `  ${color.yellow('blocked')}  ${file} ${color.dim('(left untouched — fix the file by hand)')}\n`);
  for (const file of result.skipped) write(io, 'stdout', `  ${color.gray('skipped')}  ${file} ${color.dim('(exists — use --force)')}\n`);
  for (const warning of result.warnings) write(io, 'stdout', `  ${color.yellow('note')}     ${warning}\n`);

  write(io, 'stdout', `\n${color.bold('Next steps')}\n`);
  write(io, 'stdout', `  1. ${color.dim('npx -y @vibefoundry/vibe-shield scan')}                 ${color.dim('# baseline your repo')}\n`);
  write(io, 'stdout', `  2. ${color.dim('npx -y @vibefoundry/vibe-shield scan --fix-prompt')}   ${color.dim('# generate the fix list')}\n`);
  write(io, 'stdout', `  3. Commit the new files — your agent now audits before it says "done".\n\n`);
  return EXIT_OK;
}

function commandRules(parsed: ParsedArgs, io: CliIo): number {
  const category = flagString(parsed, 'category');
  const rules = category
    ? RULE_CATEGORIES.includes(category as never)
      ? rulesByCategory(category as never)
      : []
    : [...ALL_RULES];

  if (category && !rules.length) {
    write(io, 'stderr', `vibe-shield: unknown --category "${category}". Choose one of: ${RULE_CATEGORIES.join(', ')}\n`);
    return EXIT_USAGE;
  }

  if (flagBool(parsed, 'json') || flagString(parsed, 'format') === 'json') {
    write(
      io,
      'stdout',
      `${JSON.stringify(
        rules.map((rule) => ({
          id: rule.id,
          slug: rule.slug,
          title: rule.title,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          cwe: rule.cwe.id,
          owasp: rule.owasp,
          description: rule.description,
          remediation: rule.remediation,
          references: rule.references,
        })),
        null,
        2,
      )}\n`,
    );
    return EXIT_OK;
  }

  const color = createColorizer(io.stdout);
  if (flagBool(parsed, 'no-color')) color.enabled = false;
  write(io, 'stdout', `\n${color.bold(`${rules.length} detection rules`)}\n`);
  let currentCategory = '';
  for (const rule of rules) {
    if (rule.category !== currentCategory) {
      currentCategory = rule.category;
      write(io, 'stdout', `\n${color.bold(color.cyan(CATEGORY_TITLES[rule.category]))}\n`);
    }
    write(io, 'stdout', `  ${color.dim(rule.id.padEnd(14))} ${rule.severity.padEnd(9)} ${rule.title}\n`);
  }
  write(io, 'stdout', `\n${color.dim('Run `npx -y @vibefoundry/vibe-shield explain <RULE_ID>` for the full documentation.')}\n\n`);
  return EXIT_OK;
}

function commandExplain(parsed: ParsedArgs, io: CliIo): number {
  const id = parsed.positionals[0];
  if (!id) {
    write(io, 'stderr', 'vibe-shield: explain needs a rule id, e.g. `vibe-shield explain VSB-DB-001`\n');
    return EXIT_USAGE;
  }
  const rule = getRule(id);
  if (!rule) {
    write(io, 'stderr', `vibe-shield: unknown rule "${id}". Run \`vibe-shield rules\` to list them.\n`);
    return EXIT_USAGE;
  }
  const color = createColorizer(io.stdout);
  if (flagBool(parsed, 'no-color')) color.enabled = false;
  const out: string[] = [];
  out.push('');
  out.push(`${color.bold(rule.id)}  ${color.bold(rule.title)}`);
  out.push(color.dim(`${rule.category} · ${rule.severity} severity · ${rule.confidence} confidence · ${rule.cwe.id}`));
  out.push('');
  out.push(rule.description);
  out.push('');
  out.push(color.bold('Vulnerable'));
  out.push(color.red(rule.insecureExample));
  out.push('');
  out.push(color.bold('Fixed'));
  out.push(color.green(rule.secureExample));
  out.push('');
  out.push(color.bold('Remediation'));
  rule.remediation.forEach((step, index) => out.push(`  ${index + 1}. ${step}`));
  out.push('');
  out.push(color.bold('References'));
  for (const reference of rule.references) out.push(`  ${color.cyan(reference)}`);
  out.push('');
  out.push(color.dim(`CWE: ${rule.cwe.name} — ${rule.cwe.url}`));
  if (rule.owasp?.web) out.push(color.dim(`OWASP: ${rule.owasp.web.id} ${rule.owasp.web.name} (${rule.owasp.web.basis})`));
  if (rule.owasp?.llm.length) out.push(color.dim(`OWASP LLM: ${rule.owasp.llm.map(m => `${m.id} ${m.name}`).join(', ')} (contextual)`));
  out.push('');
  write(io, 'stdout', `${out.join('\n')}\n`);
  return EXIT_OK;
}

/* -------------------------------------------------------------------------- */
/* mcp                                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Serve MCP over stdio.
 *
 * Nothing but JSON-RPC may reach stdout here — a banner or progress line would
 * corrupt the client session — so the one diagnostic permitted (an explicit
 * note that the server is ready) goes to stderr.
 */
async function commandMcp(parsed: ParsedArgs, io: CliIo): Promise<number> {
  if (parsed.positionals.length) {
    write(io, 'stderr', `vibe-shield: mcp takes no positional arguments (got ${parsed.positionals.join(', ')})\n`);
    return EXIT_USAGE;
  }
  write(io, 'stderr', 'vibe-shield: MCP server listening on stdio\n');
  await serveMcp(
    { stdin: process.stdin, stdout: io.stdout, stderr: io.stderr },
    { cwd: io.cwd, version: await packageVersion() },
  );
  return EXIT_OK;
}

/* -------------------------------------------------------------------------- */
/* Entry point                                                                */
/* -------------------------------------------------------------------------- */

/** Run the CLI. Returns the process exit code. */
export async function run(argv: readonly string[], io: CliIo = defaultIo()): Promise<number> {
  const parsed = parseArgs(argv);
  const command =
    parsed.command ||
    (flagBool(parsed, 'mcp') ? 'mcp' : flagBool(parsed, 'version') ? 'version' : flagBool(parsed, 'help') ? 'help' : '');

  if (parsed.unknown.length) {
    write(io, 'stderr', `vibe-shield: unknown option${parsed.unknown.length === 1 ? '' : 's'} ${parsed.unknown.join(', ')}\n`);
    write(io, 'stderr', 'Run `vibe-shield help` for usage.\n');
    return EXIT_USAGE;
  }

  switch (command) {
    case 'scan':
      return commandScan(parsed, io);
    case 'audit-skills':
    case 'audit':
      return commandAuditSkills(parsed, io);
    case 'init':
      return commandInit(parsed, io);
    case 'rules':
      return commandRules(parsed, io);
    case 'explain':
      return commandExplain(parsed, io);
    case 'mcp':
      return commandMcp(parsed, io);
    case 'version':
      write(io, 'stdout', `${await packageVersion()}\n`);
      return EXIT_OK;
    case 'help':
    case '':
      write(io, 'stdout', HELP);
      return command ? EXIT_OK : EXIT_USAGE;
    default:
      write(io, 'stderr', `vibe-shield: unknown command "${command}"\nRun \`vibe-shield help\` for usage.\n`);
      return EXIT_USAGE;
  }
}

/* Self-execute only when invoked as a program (never under test). */
if (require.main === module) {
  void run(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      process.stderr.write(`vibe-shield: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = EXIT_USAGE;
    });
}

export { HELP as HELP_TEXT, commandScan, commandAuditSkills, commandInit, commandRules, commandExplain, commandMcp };
