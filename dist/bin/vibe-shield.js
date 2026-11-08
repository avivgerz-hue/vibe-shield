#!/usr/bin/env node
"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.HELP_TEXT = exports.EXIT_USAGE = exports.EXIT_FINDINGS = exports.EXIT_OK = exports.defaultIo = void 0;
exports.parseArgs = parseArgs;
exports.run = run;
exports.commandScan = commandScan;
exports.commandAuditSkills = commandAuditSkills;
exports.commandInit = commandInit;
exports.commandRules = commandRules;
exports.commandExplain = commandExplain;
exports.commandMcp = commandMcp;
const node_fs_1 = require("node:fs");
const path = __importStar(require("node:path"));
const skill_auditor_1 = require("../src/mcp-guard/skill-auditor");
const server_1 = require("../src/mcp/server");
const scaffold_1 = require("../src/init/scaffold");
const console_reporter_1 = require("../src/reporter/console-reporter");
const formatters_1 = require("../src/reporter/formatters");
const patch_prompt_writer_1 = require("../src/reporter/patch-prompt-writer");
const engine_1 = require("../src/scanner/engine");
const rules_1 = require("../src/scanner/rules");
const types_1 = require("../src/scanner/types");
const defaultIo = () => ({
    stdout: process.stdout,
    stderr: process.stderr,
    cwd: process.cwd(),
    env: process.env,
});
exports.defaultIo = defaultIo;
/** Exit codes: 0 clean, 1 findings at/above `--fail-on`, 2 usage error. */
exports.EXIT_OK = 0;
exports.EXIT_FINDINGS = 1;
exports.EXIT_USAGE = 2;
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
  --format <fmt>         console | compact | summary | json | sarif | github   (console)
  --out <file>           Write the report to a file instead of stdout.
  --fix-prompt           Write ${patch_prompt_writer_1.PATCH_PROMPT_FILENAME} with exact fix instructions.
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
  npx github:avivgerz-hue/vibe-shield scan
  npx github:avivgerz-hue/vibe-shield scan --fail-on high --format github
  npx github:avivgerz-hue/vibe-shield scan --fix-prompt
  npx github:avivgerz-hue/vibe-shield init
  npx github:avivgerz-hue/vibe-shield explain VSB-DB-001
  npx github:avivgerz-hue/vibe-shield audit-skills .claude
`;
exports.HELP_TEXT = HELP;
const BOOLEAN_FLAGS = new Set([
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
    'fail-on',
    'severity',
    'rules',
    'ignore',
    'max-findings',
    'target',
    'agent',
    'category',
]);
const SHORT_FLAGS = {
    '-h': 'help',
    '-v': 'version',
    '-f': 'format',
    '-o': 'out',
    '-q': 'quiet',
};
/** Parse `argv` without any dependency. Supports `--flag=value` and repeats. */
function parseArgs(argv) {
    const positionals = [];
    const flags = new Map();
    const unknown = [];
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
                if (inlineValue === undefined && value !== undefined)
                    i += 1;
                if (value === undefined) {
                    unknown.push(raw);
                    continue;
                }
                // Repeatable flag: keep every value.
                const existing = flags.get(normalised);
                if (normalised === 'ignore' && typeof existing === 'string') {
                    flags.set(normalised, `${existing}\n${value}`);
                }
                else {
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
const flagString = (parsed, name) => {
    const value = parsed.flags.get(name);
    return typeof value === 'string' ? value : undefined;
};
const flagBool = (parsed, name) => parsed.flags.get(name) === true;
const flagNumber = (parsed, name, fallback) => {
    const raw = flagString(parsed, name);
    if (raw === undefined)
        return fallback;
    const value = Number.parseInt(raw, 10);
    return Number.isFinite(value) ? value : fallback;
};
/* -------------------------------------------------------------------------- */
/* Output helpers                                                             */
/* -------------------------------------------------------------------------- */
const write = (io, stream, text) => {
    io[stream].write(text);
};
async function emitReport(result, io, options, parsed) {
    const noColor = flagBool(parsed, 'no-color') || io.env.NO_COLOR !== undefined;
    const color = (0, console_reporter_1.createColorizer)(io.stdout);
    if (noColor)
        color.enabled = false;
    let patchPath = null;
    if (options.fixPrompt) {
        patchPath = await (0, patch_prompt_writer_1.writePatchPrompt)(result, {
            outDir: io.cwd,
            minSeverity: ((0, types_1.isSeverity)(flagString(parsed, 'severity')) ? flagString(parsed, 'severity') : 'info'),
        });
    }
    if (options.quiet) {
        // One line: verdict + counts. Machine-friendly and CI-log friendly.
        const counts = result.score.counts;
        const files = `${result.stats.filesScanned} ${result.stats.filesScanned === 1 ? 'file' : 'files'}`;
        const verdict = result.stats.filesScanned === 0 ? '0 files scanned — not a pass' : `${result.score.score}/100 ${result.score.grade}`;
        write(io, 'stdout', `${verdict} — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low (${files})\n`);
    }
    else if (options.format === 'console') {
        (0, console_reporter_1.reportConsole)(result, io.stdout, {
            color,
            maxFindings: options.maxFindings,
            width: Math.min(io.stdout.columns ?? 100, 140),
        });
    }
    else {
        write(io, 'stdout', (0, formatters_1.formatResult)(result, options.format));
    }
    if (patchPath) {
        write(io, 'stderr', `\n📝 Wrote ${path.relative(io.cwd, patchPath) || patchPath} — hand it to your agent, or run \`npx github:avivgerz-hue/vibe-shield scan\` after fixing.\n`);
    }
    if (options.out) {
        const target = path.resolve(io.cwd, options.out);
        const { promises: fs } = await Promise.resolve().then(() => __importStar(require('node:fs')));
        await fs.writeFile(target, (0, formatters_1.formatResult)(result, options.format === 'console' ? 'json' : options.format), 'utf8');
        write(io, 'stderr', `📄 Report written to ${options.out}\n`);
    }
}
/* -------------------------------------------------------------------------- */
/* Commands                                                                   */
/* -------------------------------------------------------------------------- */
async function commandScan(parsed, io) {
    const format = (flagString(parsed, 'format') ?? (flagBool(parsed, 'json') ? 'json' : 'console')).toLowerCase();
    if (!(0, formatters_1.isOutputFormat)(format)) {
        write(io, 'stderr', `vibe-shield: unknown --format "${format}". Choose one of: ${formatters_1.OUTPUT_FORMATS.join(', ')}\n`);
        return exports.EXIT_USAGE;
    }
    const failOn = (flagString(parsed, 'fail-on') ?? 'critical').toLowerCase();
    if (!(0, types_1.isSeverity)(failOn)) {
        write(io, 'stderr', `vibe-shield: --fail-on expects one of: critical, high, medium, low, info\n`);
        return exports.EXIT_USAGE;
    }
    const severity = flagString(parsed, 'severity');
    if (severity && !(0, types_1.isSeverity)(severity)) {
        write(io, 'stderr', `vibe-shield: --severity expects one of: critical, high, medium, low, info\n`);
        return exports.EXIT_USAGE;
    }
    const ruleSelectors = (flagString(parsed, 'rules') ?? '').split(',').map((entry) => entry.trim()).filter(Boolean);
    const rules = ruleSelectors.length ? (0, rules_1.selectRules)(ruleSelectors) : undefined;
    if (ruleSelectors.length && (!rules || rules.length === 0)) {
        write(io, 'stderr', `vibe-shield: no rules matched --rules "${ruleSelectors.join(',')}"\n`);
        return exports.EXIT_USAGE;
    }
    // A typo in the path must not look like a clean pass.
    const missing = parsed.positionals.filter((target) => !(0, node_fs_1.existsSync)(path.resolve(io.cwd, target)));
    if (missing.length) {
        write(io, 'stderr', `vibe-shield: no such file or directory: ${missing.join(', ')}\n`);
        return exports.EXIT_USAGE;
    }
    const result = await (0, engine_1.scanProject)({
        rootDir: io.cwd,
        paths: parsed.positionals.length ? parsed.positionals : undefined,
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
    const filtered = severity && (0, types_1.isSeverity)(severity)
        ? {
            ...result,
            findings: result.findings.filter((finding) => (0, engine_1.hasFindingsAtOrAbove)({ ...result, findings: [finding] }, severity)),
        }
        : result;
    await emitReport(filtered, io, {
        fixPrompt: flagBool(parsed, 'fix-prompt'),
        format: format,
        out: flagString(parsed, 'out'),
        quiet: flagBool(parsed, 'quiet'),
        maxFindings: flagNumber(parsed, 'max-findings', 50),
    }, parsed);
    // An explicit target that matched nothing is a configuration error, not a
    // pass: a CI gate pointed at a path excluded by an ignore file would
    // otherwise report success forever without scanning a single file.
    if (parsed.positionals.length > 0 && filtered.stats.filesScanned === 0) {
        write(io, 'stderr', `vibe-shield: no scannable files matched ${parsed.positionals.join(', ')} (check ignore files, or pass --no-shield-ignore)\n`);
        return exports.EXIT_USAGE;
    }
    return (0, engine_1.hasFindingsAtOrAbove)(filtered, failOn) ? exports.EXIT_FINDINGS : exports.EXIT_OK;
}
async function commandAuditSkills(parsed, io) {
    const format = (flagString(parsed, 'format') ?? (flagBool(parsed, 'json') ? 'json' : 'console')).toLowerCase();
    if (!(0, formatters_1.isOutputFormat)(format)) {
        write(io, 'stderr', `vibe-shield: unknown --format "${format}".\n`);
        return exports.EXIT_USAGE;
    }
    const failOn = (flagString(parsed, 'fail-on') ?? 'high').toLowerCase();
    if (!(0, types_1.isSeverity)(failOn)) {
        write(io, 'stderr', `vibe-shield: --fail-on expects one of: critical, high, medium, low, info\n`);
        return exports.EXIT_USAGE;
    }
    const result = await (0, skill_auditor_1.auditSkills)(io.cwd, {
        paths: parsed.positionals.length ? parsed.positionals : undefined,
        version: await (0, engine_1.packageVersion)(),
    });
    await emitReport(result, io, {
        fixPrompt: flagBool(parsed, 'fix-prompt'),
        format: format,
        out: flagString(parsed, 'out'),
        quiet: flagBool(parsed, 'quiet'),
        maxFindings: flagNumber(parsed, 'max-findings', 50),
    }, parsed);
    return (0, engine_1.hasFindingsAtOrAbove)(result, failOn) ? exports.EXIT_FINDINGS : exports.EXIT_OK;
}
async function commandInit(parsed, io) {
    const target = path.resolve(io.cwd, flagString(parsed, 'target') ?? '.');
    const agent = (flagString(parsed, 'agent') ?? 'all').toLowerCase();
    if (!['claude', 'cursor', 'generic', 'all'].includes(agent)) {
        write(io, 'stderr', 'vibe-shield: --agent expects claude, cursor, generic or all\n');
        return exports.EXIT_USAGE;
    }
    const result = await (0, scaffold_1.installScaffold)({
        rootDir: target,
        agents: agent,
        workflow: !flagBool(parsed, 'no-workflow'),
        force: flagBool(parsed, 'force'),
        dryRun: false,
        env: io.env,
    });
    const color = (0, console_reporter_1.createColorizer)(io.stdout);
    if (flagBool(parsed, 'no-color'))
        color.enabled = false;
    write(io, 'stdout', `\n${color.bold(color.cyan('🛡️  vibe-shield init'))} ${color.dim(target)}\n\n`);
    for (const file of result.written)
        write(io, 'stdout', `  ${color.green('created')}  ${file}\n`);
    for (const file of result.appended)
        write(io, 'stdout', `  ${color.green('updated')}  ${file}\n`);
    for (const file of result.blocked)
        write(io, 'stdout', `  ${color.yellow('blocked')}  ${file} ${color.dim('(left untouched — fix the file by hand)')}\n`);
    for (const file of result.skipped)
        write(io, 'stdout', `  ${color.gray('skipped')}  ${file} ${color.dim('(exists — use --force)')}\n`);
    for (const warning of result.warnings)
        write(io, 'stdout', `  ${color.yellow('note')}     ${warning}\n`);
    write(io, 'stdout', `\n${color.bold('Next steps')}\n`);
    write(io, 'stdout', `  1. ${color.dim('npx github:avivgerz-hue/vibe-shield scan')}                 ${color.dim('# baseline your repo')}\n`);
    write(io, 'stdout', `  2. ${color.dim('npx github:avivgerz-hue/vibe-shield scan --fix-prompt')}   ${color.dim('# generate the fix list')}\n`);
    write(io, 'stdout', `  3. Commit the new files — your agent now audits before it says "done".\n\n`);
    return exports.EXIT_OK;
}
function commandRules(parsed, io) {
    const category = flagString(parsed, 'category');
    const rules = category
        ? types_1.RULE_CATEGORIES.includes(category)
            ? (0, rules_1.rulesByCategory)(category)
            : []
        : [...rules_1.ALL_RULES];
    if (category && !rules.length) {
        write(io, 'stderr', `vibe-shield: unknown --category "${category}". Choose one of: ${types_1.RULE_CATEGORIES.join(', ')}\n`);
        return exports.EXIT_USAGE;
    }
    if (flagBool(parsed, 'json') || flagString(parsed, 'format') === 'json') {
        write(io, 'stdout', `${JSON.stringify(rules.map((rule) => ({
            id: rule.id,
            slug: rule.slug,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            confidence: rule.confidence,
            cwe: rule.cwe.id,
            description: rule.description,
            remediation: rule.remediation,
            references: rule.references,
        })), null, 2)}\n`);
        return exports.EXIT_OK;
    }
    const color = (0, console_reporter_1.createColorizer)(io.stdout);
    if (flagBool(parsed, 'no-color'))
        color.enabled = false;
    write(io, 'stdout', `\n${color.bold(`${rules.length} detection rules`)}\n`);
    let currentCategory = '';
    for (const rule of rules) {
        if (rule.category !== currentCategory) {
            currentCategory = rule.category;
            write(io, 'stdout', `\n${color.bold(color.cyan(types_1.CATEGORY_TITLES[rule.category]))}\n`);
        }
        write(io, 'stdout', `  ${color.dim(rule.id.padEnd(14))} ${rule.severity.padEnd(9)} ${rule.title}\n`);
    }
    write(io, 'stdout', `\n${color.dim('Run `npx github:avivgerz-hue/vibe-shield explain <RULE_ID>` for the full documentation.')}\n\n`);
    return exports.EXIT_OK;
}
function commandExplain(parsed, io) {
    const id = parsed.positionals[0];
    if (!id) {
        write(io, 'stderr', 'vibe-shield: explain needs a rule id, e.g. `vibe-shield explain VSB-DB-001`\n');
        return exports.EXIT_USAGE;
    }
    const rule = (0, rules_1.getRule)(id);
    if (!rule) {
        write(io, 'stderr', `vibe-shield: unknown rule "${id}". Run \`vibe-shield rules\` to list them.\n`);
        return exports.EXIT_USAGE;
    }
    const color = (0, console_reporter_1.createColorizer)(io.stdout);
    if (flagBool(parsed, 'no-color'))
        color.enabled = false;
    const out = [];
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
    for (const reference of rule.references)
        out.push(`  ${color.cyan(reference)}`);
    out.push('');
    out.push(color.dim(`CWE: ${rule.cwe.name} — ${rule.cwe.url}`));
    out.push('');
    write(io, 'stdout', `${out.join('\n')}\n`);
    return exports.EXIT_OK;
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
async function commandMcp(parsed, io) {
    if (parsed.positionals.length) {
        write(io, 'stderr', `vibe-shield: mcp takes no positional arguments (got ${parsed.positionals.join(', ')})\n`);
        return exports.EXIT_USAGE;
    }
    write(io, 'stderr', 'vibe-shield: MCP server listening on stdio\n');
    await (0, server_1.serveMcp)({ stdin: process.stdin, stdout: io.stdout, stderr: io.stderr }, { cwd: io.cwd, version: await (0, engine_1.packageVersion)() });
    return exports.EXIT_OK;
}
/* -------------------------------------------------------------------------- */
/* Entry point                                                                */
/* -------------------------------------------------------------------------- */
/** Run the CLI. Returns the process exit code. */
async function run(argv, io = (0, exports.defaultIo)()) {
    const parsed = parseArgs(argv);
    const command = parsed.command || (flagBool(parsed, 'version') ? 'version' : flagBool(parsed, 'help') ? 'help' : '');
    if (parsed.unknown.length) {
        write(io, 'stderr', `vibe-shield: unknown option${parsed.unknown.length === 1 ? '' : 's'} ${parsed.unknown.join(', ')}\n`);
        write(io, 'stderr', 'Run `vibe-shield help` for usage.\n');
        return exports.EXIT_USAGE;
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
            write(io, 'stdout', `${await (0, engine_1.packageVersion)()}\n`);
            return exports.EXIT_OK;
        case 'help':
        case '':
            write(io, 'stdout', HELP);
            return command ? exports.EXIT_OK : exports.EXIT_USAGE;
        default:
            write(io, 'stderr', `vibe-shield: unknown command "${command}"\nRun \`vibe-shield help\` for usage.\n`);
            return exports.EXIT_USAGE;
    }
}
/* Self-execute only when invoked as a program (never under test). */
if (require.main === module) {
    void run(process.argv.slice(2))
        .then((code) => {
        process.exitCode = code;
    })
        .catch((error) => {
        process.stderr.write(`vibe-shield: ${error instanceof Error ? error.message : String(error)}\n`);
        process.exitCode = exports.EXIT_USAGE;
    });
}
