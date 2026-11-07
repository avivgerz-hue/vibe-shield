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
/** Everything the CLI needs from the outside world (injectable for tests). */
export interface CliIo {
    stdout: {
        write(chunk: string): unknown;
        isTTY?: boolean;
        columns?: number;
    };
    stderr: {
        write(chunk: string): unknown;
        isTTY?: boolean;
        columns?: number;
    };
    cwd: string;
    env: NodeJS.ProcessEnv;
}
export declare const defaultIo: () => CliIo;
/** Exit codes: 0 clean, 1 findings at/above `--fail-on`, 2 usage error. */
export declare const EXIT_OK = 0;
export declare const EXIT_FINDINGS = 1;
export declare const EXIT_USAGE = 2;
declare const HELP = "vibe-shield \u2014 security scanner for AI-generated code\n\nUSAGE\n  vibe-shield <command> [options]\n\nCOMMANDS\n  scan [paths...]        Scan the project (default: current directory).\n  audit-skills [paths...]  Audit agent skills, Cursor rules, AGENTS.md and MCP configs.\n  init                   Install the Agent Skill, AGENTS.md section and CI workflow.\n  rules                  List every detection rule.\n  explain <RULE_ID>      Show full documentation for a rule.\n  mcp                    Serve the Model Context Protocol tools over stdio.\n  version                Print the version.\n  help                   Print this help.\n\nSCAN OPTIONS\n  --format <fmt>         console | compact | summary | json | sarif | github   (console)\n  --out <file>           Write the report to a file instead of stdout.\n  --fix-prompt           Write SECURITY_PATCH_PROMPT.md with exact fix instructions.\n  --fail-on <severity>   Exit 1 when a finding at/above this severity exists. (critical)\n  --severity <severity>  Only report findings at/above this severity.\n  --rules <ids>          Comma-separated rule ids/slugs (supports VSB-DB-*).\n  --ignore <glob>        Extra gitignore-style pattern (repeatable).\n  --include-tests        Include test, spec and fixture files.\n  --include-docs         Include Markdown and docs/.\n  --cache                Reuse .vibe-shield-cache.json between runs.\n  --max-findings <n>     Limit the console list (0 = all).   (50)\n  --quiet                Print only the verdict line and the exit code.\n  --no-color             Disable ANSI colour.\n  --no-shield-ignore     Ignore .vibe-shieldignore (e.g. to scan excluded fixtures).\n  --json                 Shorthand for --format json.\n\nINIT OPTIONS\n  --target <dir>         Repository to install into.          (cwd)\n  --agent <kind>         claude | cursor | generic | all.      (all)\n  --no-workflow          Skip the GitHub Actions workflow.\n  --force                Overwrite existing files.\n  --yes                  Accepted for non-interactive CI use (init never prompts).\n\nEXAMPLES\n  npx vibe-shield scan\n  npx vibe-shield scan --fail-on high --format github\n  npx vibe-shield scan --fix-prompt\n  npx vibe-shield init\n  npx vibe-shield explain VSB-DB-001\n  npx vibe-shield audit-skills .claude\n";
interface ParsedArgs {
    command: string;
    positionals: string[];
    flags: Map<string, string | boolean>;
    unknown: string[];
}
/** Parse `argv` without any dependency. Supports `--flag=value` and repeats. */
export declare function parseArgs(argv: readonly string[]): ParsedArgs;
declare function commandScan(parsed: ParsedArgs, io: CliIo): Promise<number>;
declare function commandAuditSkills(parsed: ParsedArgs, io: CliIo): Promise<number>;
declare function commandInit(parsed: ParsedArgs, io: CliIo): Promise<number>;
declare function commandRules(parsed: ParsedArgs, io: CliIo): number;
declare function commandExplain(parsed: ParsedArgs, io: CliIo): number;
/**
 * Serve MCP over stdio.
 *
 * Nothing but JSON-RPC may reach stdout here — a banner or progress line would
 * corrupt the client session — so the one diagnostic permitted (an explicit
 * note that the server is ready) goes to stderr.
 */
declare function commandMcp(parsed: ParsedArgs, io: CliIo): Promise<number>;
/** Run the CLI. Returns the process exit code. */
export declare function run(argv: readonly string[], io?: CliIo): Promise<number>;
export { HELP as HELP_TEXT, commandScan, commandAuditSkills, commandInit, commandRules, commandExplain, commandMcp };
