"use strict";
/**
 * vibe-shield :: `npx -y @vibefoundry/vibe-shield init`
 * -------------------------------------
 * One command turns any repository into a guarded one. It installs:
 *
 *  - `.claude/skills/vibe-shield/SKILL.md` — the Agent Skill, so Claude Code
 *    (and any SKILL.md-aware agent) audits before it reports "done".
 *  - an `AGENTS.md` section — the same contract for Codex, Cursor, Windsurf and
 *    every other agent that reads a repo-level instruction file.
 *  - `.github/workflows/vibe-shield.yml` — fails the build on new findings.
 *  - `.vibe-shieldignore` — the documented escape hatch for generated code.
 *
 * Nothing is overwritten without `--force`, and every write is reported so the
 * command is safe to re-run.
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
exports.IGNORE_TEMPLATE = exports.WORKFLOW_TEMPLATE = exports.MCP_SERVER_ENTRY = exports.MCP_SERVER_SPEC = exports.MCP_SERVER_KEY = exports.AGENTS_SECTION = exports.SKILL_TEMPLATE = exports.AGENT_NAMES = void 0;
exports.mcpServerEntry = mcpServerEntry;
exports.packageVersionFromDisk = packageVersionFromDisk;
exports.mergeMcpConfig = mergeMcpConfig;
exports.buildScaffold = buildScaffold;
exports.mergeAgentConfig = mergeAgentConfig;
exports.installScaffold = installScaffold;
exports.locateBundledSkill = locateBundledSkill;
const node_fs_1 = require("node:fs");
const path = __importStar(require("node:path"));
exports.AGENT_NAMES = ['claude', 'opencode', 'codex', 'generic', 'cursor', 'windsurf', 'copilot', 'cline', 'roo', 'zed'];
const shared_1 = require("../scanner/rules/shared");
const BANNER = '<!-- Managed by vibe-shield. Edit freely; `npx -y @vibefoundry/vibe-shield init --force` regenerates this file. -->';
/* -------------------------------------------------------------------------- */
/* SKILL.md                                                                   */
/* -------------------------------------------------------------------------- */
exports.SKILL_TEMPLATE = `---
name: vibe-shield
description: Apply a six-phase defensive security review to changes affecting applications, APIs, data, AI agents, and MCP configuration. Use static evidence, preserve behavior, and report limitations.
allowed-tools: Bash(npx -y @vibefoundry/vibe-shield scan*), Bash(npx -y @vibefoundry/vibe-shield audit-skills*), Bash(npx -y @vibefoundry/vibe-shield explain*), Read(./**), Grep, Glob
license: MIT
metadata:
  author: VibeFoundry
  homepage: https://github.com/avivgerz-hue/vibe-shield
  version: 2.0.0
---

# Defensive AppSec architect protocol

Work only within the authorized project. Static findings are evidence for review, not proof of exploitability or a guarantee of safety. Do not transmit source code or secrets. Ask before changing production services, rotating credentials, or making destructive changes.

## Phase 1: Attack-surface reconnaissance

Map entrypoints and trust boundaries: API methods, authentication and authorization, middleware matchers, database tables and policies, storage, LLM inputs and tools, webhooks, and agent/MCP configuration. Check deployment configuration and exclusions. Identify what the scanner cannot see.

## Phase 2: Automated static scan and skill audit

\`\`\`bash
npx -y @vibefoundry/vibe-shield scan . --format json
npx -y @vibefoundry/vibe-shield audit-skills . --format json
\`\`\`

Inspect findings, inventory, ignored paths, and the files scanned. The explicit \`.\` includes test and documentation files: review fixtures as examples rather than blindly changing them. Use \`explain <RULE_ID>\` to investigate a rule. These commands run locally; first-time installation with npx requires registry access.

## Phase 3: Deep contextual threat modeling

Trace untrusted input through authentication, ownership checks and tenant boundaries to database, filesystem, network, HTML, and LLM sinks. Inspect IDOR, business-logic bypasses, webhook signature verification and asynchronous jobs. Check cross-file guards and deployed database policies; absence of a static finding is not evidence of protection.

## Phase 4: Surgical zero-regression remediation

- On Next.js mutation routes, authenticate the session on the server and authorize the target resource against the session principal before writes. Do not trust identity from request bodies.
- Enable Supabase RLS and write action-specific policies using the authenticated principal; test both permitted and denied tenants before deploying migrations.
- Validate inputs at the boundary with a schema such as Zod, then use parameterized database queries. Treat LLM output as untrusted.
- Use explicit CORS allowlists, secure cookie flags and a CSP appropriate for the application. Test login, redirects, and browser behavior.
- Report exposed credentials to the owner for provider-side rotation; avoid reproducing their values in reports. Do not suppress findings or weaken controls to obtain a higher score. Ask for missing business or deployment decisions.

## Phase 5: Verification gate

Run project tests and both audits again. Aim for 100/100 Grade A+ with no high or critical findings, but report any unresolved finding, exclusion, false positive, or verification limitation honestly rather than claiming success. Never equate a clean score with a complete security assessment.

\`\`\`bash
npx -y @vibefoundry/vibe-shield scan --fail-on high
npx -y @vibefoundry/vibe-shield audit-skills --fail-on high
\`\`\`

## Phase 6: Executive security sign-off

Produce a Markdown or HTML report with scope, inventory, risks prioritized by severity, evidence, actions, test results and remaining uncertainty. Illustrative code examples are not project-specific patches; review and adapt them. Obtain human approval before deployment or provider-side action.

\`\`\`bash
npx -y @vibefoundry/vibe-shield scan --report SECURITY-REPORT.md --patch-prompt PATCH-PROMPT.md
npx -y @vibefoundry/vibe-shield audit-skills --report AGENT-REPORT.html
\`\`\`
`;
/* -------------------------------------------------------------------------- */
/* AGENTS.md section                                                          */
/* -------------------------------------------------------------------------- */
exports.AGENTS_SECTION = `## Security gate (vibe-shield)

This repository is guarded by [vibe-shield](https://github.com/avivgerz-hue/vibe-shield).

Before you report any task as complete:

1. Run \`npx -y @vibefoundry/vibe-shield scan --fail-on high\` and fix every finding it reports.
2. Never suppress a finding (\`vibe-shield-disable\`, \`.vibe-shieldignore\` edits,
   \`--ignore\`) to make the gate pass — that is the human's call.
3. If you touched \`.claude/\`, \`.cursor/\`, \`AGENTS.md\`, \`mcp.json\` or a skill,
   also run \`npx -y @vibefoundry/vibe-shield audit-skills\`.
4. Surface any exposed credential to the user for rotation. Do not "fix" it by
   deleting the line and moving on.

The gate exists because the most common way AI-written code reaches production
with a leaked \`SUPABASE_SERVICE_ROLE_KEY\` or an unauthenticated \`DELETE\`
endpoint is that nobody asked it a second question.
`;
/* -------------------------------------------------------------------------- */
/* .mcp.json                                                                  */
/* -------------------------------------------------------------------------- */
/** Key this tool owns inside `mcpServers`; nothing else is ever touched. */
exports.MCP_SERVER_KEY = 'vibe-shield';
/**
 * The server entry written into `.mcp.json`.
 *
 * `npx` is used rather than a local path so the config keeps working when the
 * project is cloned elsewhere or the package is upgraded.
 *
 * The spec is always pinned to an exact version — `@vibefoundry/vibe-shield@1.1.0`.
 * Two reasons: a bare name re-resolves to whatever `latest` points at on every
 * launch, and vibe-shield's own `VSB-AGENT-004` rule flags an unpinned `npx -y`
 * server as high severity. Pinning keeps the gate at A+ for projects that adopt
 * the tool, and upgrades become explicit (`init --force` rewrites the pin).
 */
exports.MCP_SERVER_SPEC = shared_1.SELF_GITHUB_SPEC;
/** Build the `.mcp.json` entry, pinned to `version` when one is known. */
function mcpServerEntry(version) {
    const spec = version ? `${exports.MCP_SERVER_SPEC}@${version}` : exports.MCP_SERVER_SPEC;
    return { command: 'npx', args: ['--yes', spec, 'mcp'] };
}
/**
 * The entry as this install writes it: pinned to the running package version.
 * Falls back to unpinned only in a stripped checkout where no `package.json`
 * names this package, which is the one case where no version is knowable.
 */
exports.MCP_SERVER_ENTRY = mcpServerEntry(packageVersionFromDisk());
/**
 * Merge the vibe-shield server into an existing `.mcp.json` without disturbing
 * anything already there.
 *
 * Returns the serialised file and whether our key was newly added. Existing
 * servers, other top-level keys and the user's formatting choices are preserved;
 * a malformed file is reported rather than overwritten, because silently
 * rewriting someone's MCP config could break every server they run.
 */
/**
 * The version of the running install, used to pin `.mcp.json`.
 *
 * Read from the nearest `package.json` that names this package. Falls back to
 * the range in `package.json` only if nothing is found, which keeps `init`
 * working in a stripped-down checkout rather than writing a nameless spec.
 */
function packageVersionFromDisk() {
    let dir = __dirname;
    for (let depth = 0; depth < 6; depth += 1) {
        try {
            const raw = (0, node_fs_1.readFileSync)(path.join(dir, 'package.json'), 'utf8');
            const parsed = JSON.parse(raw);
            if ((parsed.name === shared_1.SELF_GITHUB_SPEC || parsed.name === 'vibe-shield') && parsed.version) {
                return parsed.version;
            }
        }
        catch {
            // Keep walking up.
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return null;
}
function mergeMcpConfig(existing, options = {}) {
    const entry = mcpServerEntry(options.version ?? packageVersionFromDisk());
    if (existing === null || existing.trim() === '') {
        return {
            contents: `${JSON.stringify({ mcpServers: { [exports.MCP_SERVER_KEY]: entry } }, null, 2)}\n`,
            changed: true,
        };
    }
    let parsed;
    try {
        parsed = JSON.parse(existing);
    }
    catch (error) {
        return {
            contents: existing,
            changed: false,
            error: `.mcp.json is not valid JSON (${error instanceof Error ? error.message : String(error)}); left untouched.`,
        };
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return { contents: existing, changed: false, error: '.mcp.json is not a JSON object; left untouched.' };
    }
    const config = parsed;
    const servers = config.mcpServers;
    if (servers !== undefined && (typeof servers !== 'object' || servers === null || Array.isArray(servers))) {
        return { contents: existing, changed: false, error: '.mcp.json has a non-object "mcpServers"; left untouched.' };
    }
    const table = (servers ?? {});
    const present = Object.prototype.hasOwnProperty.call(table, exports.MCP_SERVER_KEY);
    if (present && !options.force) {
        return { contents: existing, changed: false };
    }
    const next = { ...config, mcpServers: { ...table, [exports.MCP_SERVER_KEY]: entry } };
    return { contents: `${JSON.stringify(next, null, 2)}\n`, changed: true };
}
/* -------------------------------------------------------------------------- */
/* GitHub Actions workflow                                                    */
/* -------------------------------------------------------------------------- */
exports.WORKFLOW_TEMPLATE = `name: vibe-shield

on:
  push:
    branches: [main, master]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scan:
    name: Security audit
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Scan for vulnerabilities
        run: npx -y @vibefoundry/vibe-shield scan --format sarif --out vibe-shield.sarif --fail-on high
        continue-on-error: true

      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vibe-shield.sarif
          category: vibe-shield

      - name: Audit agent surface
        run: npx -y @vibefoundry/vibe-shield audit-skills --fail-on high

      - name: Enforce the gate
        run: npx -y @vibefoundry/vibe-shield scan --fail-on high --quiet
`;
/* -------------------------------------------------------------------------- */
/* .vibe-shieldignore                                                         */
/* -------------------------------------------------------------------------- */
exports.IGNORE_TEMPLATE = `# .vibe-shieldignore — gitignore syntax.
#
# Keep this file as short as possible: every line hides real code from the
# security gate. Prefer an inline suppression with a reason where it applies:
#
#   // vibe-shield-disable-next-line VSB-AI-001 -- path comes from a fixed enum
#
# Generated code, vendored third-party sources and build output are the only
# good reasons to ignore a path wholesale.

# Generated / vendored
# vendor/**
# **/*.generated.ts
# **/__generated__/**

# Local-only scratch work
# scratch/**
`;
/* -------------------------------------------------------------------------- */
/* Cursor rules                                                               */
/* -------------------------------------------------------------------------- */
const CURSOR_RULE = `---
description: Run vibe-shield before finishing any coding task
globs: ["**/*"]
alwaysApply: true
---

${BANNER}

# Security gate

Before reporting a task complete, run \`npx -y @vibefoundry/vibe-shield scan --fail-on high\` and
fix every finding. Never suppress a finding to make the gate pass. If the scan
reports an exposed credential, tell the user to rotate it at the provider.
`;
/** Build the full set of files for a given target repository. */
function buildScaffold(options) {
    const selection = options.agents ?? 'all';
    const agents = selection === 'all' ? exports.AGENT_NAMES : typeof selection === 'string' ? [selection] : selection;
    const selected = (name) => agents.includes(name);
    const files = [];
    const add = (relativePath, contents, mode, description, mergeKey) => {
        if (!files.some(file => file.relativePath === relativePath))
            files.push({ relativePath, contents, mode, description, mergeKey, ...(mode === 'append' ? { marker: '## Security gate (vibe-shield)' } : {}) });
    };
    // Kept for compatibility with the original --agent interface.
    add('.mcp.json', '', 'merge', 'Shared Claude MCP server', 'mcpServers');
    if (selected('claude')) {
        add('.claude/skills/vibe-shield/SKILL.md', exports.SKILL_TEMPLATE, 'write', 'Claude Code skill');
        add('CLAUDE.md', exports.AGENTS_SECTION, 'append', 'Claude Code instructions');
        add('.claude-plugin/plugin.json', JSON.stringify({ name: 'vibe-shield', description: 'Defensive static security audit skill and MCP server', version: packageVersionFromDisk() ?? '2.0.0', author: { name: 'VibeFoundry' }, skills: './.claude/skills/' }, null, 2) + '\n', 'write', 'Claude Code plugin manifest');
    }
    if (selected('opencode'))
        add('opencode.json', '', 'merge', 'OpenCode MCP configuration', 'mcp');
    if (selected('opencode') || selected('codex') || selected('generic'))
        add('AGENTS.md', exports.AGENTS_SECTION, 'append', 'Universal agent instructions');
    if (selected('codex') || selected('generic'))
        add('.agents/skills/vibe-shield/SKILL.md', exports.SKILL_TEMPLATE, 'write', 'Universal agent skill');
    if (selected('cursor')) {
        add('.cursor/mcp.json', '', 'merge', 'Cursor MCP configuration', 'mcpServers');
        add('.cursor/rules/vibe-shield.mdc', CURSOR_RULE, 'write', 'Cursor security rule');
    }
    if (selected('windsurf'))
        add('.windsurfrules', exports.AGENTS_SECTION, 'append', 'Windsurf instructions');
    if (selected('copilot')) {
        add('.vscode/mcp.json', '', 'merge', 'VS Code MCP configuration', 'servers');
        add('.github/copilot-instructions.md', exports.AGENTS_SECTION, 'append', 'Copilot instructions');
    }
    if (selected('cline') || selected('roo'))
        add('.clinerules', exports.AGENTS_SECTION, 'append', 'Cline and Roo instructions');
    if (selected('zed'))
        add('.zed/settings.json', '', 'merge', 'Zed context server', 'context_servers');
    if (options.workflow !== false)
        add('.github/workflows/vibe-shield.yml', exports.WORKFLOW_TEMPLATE, 'write', 'GitHub Actions security gate');
    add('.vibe-shieldignore', exports.IGNORE_TEMPLATE, 'write', 'Documented ignore file');
    return files;
}
/** Merge one owned server without replacing other entries or malformed files. */
function mergeAgentConfig(existing, key, options = {}) {
    if (key === 'mcpServers')
        return mergeMcpConfig(existing, options);
    let config = {};
    if (existing !== null && existing.trim()) {
        try {
            const parsed = JSON.parse(existing);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
                return { contents: existing, changed: false, error: 'Configuration is not a JSON object; left untouched.' };
            config = parsed;
        }
        catch {
            return { contents: existing, changed: false, error: 'Configuration is not valid JSON (including JSON with comments); left untouched.' };
        }
    }
    const current = config[key];
    if (current !== undefined && (!current || typeof current !== 'object' || Array.isArray(current)))
        return { contents: existing ?? '', changed: false, error: `${key} is not an object; left untouched.` };
    const servers = (current ?? {});
    if (Object.prototype.hasOwnProperty.call(servers, exports.MCP_SERVER_KEY) && !options.force)
        return { contents: existing ?? '', changed: false };
    const base = mcpServerEntry(options.version ?? packageVersionFromDisk());
    const entry = key === 'mcp' ? { type: 'local', command: [base.command, ...base.args], enabled: true }
        : key === 'servers' ? { type: 'stdio', ...base }
            : base;
    const next = { ...config, [key]: { ...servers, [exports.MCP_SERVER_KEY]: entry } };
    return { contents: `${JSON.stringify(next, null, 2)}\n`, changed: true };
}
const exists = async (file) => {
    try {
        await node_fs_1.promises.access(file);
        return true;
    }
    catch {
        return false;
    }
};
/** Write the scaffold into `options.rootDir`. Idempotent unless `force`. */
async function installScaffold(options) {
    const rootDir = path.resolve(options.rootDir);
    const result = { written: [], appended: [], skipped: [], blocked: [], warnings: [] };
    const resolvedVersion = options.version ?? options.env?.VIBE_SHIELD_VERSION ?? packageVersionFromDisk();
    const files = buildScaffold(options);
    for (const file of files) {
        const absolute = path.join(rootDir, file.relativePath);
        const present = await exists(absolute);
        if (file.mode === 'append') {
            let current = '';
            if (present) {
                try {
                    current = await node_fs_1.promises.readFile(absolute, 'utf8');
                }
                catch {
                    current = '';
                }
            }
            if (file.marker && current.includes(file.marker)) {
                result.skipped.push(file.relativePath);
                continue;
            }
            if (options.dryRun) {
                result.appended.push(file.relativePath);
                continue;
            }
            await node_fs_1.promises.mkdir(path.dirname(absolute), { recursive: true });
            const separator = current.trim().length ? (current.endsWith('\n') ? '\n' : '\n\n') : '';
            await node_fs_1.promises.appendFile(absolute, `${separator}${file.contents}`, 'utf8');
            result.appended.push(file.relativePath);
            continue;
        }
        if (file.mode === 'merge') {
            let existing = null;
            if (present) {
                try {
                    existing = await node_fs_1.promises.readFile(absolute, 'utf8');
                }
                catch {
                    result.blocked.push(file.relativePath);
                    result.warnings.push(`${file.relativePath}: could not read existing configuration; left untouched.`);
                    continue;
                }
            }
            const merged = mergeAgentConfig(existing, file.mergeKey ?? 'mcpServers', { force: options.force, version: resolvedVersion });
            if (merged.error) {
                // Not a `skipped` entry: `--force` cannot repair invalid JSON, so the
                // summary must not suggest it can.
                result.warnings.push(`${file.relativePath}: ${merged.error}`);
                result.blocked.push(file.relativePath);
                continue;
            }
            if (!merged.changed) {
                result.skipped.push(file.relativePath);
                continue;
            }
            if (options.dryRun) {
                result.written.push(file.relativePath);
                continue;
            }
            await node_fs_1.promises.mkdir(path.dirname(absolute), { recursive: true });
            await node_fs_1.promises.writeFile(absolute, merged.contents, 'utf8');
            result.written.push(file.relativePath);
            continue;
        }
        if (present && !options.force) {
            result.skipped.push(file.relativePath);
            continue;
        }
        if (options.dryRun) {
            result.written.push(file.relativePath);
            continue;
        }
        await node_fs_1.promises.mkdir(path.dirname(absolute), { recursive: true });
        await node_fs_1.promises.writeFile(absolute, file.contents, 'utf8');
        result.written.push(file.relativePath);
    }
    // A repository without a package.json will not be able to `npx -y @vibefoundry/vibe-shield`
    // as a dev dependency; it still works through npx, so this is only a warning.
    if (!(await exists(path.join(rootDir, 'package.json')))) {
        result.warnings.push('No package.json found — run the gate with `npx -y @vibefoundry/vibe-shield scan`.');
    }
    if (!(await exists(path.join(rootDir, '.git')))) {
        result.warnings.push('No .git directory found — the workflow only runs once this is a git repository.');
    }
    return result;
}
/** Locate the shipped `SKILL.md` (used by `init` to copy the canonical file). */
async function locateBundledSkill(startDir) {
    let dir = startDir;
    for (let depth = 0; depth < 8; depth += 1) {
        const candidate = path.join(dir, 'SKILL.md');
        const packageJson = path.join(dir, 'package.json');
        if ((await exists(candidate)) && (await exists(packageJson)))
            return candidate;
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return null;
}
