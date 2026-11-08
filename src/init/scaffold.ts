/**
 * vibe-shield :: `npx github:avivgerz-hue/vibe-shield init`
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

import { promises as fs } from 'node:fs';
import * as path from 'node:path';

/** One file the scaffolder wants to create. */
export interface ScaffoldFile {
  /** Path relative to the target repository root (POSIX). */
  relativePath: string;
  contents: string;
  /** `write` creates if missing, `append` adds a section, `merge` adds one JSON key. */
  mode: 'write' | 'append' | 'merge';
  /** Marker used to detect an existing section for `append` mode. */
  marker?: string;
  /** Human description shown in the init summary. */
  description: string;
}

export interface InitOptions {
  /** Repository root (absolute). */
  rootDir: string;
  /** Which agent integration to install. */
  agents?: 'claude' | 'cursor' | 'generic' | 'all';
  /** Write the GitHub Actions workflow. Default true. */
  workflow?: boolean;
  /** Overwrite existing files. Default false. */
  force?: boolean;
  /** Print what would happen without writing. */
  dryRun?: boolean;
  /** Pin a specific version in the workflow (default `latest`). */
  version?: string;
}

export interface InitResult {
  written: string[];
  appended: string[];
  skipped: string[];
  /** Files that exist but were left alone because they could not be merged. */
  blocked: string[];
  warnings: string[];
}

const BANNER = '<!-- Managed by vibe-shield. Edit freely; `npx github:avivgerz-hue/vibe-shield init --force` regenerates this file. -->';

/* -------------------------------------------------------------------------- */
/* SKILL.md                                                                   */
/* -------------------------------------------------------------------------- */

export const SKILL_TEMPLATE = `---
name: vibe-shield
description: Audit any change for AI-introduced security bugs (leaked keys, unguarded API routes, disabled Row Level Security, SQL injection, prompt injection, poisoned MCP servers) and fix them before reporting a task as done. Use whenever you write or modify application code, API routes, server actions, database migrations, auth logic, environment variables, LLM calls, webhook handlers, agent skills or MCP configuration.
allowed-tools: Bash(npx github:avivgerz-hue/vibe-shield scan*), Bash(npx github:avivgerz-hue/vibe-shield audit-skills*), Bash(npx github:avivgerz-hue/vibe-shield explain*), Read(./**), Grep, Glob
license: MIT
metadata:
  author: VibeFoundry
  homepage: https://github.com/avivgerz-hue/vibe-shield
  version: 1.0.0
---

# vibe-shield

You are not allowed to say "done" until the code you just wrote passes a security audit.

AI coding agents ship a specific, repeatable class of vulnerability: a \`SUPABASE_SERVICE_ROLE_KEY\` behind a \`NEXT_PUBLIC_\` prefix, a \`DELETE\` route handler with no session check, a \`CREATE TABLE\` with no \`ENABLE ROW LEVEL SECURITY\`, a tool whose \`execute\` forwards model output into \`exec\`. These are not exotic — they are the default shape of code written quickly by something optimising for "it works". This skill is the second pair of eyes.

## When to run

Run the audit **after every change that touches**:

- an API route, route handler, server action, RPC endpoint or GraphQL mutation
- authentication, session, role, permission or ownership logic
- a database migration, policy, grant, schema or Supabase table
- an environment variable, config file, \`.env*\` file or build config
- anything calling an LLM, a tool, a webhook, a shell command or the filesystem
- \`.claude/\`, \`.cursor/\`, \`AGENTS.md\`, \`mcp.json\` or any skill/config file

If you did not touch any of those, you do not need to run it.

## The loop

\`\`\`bash
# 1. Scan (a whole-repo scan finishes in well under a second)
npx github:avivgerz-hue/vibe-shield scan --fail-on high

# 2. If it fails, generate the machine-readable fix list
npx github:avivgerz-hue/vibe-shield scan --fix-prompt

# 3. Read SECURITY_PATCH_PROMPT.md and fix every finding, critical first
#    Each entry has the exact file:line, the vulnerable snippet, the CWE and
#    the required change. Apply it literally.

# 4. Re-run until it exits 0
npx github:avivgerz-hue/vibe-shield scan --fail-on high
\`\`\`

\`--fail-on high\` exits non-zero while any high or critical finding exists. That is the gate.

## Reading a finding

\`\`\`
CRITICAL 47:15    VSB-CLIENT-001  Server-only secret exposed through a public environment prefix
         const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
\`\`\`

| Part | Meaning |
| --- | --- |
| \`47:15\` | exact line and column to edit |
| \`VSB-CLIENT-001\` | rule id — use it with \`explain\` for full docs |
| message | why this specific line is exploitable |
| \`(CWE-200)\` | bug class, for a deeper search if the fix is unclear |

Need the full picture? \`npx github:avivgerz-hue/vibe-shield explain VSB-CLIENT-001\` prints the vulnerable shape, the fixed shape, remediation steps and references.

## Hard rules

1. **Fix the root cause.** Never delete an auth check, disable RLS, silence a log or add a catch-all \`catch {}\` to make the finding disappear.
2. **Never suppress.** Do not add \`// vibe-shield-disable\`, do not edit \`.vibe-shieldignore\`, do not pass \`--ignore\`. Suppression is a decision for the human.
3. **Rotate exposed credentials.** If the scan reported a live key, tell the user to rotate it at the provider in the same message. Removing the line does not un-leak it — the value may already be in a bundle, a cache or a git history.
4. **Report honestly.** If you cannot fix a finding (you need a decision, a credential or a provider change), say so explicitly, name the rule id, and stop.
5. **Re-verify.** A fix is not finished until the gate exits 0.

## Agent surface audit

When you add or modify a skill, rule file, MCP server or instruction file, also run:

\`\`\`bash
npx github:avivgerz-hue/vibe-shield audit-skills
\`\`\`

Twelve \`VSB-AGENT-*\` rules check for hidden Unicode (zero-width and bidi characters used to smuggle instructions past review), \`curl\`/\`wget\` exfiltration of environment variables, credential-harvesting instructions (\`.env\`, \`~/.ssh\`, \`~/.aws\`), unpinned or remote MCP servers, literal tokens in an \`env\` block, safety-override language, over-broad tool permissions, base64 \`eval\` payloads, remote-instruction fetching, wildcard \`allowed-tools\`, and shell injection in skill scripts.

Each finding carries a \`triage\` field: \`block\` means refuse and escalate, \`review\` means ask the user, \`report\` means mention it and continue. Do not blanket-refuse a repository because a rule fired — read the triage.

## Flags worth knowing

| Flag | Effect |
| --- | --- |
| \`--format json\` | full machine-readable report (schemaVersion 1) |
| \`--format sarif\` | SARIF 2.1.0 for GitHub code scanning |
| \`--format compact\` | one line per finding |
| \`--format github\` | inline GitHub Actions annotations |
| \`--severity high\` | only report high and critical |
| \`--fail-on medium\` | stricter gate |
| \`--include-tests\` | include test and fixture files |
| \`--cache\` | reuse results between runs |
| \`--quiet\` | one-line verdict (ideal for piping) |
| \`rules\` | list every rule |
| \`explain <RULE_ID>\` | full documentation for one rule |

If the repository has a \`.mcp.json\`, the same three capabilities are also
available as MCP tools — \`vibe_shield_scan\`, \`vibe_shield_audit_skills\` and
\`vibe_shield_explain_rule\`. Prefer those when they are listed, because they
return structured findings instead of text you have to parse.

## Definition of done

- [ ] \`npx github:avivgerz-hue/vibe-shield scan --fail-on high\` exits \`0\`
- [ ] \`npx github:avivgerz-hue/vibe-shield audit-skills\` exits \`0\` if you touched agent files
- [ ] every credential the scan surfaced has been flagged to the user for rotation
- [ ] no suppression directive was added
- [ ] the feature still works and the existing tests still pass

## Install it into a repository

\`\`\`bash
npx github:avivgerz-hue/vibe-shield init
\`\`\`

That writes this file to \`.claude/skills/vibe-shield/SKILL.md\`, appends a security
gate section to \`AGENTS.md\`, adds a \`.cursor/rules/vibe-shield.mdc\`, and installs a
GitHub Actions workflow that fails the pull request on new high or critical
findings. Every future task in that repository starts guarded.
`;

/* -------------------------------------------------------------------------- */
/* AGENTS.md section                                                          */
/* -------------------------------------------------------------------------- */

export const AGENTS_SECTION = `## Security gate (vibe-shield)

This repository is guarded by [vibe-shield](https://github.com/avivgerz-hue/vibe-shield).

Before you report any task as complete:

1. Run \`npx github:avivgerz-hue/vibe-shield scan --fail-on high\` and fix every finding it reports.
2. Never suppress a finding (\`vibe-shield-disable\`, \`.vibe-shieldignore\` edits,
   \`--ignore\`) to make the gate pass — that is the human's call.
3. If you touched \`.claude/\`, \`.cursor/\`, \`AGENTS.md\`, \`mcp.json\` or a skill,
   also run \`npx github:avivgerz-hue/vibe-shield audit-skills\`.
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
export const MCP_SERVER_KEY = 'vibe-shield';

/**
 * The server entry written into `.mcp.json`.
 *
 * `npx` is used rather than a local path so the config keeps working when the
 * project is cloned elsewhere or the package is upgraded.
 */
export const MCP_SERVER_ENTRY = {
  command: 'npx',
  args: ['--yes', 'github:avivgerz-hue/vibe-shield', 'mcp'],
} as const;

/**
 * Merge the vibe-shield server into an existing `.mcp.json` without disturbing
 * anything already there.
 *
 * Returns the serialised file and whether our key was newly added. Existing
 * servers, other top-level keys and the user's formatting choices are preserved;
 * a malformed file is reported rather than overwritten, because silently
 * rewriting someone's MCP config could break every server they run.
 */
export function mergeMcpConfig(
  existing: string | null,
  options: { force?: boolean } = {},
): { contents: string; changed: boolean; error?: string } {
  if (existing === null || existing.trim() === '') {
    return {
      contents: `${JSON.stringify({ mcpServers: { [MCP_SERVER_KEY]: MCP_SERVER_ENTRY } }, null, 2)}\n`,
      changed: true,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(existing);
  } catch (error) {
    return {
      contents: existing,
      changed: false,
      error: `.mcp.json is not valid JSON (${error instanceof Error ? error.message : String(error)}); left untouched.`,
    };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { contents: existing, changed: false, error: '.mcp.json is not a JSON object; left untouched.' };
  }

  const config = parsed as Record<string, unknown>;
  const servers = config.mcpServers;

  if (servers !== undefined && (typeof servers !== 'object' || servers === null || Array.isArray(servers))) {
    return { contents: existing, changed: false, error: '.mcp.json has a non-object "mcpServers"; left untouched.' };
  }

  const table = (servers ?? {}) as Record<string, unknown>;
  const present = Object.prototype.hasOwnProperty.call(table, MCP_SERVER_KEY);
  if (present && !options.force) {
    return { contents: existing, changed: false };
  }

  const next = { ...config, mcpServers: { ...table, [MCP_SERVER_KEY]: MCP_SERVER_ENTRY } };
  return { contents: `${JSON.stringify(next, null, 2)}\n`, changed: true };
}

/* -------------------------------------------------------------------------- */
/* GitHub Actions workflow                                                    */
/* -------------------------------------------------------------------------- */

export const WORKFLOW_TEMPLATE = `name: vibe-shield

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
        run: npx --yes github:avivgerz-hue/vibe-shield scan --format sarif --out vibe-shield.sarif --fail-on high
        continue-on-error: true

      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vibe-shield.sarif
          category: vibe-shield

      - name: Audit agent surface
        run: npx --yes github:avivgerz-hue/vibe-shield audit-skills --fail-on high

      - name: Enforce the gate
        run: npx --yes github:avivgerz-hue/vibe-shield scan --fail-on high --quiet
`;

/* -------------------------------------------------------------------------- */
/* .vibe-shieldignore                                                         */
/* -------------------------------------------------------------------------- */

export const IGNORE_TEMPLATE = `# .vibe-shieldignore — gitignore syntax.
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

Before reporting a task complete, run \`npx github:avivgerz-hue/vibe-shield scan --fail-on high\` and
fix every finding. Never suppress a finding to make the gate pass. If the scan
reports an exposed credential, tell the user to rotate it at the provider.
`;

/** Build the full set of files for a given target repository. */
export function buildScaffold(options: InitOptions): ScaffoldFile[] {
  const agents = options.agents ?? 'all';
  const files: ScaffoldFile[] = [];

  if (agents === 'claude' || agents === 'all') {
    files.push({
      relativePath: '.claude/skills/vibe-shield/SKILL.md',
      contents: SKILL_TEMPLATE,
      mode: 'write',
      description: 'Agent Skill — forces Claude Code to audit before finishing',
    });
  }
  if (agents === 'cursor' || agents === 'all') {
    files.push({
      relativePath: '.cursor/rules/vibe-shield.mdc',
      contents: CURSOR_RULE,
      mode: 'write',
      description: 'Cursor rule — same gate for Cursor/Windsurf',
    });
  }
  if (agents === 'generic' || agents === 'all') {
    files.push({
      relativePath: 'AGENTS.md',
      contents: AGENTS_SECTION,
      mode: 'append',
      marker: '## Security gate (vibe-shield)',
      description: 'AGENTS.md section — Codex, Cursor, Windsurf, Amp',
    });
  }
  if (options.workflow !== false) {
    files.push({
      relativePath: '.github/workflows/vibe-shield.yml',
      contents: WORKFLOW_TEMPLATE,
      mode: 'write',
      description: 'GitHub Actions — fails the PR on new high/critical findings',
    });
  }
  files.push({
    relativePath: '.mcp.json',
    contents: '', // produced by mergeMcpConfig so existing servers survive
    mode: 'merge',
    description: 'MCP server config — lets Claude Code/Desktop, Cursor and Codex call the scanner',
  });
  files.push({
    relativePath: '.vibe-shieldignore',
    contents: IGNORE_TEMPLATE,
    mode: 'write',
    description: 'Ignore file — documented escape hatch',
  });

  return files;
}

const exists = async (file: string): Promise<boolean> => {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
};

/** Write the scaffold into `options.rootDir`. Idempotent unless `force`. */
export async function installScaffold(options: InitOptions): Promise<InitResult> {
  const rootDir = path.resolve(options.rootDir);
  const result: InitResult = { written: [], appended: [], skipped: [], blocked: [], warnings: [] };
  const files = buildScaffold(options);

  for (const file of files) {
    const absolute = path.join(rootDir, file.relativePath);
    const present = await exists(absolute);

    if (file.mode === 'append') {
      let current = '';
      if (present) {
        try {
          current = await fs.readFile(absolute, 'utf8');
        } catch {
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
      await fs.mkdir(path.dirname(absolute), { recursive: true });
      const separator = current.trim().length ? (current.endsWith('\n') ? '\n' : '\n\n') : '';
      await fs.appendFile(absolute, `${separator}${file.contents}`, 'utf8');
      result.appended.push(file.relativePath);
      continue;
    }

    if (file.mode === 'merge') {
      let existing: string | null = null;
      if (present) {
        try {
          existing = await fs.readFile(absolute, 'utf8');
        } catch {
          existing = null;
        }
      }
      const merged = mergeMcpConfig(existing, { force: options.force });
      if (merged.error) {
        // Not a `skipped` entry: `--force` cannot repair invalid JSON, so the
        // summary must not suggest it can.
        result.warnings.push(merged.error);
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
      await fs.mkdir(path.dirname(absolute), { recursive: true });
      await fs.writeFile(absolute, merged.contents, 'utf8');
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
    await fs.mkdir(path.dirname(absolute), { recursive: true });
    await fs.writeFile(absolute, file.contents, 'utf8');
    result.written.push(file.relativePath);
  }

  // A repository without a package.json will not be able to `npx github:avivgerz-hue/vibe-shield`
  // as a dev dependency; it still works through npx, so this is only a warning.
  if (!(await exists(path.join(rootDir, 'package.json')))) {
    result.warnings.push('No package.json found — run the gate with `npx github:avivgerz-hue/vibe-shield scan`.');
  }
  if (!(await exists(path.join(rootDir, '.git')))) {
    result.warnings.push('No .git directory found — the workflow only runs once this is a git repository.');
  }

  return result;
}

/** Locate the shipped `SKILL.md` (used by `init` to copy the canonical file). */
export async function locateBundledSkill(startDir: string): Promise<string | null> {
  let dir = startDir;
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = path.join(dir, 'SKILL.md');
    const packageJson = path.join(dir, 'package.json');
    if ((await exists(candidate)) && (await exists(packageJson))) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
