/**
 * vibe-shield :: `npx vibe-shield init`
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
export declare const SKILL_TEMPLATE = "---\nname: vibe-shield\ndescription: Audit any change for AI-introduced security bugs (leaked keys, unguarded API routes, disabled Row Level Security, SQL injection, prompt injection, poisoned MCP servers) and fix them before reporting a task as done. Use whenever you write or modify application code, API routes, server actions, database migrations, auth logic, environment variables, LLM calls, webhook handlers, agent skills or MCP configuration.\nallowed-tools: Bash(npx vibe-shield scan*), Bash(npx vibe-shield audit-skills*), Bash(npx vibe-shield explain*), Read(./**), Grep, Glob\nlicense: MIT\nmetadata:\n  author: VibeFoundry\n  homepage: https://github.com/avivgerz-hue/vibe-shield\n  version: 1.0.0\n---\n\n# vibe-shield\n\nYou are not allowed to say \"done\" until the code you just wrote passes a security audit.\n\nAI coding agents ship a specific, repeatable class of vulnerability: a `SUPABASE_SERVICE_ROLE_KEY` behind a `NEXT_PUBLIC_` prefix, a `DELETE` route handler with no session check, a `CREATE TABLE` with no `ENABLE ROW LEVEL SECURITY`, a tool whose `execute` forwards model output into `exec`. These are not exotic \u2014 they are the default shape of code written quickly by something optimising for \"it works\". This skill is the second pair of eyes.\n\n## When to run\n\nRun the audit **after every change that touches**:\n\n- an API route, route handler, server action, RPC endpoint or GraphQL mutation\n- authentication, session, role, permission or ownership logic\n- a database migration, policy, grant, schema or Supabase table\n- an environment variable, config file, `.env*` file or build config\n- anything calling an LLM, a tool, a webhook, a shell command or the filesystem\n- `.claude/`, `.cursor/`, `AGENTS.md`, `mcp.json` or any skill/config file\n\nIf you did not touch any of those, you do not need to run it.\n\n## The loop\n\n```bash\n# 1. Scan (a whole-repo scan finishes in well under a second)\nnpx vibe-shield scan --fail-on high\n\n# 2. If it fails, generate the machine-readable fix list\nnpx vibe-shield scan --fix-prompt\n\n# 3. Read SECURITY_PATCH_PROMPT.md and fix every finding, critical first\n#    Each entry has the exact file:line, the vulnerable snippet, the CWE and\n#    the required change. Apply it literally.\n\n# 4. Re-run until it exits 0\nnpx vibe-shield scan --fail-on high\n```\n\n`--fail-on high` exits non-zero while any high or critical finding exists. That is the gate.\n\n## Reading a finding\n\n```\nCRITICAL 47:15    VSB-CLIENT-001  Server-only secret exposed through a public environment prefix\n         const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n```\n\n| Part | Meaning |\n| --- | --- |\n| `47:15` | exact line and column to edit |\n| `VSB-CLIENT-001` | rule id \u2014 use it with `explain` for full docs |\n| message | why this specific line is exploitable |\n| `(CWE-200)` | bug class, for a deeper search if the fix is unclear |\n\nNeed the full picture? `npx vibe-shield explain VSB-CLIENT-001` prints the vulnerable shape, the fixed shape, remediation steps and references.\n\n## Hard rules\n\n1. **Fix the root cause.** Never delete an auth check, disable RLS, silence a log or add a catch-all `catch {}` to make the finding disappear.\n2. **Never suppress.** Do not add `// vibe-shield-disable`, do not edit `.vibe-shieldignore`, do not pass `--ignore`. Suppression is a decision for the human.\n3. **Rotate exposed credentials.** If the scan reported a live key, tell the user to rotate it at the provider in the same message. Removing the line does not un-leak it \u2014 the value may already be in a bundle, a cache or a git history.\n4. **Report honestly.** If you cannot fix a finding (you need a decision, a credential or a provider change), say so explicitly, name the rule id, and stop.\n5. **Re-verify.** A fix is not finished until the gate exits 0.\n\n## Agent surface audit\n\nWhen you add or modify a skill, rule file, MCP server or instruction file, also run:\n\n```bash\nnpx vibe-shield audit-skills\n```\n\nTwelve `VSB-AGENT-*` rules check for hidden Unicode (zero-width and bidi characters used to smuggle instructions past review), `curl`/`wget` exfiltration of environment variables, credential-harvesting instructions (`.env`, `~/.ssh`, `~/.aws`), unpinned or remote MCP servers, literal tokens in an `env` block, safety-override language, over-broad tool permissions, base64 `eval` payloads, remote-instruction fetching, wildcard `allowed-tools`, and shell injection in skill scripts.\n\nEach finding carries a `triage` field: `block` means refuse and escalate, `review` means ask the user, `report` means mention it and continue. Do not blanket-refuse a repository because a rule fired \u2014 read the triage.\n\n## Flags worth knowing\n\n| Flag | Effect |\n| --- | --- |\n| `--format json` | full machine-readable report (schemaVersion 1) |\n| `--format sarif` | SARIF 2.1.0 for GitHub code scanning |\n| `--format compact` | one line per finding |\n| `--format github` | inline GitHub Actions annotations |\n| `--severity high` | only report high and critical |\n| `--fail-on medium` | stricter gate |\n| `--include-tests` | include test and fixture files |\n| `--cache` | reuse results between runs |\n| `--quiet` | one-line verdict (ideal for piping) |\n| `rules` | list every rule |\n| `explain <RULE_ID>` | full documentation for one rule |\n\nIf the repository has a `.mcp.json`, the same three capabilities are also\navailable as MCP tools \u2014 `vibe_shield_scan`, `vibe_shield_audit_skills` and\n`vibe_shield_explain_rule`. Prefer those when they are listed, because they\nreturn structured findings instead of text you have to parse.\n\n## Definition of done\n\n- [ ] `npx vibe-shield scan --fail-on high` exits `0`\n- [ ] `npx vibe-shield audit-skills` exits `0` if you touched agent files\n- [ ] every credential the scan surfaced has been flagged to the user for rotation\n- [ ] no suppression directive was added\n- [ ] the feature still works and the existing tests still pass\n\n## Install it into a repository\n\n```bash\nnpx vibe-shield init\n```\n\nThat writes this file to `.claude/skills/vibe-shield/SKILL.md`, appends a security\ngate section to `AGENTS.md`, adds a `.cursor/rules/vibe-shield.mdc`, and installs a\nGitHub Actions workflow that fails the pull request on new high or critical\nfindings. Every future task in that repository starts guarded.\n";
export declare const AGENTS_SECTION = "## Security gate (vibe-shield)\n\nThis repository is guarded by [vibe-shield](https://github.com/avivgerz-hue/vibe-shield).\n\nBefore you report any task as complete:\n\n1. Run `npx vibe-shield scan --fail-on high` and fix every finding it reports.\n2. Never suppress a finding (`vibe-shield-disable`, `.vibe-shieldignore` edits,\n   `--ignore`) to make the gate pass \u2014 that is the human's call.\n3. If you touched `.claude/`, `.cursor/`, `AGENTS.md`, `mcp.json` or a skill,\n   also run `npx vibe-shield audit-skills`.\n4. Surface any exposed credential to the user for rotation. Do not \"fix\" it by\n   deleting the line and moving on.\n\nThe gate exists because the most common way AI-written code reaches production\nwith a leaked `SUPABASE_SERVICE_ROLE_KEY` or an unauthenticated `DELETE`\nendpoint is that nobody asked it a second question.\n";
/** Key this tool owns inside `mcpServers`; nothing else is ever touched. */
export declare const MCP_SERVER_KEY = "vibe-shield";
/**
 * The server entry written into `.mcp.json`.
 *
 * `npx` is used rather than a local path so the config keeps working when the
 * project is cloned elsewhere or the package is upgraded.
 */
export declare const MCP_SERVER_ENTRY: {
    readonly command: "npx";
    readonly args: readonly ["--yes", "vibe-shield@latest", "mcp"];
};
/**
 * Merge the vibe-shield server into an existing `.mcp.json` without disturbing
 * anything already there.
 *
 * Returns the serialised file and whether our key was newly added. Existing
 * servers, other top-level keys and the user's formatting choices are preserved;
 * a malformed file is reported rather than overwritten, because silently
 * rewriting someone's MCP config could break every server they run.
 */
export declare function mergeMcpConfig(existing: string | null, options?: {
    force?: boolean;
}): {
    contents: string;
    changed: boolean;
    error?: string;
};
export declare const WORKFLOW_TEMPLATE = "name: vibe-shield\n\non:\n  push:\n    branches: [main, master]\n  pull_request:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n  security-events: write\n  pull-requests: write\n\njobs:\n  scan:\n    name: Security audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n\n      - name: Scan for vulnerabilities\n        run: npx --yes vibe-shield@latest scan --format sarif --out vibe-shield.sarif --fail-on high\n        continue-on-error: true\n\n      - name: Upload SARIF to code scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: vibe-shield.sarif\n          category: vibe-shield\n\n      - name: Audit agent surface\n        run: npx --yes vibe-shield@latest audit-skills --fail-on high\n\n      - name: Enforce the gate\n        run: npx --yes vibe-shield@latest scan --fail-on high --quiet\n";
export declare const IGNORE_TEMPLATE = "# .vibe-shieldignore \u2014 gitignore syntax.\n#\n# Keep this file as short as possible: every line hides real code from the\n# security gate. Prefer an inline suppression with a reason where it applies:\n#\n#   // vibe-shield-disable-next-line VSB-AI-001 -- path comes from a fixed enum\n#\n# Generated code, vendored third-party sources and build output are the only\n# good reasons to ignore a path wholesale.\n\n# Generated / vendored\n# vendor/**\n# **/*.generated.ts\n# **/__generated__/**\n\n# Local-only scratch work\n# scratch/**\n";
/** Build the full set of files for a given target repository. */
export declare function buildScaffold(options: InitOptions): ScaffoldFile[];
/** Write the scaffold into `options.rootDir`. Idempotent unless `force`. */
export declare function installScaffold(options: InitOptions): Promise<InitResult>;
/** Locate the shipped `SKILL.md` (used by `init` to copy the canonical file). */
export declare function locateBundledSkill(startDir: string): Promise<string | null>;
