---
name: vibe-shield
description: Audit any change for AI-introduced security bugs (leaked keys, unguarded API routes, disabled Row Level Security, SQL injection, prompt injection, poisoned MCP servers) and fix them before reporting a task as done. Use whenever you write or modify application code, API routes, server actions, database migrations, auth logic, environment variables, LLM calls, webhook handlers, agent skills or MCP configuration.
allowed-tools: Bash(npx vibe-shield scan*), Bash(npx vibe-shield audit-skills*), Bash(npx vibe-shield explain*), Read(./**), Grep, Glob
license: MIT
metadata:
  author: VibeFoundry
  homepage: https://github.com/avivgerz-hue/vibe-shield
  version: 1.0.0
---

# vibe-shield

You are not allowed to say "done" until the code you just wrote passes a security audit.

AI coding agents ship a specific, repeatable class of vulnerability: a `SUPABASE_SERVICE_ROLE_KEY` behind a `NEXT_PUBLIC_` prefix, a `DELETE` route handler with no session check, a `CREATE TABLE` with no `ENABLE ROW LEVEL SECURITY`, a tool whose `execute` forwards model output into `exec`. These are not exotic — they are the default shape of code written quickly by something optimising for "it works". This skill is the second pair of eyes.

## When to run

Run the audit **after every change that touches**:

- an API route, route handler, server action, RPC endpoint or GraphQL mutation
- authentication, session, role, permission or ownership logic
- a database migration, policy, grant, schema or Supabase table
- an environment variable, config file, `.env*` file or build config
- anything calling an LLM, a tool, a webhook, a shell command or the filesystem
- `.claude/`, `.cursor/`, `AGENTS.md`, `mcp.json` or any skill/config file

If you did not touch any of those, you do not need to run it.

## The loop

```bash
# 1. Scan (a whole-repo scan finishes in well under a second)
npx vibe-shield scan --fail-on high

# 2. If it fails, generate the machine-readable fix list
npx vibe-shield scan --fix-prompt

# 3. Read SECURITY_PATCH_PROMPT.md and fix every finding, critical first
#    Each entry has the exact file:line, the vulnerable snippet, the CWE and
#    the required change. Apply it literally.

# 4. Re-run until it exits 0
npx vibe-shield scan --fail-on high
```

`--fail-on high` exits non-zero while any high or critical finding exists. That is the gate.

## Reading a finding

```
CRITICAL 47:15    VSB-CLIENT-001  Server-only secret exposed through a public environment prefix
         const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;
```

| Part | Meaning |
| --- | --- |
| `47:15` | exact line and column to edit |
| `VSB-CLIENT-001` | rule id — use it with `explain` for full docs |
| message | why this specific line is exploitable |
| `(CWE-200)` | bug class, for a deeper search if the fix is unclear |

Need the full picture? `npx vibe-shield explain VSB-CLIENT-001` prints the vulnerable shape, the fixed shape, remediation steps and references.

## Hard rules

1. **Fix the root cause.** Never delete an auth check, disable RLS, silence a log or add a catch-all `catch {}` to make the finding disappear.
2. **Never suppress.** Do not add `// vibe-shield-disable`, do not edit `.vibe-shieldignore`, do not pass `--ignore`. Suppression is a decision for the human.
3. **Rotate exposed credentials.** If the scan reported a live key, tell the user to rotate it at the provider in the same message. Removing the line does not un-leak it — the value may already be in a bundle, a cache or a git history.
4. **Report honestly.** If you cannot fix a finding (you need a decision, a credential or a provider change), say so explicitly, name the rule id, and stop.
5. **Re-verify.** A fix is not finished until the gate exits 0.

## Agent surface audit

When you add or modify a skill, rule file, MCP server or instruction file, also run:

```bash
npx vibe-shield audit-skills
```

Twelve `VSB-AGENT-*` rules check for hidden Unicode (zero-width and bidi characters used to smuggle instructions past review), `curl`/`wget` exfiltration of environment variables, credential-harvesting instructions (`.env`, `~/.ssh`, `~/.aws`), unpinned or remote MCP servers, literal tokens in an `env` block, safety-override language, over-broad tool permissions, base64 `eval` payloads, remote-instruction fetching, wildcard `allowed-tools`, and shell injection in skill scripts.

Each finding carries a `triage` field: `block` means refuse and escalate, `review` means ask the user, `report` means mention it and continue. Do not blanket-refuse a repository because a rule fired — read the triage.

## Flags worth knowing

| Flag | Effect |
| --- | --- |
| `--format json` | full machine-readable report (schemaVersion 1) |
| `--format sarif` | SARIF 2.1.0 for GitHub code scanning |
| `--format compact` | one line per finding |
| `--format github` | inline GitHub Actions annotations |
| `--severity high` | only report high and critical |
| `--fail-on medium` | stricter gate |
| `--include-tests` | include test and fixture files |
| `--cache` | reuse results between runs |
| `--quiet` | one-line verdict (ideal for piping) |
| `rules` | list every rule |
| `explain <RULE_ID>` | full documentation for one rule |

## Definition of done

- [ ] `npx vibe-shield scan --fail-on high` exits `0`
- [ ] `npx vibe-shield audit-skills` exits `0` if you touched agent files
- [ ] every credential the scan surfaced has been flagged to the user for rotation
- [ ] no suppression directive was added
- [ ] the feature still works and the existing tests still pass

## Install it into a repository

```bash
npx vibe-shield init
```

That writes this file to `.claude/skills/vibe-shield/SKILL.md`, appends a security
gate section to `AGENTS.md`, adds a `.cursor/rules/vibe-shield.mdc`, and installs a
GitHub Actions workflow that fails the pull request on new high or critical
findings. Every future task in that repository starts guarded.
