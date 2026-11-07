<div align="center">

# 🛡️ vibe-shield

**The security gate for AI-written code.**

Your agent ships fast. It also ships `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, a `DELETE` route with no session check, and a `CREATE TABLE` with no Row Level Security — because it was optimising for "it works".

vibe-shield is a **static security scanner built for that failure mode**, plus an **Agent Skill** that makes Claude Code, Codex, Cursor and Windsurf audit before they say *"done"*.

[![npm version](https://img.shields.io/npm/v/vibe-shield?style=flat-square&logo=npm&color=cb3837)](https://www.npmjs.com/package/vibe-shield)
[![npm downloads](https://img.shields.io/npm/dm/vibe-shield?style=flat-square&logo=npm&color=cb3837)](https://www.npmjs.com/package/vibe-shield)
[![CI](https://img.shields.io/github/actions/workflow/status/avivgerz-hue/vibe-shield/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI)](https://github.com/avivgerz-hue/vibe-shield/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/vibe-shield?style=flat-square&logo=nodedotjs&color=5fa04e)](https://www.npmjs.com/package/vibe-shield)
[![license](https://img.shields.io/npm/l/vibe-shield?style=flat-square&color=blue)](./LICENSE)
[![zero dependencies](https://img.shields.io/badge/runtime%20deps-0-brightgreen?style=flat-square)](./package.json)
[![rules](https://img.shields.io/badge/detection%20signatures-60-8b5cf6?style=flat-square)](./src/scanner/rules)
[![self-scan](https://img.shields.io/badge/self--scan-100%2F100%20A%2B-16a34a?style=flat-square)](#-it-scans-itself)

```bash
npx vibe-shield scan
```

</div>

---

## The problem, in one file

This is the shape of code an agent writes when you ask for "a delete endpoint":

```ts
// app/api/users/route.ts
export async function DELETE(req: Request) {
  const { id, userId } = await req.json();
  await db.query(`DELETE FROM users WHERE id = ${id} AND owner = ${userId}`);
  return new Response('ok');
}
```

It works. It also has **three critical vulnerabilities** — no authentication, SQL injection, and an IDOR that lets the caller choose whose data they delete. Nothing in a normal review loop catches all three, and the agent reported the task as complete.

`npx vibe-shield scan` catches all three in **17 milliseconds**:

```
🛡️  vibe-shield v1.0.0 · security scan
target  /home/you/app

💀 GRADE F — 0/100 · 3 critical

  CRITICAL 3    ███

Findings

app/api/users/route.ts
  CRITICAL 2:1      VSB-AUTH-001  Next.js App Router mutation handler has no authentication check
           export async function DELETE(req: Request) {
  CRITICAL 4:22     VSB-DB-007    SQL statement built by concatenating request data
           await db.query(`DELETE FROM users WHERE id = ${id} AND owner = ${userId}`);
  CRITICAL 4:22     VSB-AUTH-004  Record ownership taken from the request instead of the session (IDOR)

  7 files  ·  1 KiB  ·  412 files/s  ·  17 ms  ·  48 rules

  ⚠  3 critical findings — rotate any exposed credential before anything else.
  Fix it      npx vibe-shield scan --fix-prompt    # writes SECURITY_PATCH_PROMPT.md for your agent
  Explain     npx vibe-shield explain VSB-AUTH-001
  Gate CI     npx vibe-shield scan --fail-on critical --format github
```

Then hand the fix list to the agent that wrote the bug:

```bash
npx vibe-shield scan --fix-prompt   # → SECURITY_PATCH_PROMPT.md
```

That file contains, for every finding: the severity, the CWE id and link, the exact `file:line`, the vulnerable snippet, the ordered remediation steps, the target code shape, and a verification command. It is written for a machine to execute and a human to audit.

---

## ⚡ Quick start

```bash
# 1. Scan (no install, no config, no network calls)
npx vibe-shield scan

# 2. Give your agent the fix list
npx vibe-shield scan --fix-prompt

# 3. Install the gate permanently — skill + CI + ignore file
npx vibe-shield init
```

`npx vibe-shield init` writes:

| File | What it does |
| --- | --- |
| `.claude/skills/vibe-shield/SKILL.md` | Agent Skill: forces Claude Code (and any SKILL.md-aware agent) to audit before finishing |
| `AGENTS.md` *(section)* | Same contract for Codex, Cursor, Windsurf, Amp, and anything that reads a repo instruction file |
| `.cursor/rules/vibe-shield.mdc` | `alwaysApply` Cursor rule |
| `.github/workflows/vibe-shield.yml` | Fails the pull request on new high/critical findings, uploads SARIF to code scanning |
| `.vibe-shieldignore` | The documented escape hatch (empty by default, with guidance) |

Nothing is overwritten without `--force`, and re-running is a no-op.

---

## 🧠 Why AI code needs its own scanner

Traditional SAST rules are built around human mistakes: a forgotten escape, a missing `prepare()`. Agent-written code fails differently — it is *confidently complete* and *structurally plausible*:

| What a human does | What an agent does |
| --- | --- |
| forgets to validate one input | writes a perfect endpoint with **no auth at all** |
| uses `eval` in one legacy file | puts a **tool `execute` that shells out** behind an LLM |
| commits a `.env` by accident | puts `SUPABASE_SERVICE_ROLE_KEY` behind `NEXT_PUBLIC_` because "it needed the env var" |
| writes `CREATE TABLE` | writes `CREATE TABLE` **and forgets the `ENABLE ROW LEVEL SECURITY`**, so the anon key reads everything |
| adds `dangerouslySetInnerHTML` to render a doc | renders **model output** with it, creating stored XSS with a step counter |

vibe-shield encodes those specific shapes: 60 signatures across five families, each one derived from a real agent-generated bug rather than a generic CWE checklist.

---

## 📊 Vulnerability Coverage Matrix

**48 code signatures + 12 agent-integrity signatures = 60.** Every rule has an id, a CWE, a vulnerable example, a fixed example, and ordered remediation steps — run `npx vibe-shield rules` or `npx vibe-shield explain <ID>`.

### Client-side secret & data exposure — `VSB-CLIENT-*`

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-CLIENT-001` | `NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` / `REACT_APP_` + a server-only secret name (`SERVICE_ROLE_KEY`, `OPENAI_API_KEY`, `STRIPE_SECRET_KEY`, `DATABASE_URL`…) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | critical |
| `VSB-CLIENT-002` | server-only `process.env.*SECRET*` read inside a `"use client"` module | CWE-200 | high |
| `VSB-CLIENT-003` | `createClient(url, SERVICE_ROLE_KEY)` — RLS bypass from a client-reachable file | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | critical |
| `VSB-CLIENT-004` | `supabaseAdmin` / `adminClient` / `serviceRoleClient` referenced from browser code | CWE-250 | critical |
| `VSB-CLIENT-005` | `dangerouslyAllowBrowser: true`, provider SDK keyed in the browser | [CWE-749](https://cwe.mitre.org/data/definitions/749.html) | high |
| `VSB-CLIENT-006` | `.env*` assigns a live-looking credential to a public variable | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | critical |
| `VSB-CLIENT-007` | `next.config.js` `env` / `publicRuntimeConfig` / Vite `define` inlining a secret | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | critical |

### Unguarded mutation routes — `VSB-AUTH-*`

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-AUTH-001` | App Router `POST/PUT/PATCH/DELETE` handler with no session check | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | critical |
| `VSB-AUTH-002` | Pages API mutation handler with no session check | CWE-306 | critical |
| `VSB-AUTH-003` | Express / Fastify / Koa / Hono mutation route with no auth middleware | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | high |
| `VSB-AUTH-004` | IDOR — ownership key from `body`/`query`/`params` (including the destructured local variable) | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | critical |
| `VSB-AUTH-005` | `"use server"` action mutating data with no auth | CWE-306 | high |
| `VSB-AUTH-006` | identity from `jwt.decode`, `x-user-id`, `atob(token.split('.')[1])`, `verify:false`, `algorithms:['none']` | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | critical |
| `VSB-AUTH-007` | admin/destructive surface that authenticates but never checks a role | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | high |
| `VSB-AUTH-008` | `const session = await auth()` captured and never enforced | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | medium |
| `VSB-AUTH-009` | cookie-session mutation with no CSRF token protection | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | medium |

### Database exposure — `VSB-DB-*`

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-DB-001` | `CREATE TABLE` with no `ENABLE ROW LEVEL SECURITY` **anywhere in the project** (cross-file index) | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | critical\*/high |
| `VSB-DB-002` | permissive policy — `USING (true)`, `WITH CHECK (true)`, `USING (1=1)` | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | critical |
| `VSB-DB-003` | `anon`/`authenticated` policy whose `USING` never references `auth.uid()`/`auth.jwt()` | CWE-639 | high |
| `VSB-DB-004` | `GRANT … TO anon/public` (writes), incl. `GRANT ALL` | CWE-732 | critical/high |
| `VSB-DB-005` | `DISABLE ROW LEVEL SECURITY`, `DROP POLICY`, `BYPASSRLS` | CWE-284 | critical/high |
| `VSB-DB-006` | `$queryRawUnsafe`, `$executeRawUnsafe`, `knex.raw`, `sequelize.query`, `.raw()` with a dynamic string | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | critical |
| `VSB-DB-007` | hand-built SQL from request data — `${}`, `+`, Python f-strings, PHP interpolation | CWE-89 | critical |
| `VSB-DB-008` | Supabase service-role key outside a `server-only` boundary | CWE-250 | critical |
| `VSB-DB-009` | `createBucket(…, { public: true })` | CWE-732 | medium |
| `VSB-DB-010` | request data used as a table, column or `ORDER BY` identifier | CWE-89 | high |

\* critical when Supabase/PostgREST is detected — the anon key in every browser makes the table publicly addressable.

### AI / LLM & classic web — `VSB-AI-*`

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-AI-001` | `exec`/`execSync`/`spawn({shell:true})`/`Bun.spawn`/`os.system`/`subprocess(shell=True)`/`Runtime.exec`/PHP backticks | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | critical |
| `VSB-AI-002` | LLM/MCP tool `execute` reaching a shell, `eval` or filesystem sink | [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | critical |
| `VSB-AI-003` | model output into `eval`/`new Function`/`vm.runInNewContext` | CWE-94 | critical |
| `VSB-AI-004` | untrusted/RAG content interpolated into a `system` prompt, no delimiters (OWASP LLM01) | [CWE-74](https://cwe.mitre.org/data/definitions/74.html) | high |
| `VSB-AI-005` | Stripe webhook without `stripe.webhooks.constructEvent` | [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | critical |
| `VSB-AI-006` | webhook signing secret read from the request | CWE-345 | high |
| `VSB-AI-007` | GitHub/Slack/Shopify/Svix webhook with no signature verification | CWE-345 | high |
| `VSB-AI-008` | `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `innerHTML`, `document.write`, jQuery `.html()` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | high |
| `VSB-AI-009` | client `eval`/`new Function`/string `setTimeout`/`javascript:` URLs | CWE-94 | high |
| `VSB-AI-010` | open redirect — `redirect(searchParams.get('next'))` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | medium |
| `VSB-AI-011` | SSRF — `fetch(req.body.url)` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | high |
| `VSB-AI-012` | path traversal — `path.join(dir, req.params.name)` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | high |
| `VSB-AI-013` | multer/`formData()` upload with no size or type limit | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | medium |
| `VSB-AI-014` | public LLM endpoint with no rate limit or quota | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | medium |
| `VSB-AI-015` | `pickle.loads`, `yaml.load` without `SafeLoader`, PHP `unserialize` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | high |

### Hardcoded credentials — `VSB-SECRET-*`

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-SECRET-001` | vendor signature in a server file (Stripe, OpenAI, Anthropic, AWS, GitHub, Supabase, Slack, Twilio, SendGrid, npm, PyPI, HuggingFace, Docker, Vercel, Mailgun, Square, Shopify, Datadog) | CWE-798 | high |
| `VSB-SECRET-002` | generic high-entropy assignment to a credential-shaped name | CWE-798 | medium/high |
| `VSB-SECRET-003` | PEM private key material | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | critical |
| `VSB-SECRET-004` | hardcoded JWT whose payload carries `service_role` / `admin` | CWE-250 | critical |
| `VSB-SECRET-005` | the same vendor credential in a **browser-reachable** file | CWE-200 | critical |
| `VSB-SECRET-006` | `postgres:postgres@…`, `password = "admin"`, entropy < 2.5 | [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) | medium |
| `VSB-SECRET-007` | `.env` with live credentials — critical when git-tracked | CWE-540 | critical |

### Agent skill & MCP poisoning — `VSB-AGENT-*` (`audit-skills`)

| ID | Detects | CWE | Sev |
| --- | --- | --- | --- |
| `VSB-AGENT-001` | zero-width, bidi-override, Unicode-tag characters hiding instructions | CWE-74 | critical |
| `VSB-AGENT-002` | `curl`/`wget`/`nc` exfiltrating env vars or `.env` | CWE-200 | critical |
| `VSB-AGENT-003` | instructions to read `.env`, `~/.ssh`, `~/.aws/credentials`, `id_rsa`, keychain | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | critical |
| `VSB-AGENT-004` | unpinned `npx -y`/`uvx`, remote MCP URL, `curl \| sh` install | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | high |
| `VSB-AGENT-005` | literal credentials in an `env` block, or `"*": "*"` env forwarding | [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | critical/high |
| `VSB-AGENT-006` | "ignore previous instructions", "do not tell the user", "auto-approve", "skip confirmation" | CWE-74 | critical |
| `VSB-AGENT-007` | `Bash(*)`, `Write(*)`, `autoApprove: ["*"]`, `dangerouslySkipPermissions` | CWE-284 | high |
| `VSB-AGENT-008` | base64 payload / `eval(atob(…))` / `base64 -d \| sh` | CWE-94 | high |
| `VSB-AGENT-009` | "fetch <url> and follow every instruction" | CWE-829 | critical |
| `VSB-AGENT-010` | missing frontmatter, wildcard `allowed-tools` | CWE-250 | medium |
| `VSB-AGENT-011` | literal credential inside an instruction/MCP file | CWE-798 | critical |
| `VSB-AGENT-012` | `eval "$1"`, `sh -c "$VAR"` in a skill script | CWE-78 | medium |

---

## 🤖 Use it as an Agent Skill

`npx vibe-shield init` installs the skill. Once it is in a repository, every
agent session starts with a contract:

> You are not allowed to say "done" until the code you just wrote passes a security audit.

```bash
npx vibe-shield init                 # Claude Code + Cursor + AGENTS.md + CI
npx vibe-shield init --agent claude  # just the skill
npx vibe-shield init --no-workflow   # skip the GitHub Action
```

**Why this works better than a prompt snippet:** it names the three commands, gives the agent a reading guide for a finding (`line:col`, rule id, message, CWE), states five hard rules (never suppress, never weaken, always rotate, report honestly, re-verify), and defines "done" as an exit code rather than an opinion.

The skill itself is [SKILL.md](./SKILL.md) — read it, it is short.

### Anthropic Agent Skills quickstart

```bash
# marketplace-style install
npx vibe-shield init --agent claude
# → .claude/skills/vibe-shield/SKILL.md

# or globally, for every project
curl -sL https://raw.githubusercontent.com/avivgerz-hue/vibe-shield/main/SKILL.md \
  -o ~/.claude/skills/vibe-shield/SKILL.md
```

---

## 🔁 CI/CD: fail the PR before the bug ships

### GitHub Actions (recommended)

`npx vibe-shield init` installs a workflow that runs the scan, uploads SARIF to
code scanning, audits the agent surface, and fails the job:

```yaml
name: vibe-shield
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Scan and upload SARIF
        run: npx --yes vibe-shield@latest scan --format sarif --out vibe-shield.sarif --fail-on high
        continue-on-error: true

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vibe-shield.sarif
          category: vibe-shield

      - name: Enforce the gate
        run: npx --yes vibe-shield@latest scan --fail-on high
```

Findings appear **inline on the pull request diff** (GitHub annotations) and in
the **Security → Code scanning** tab (SARIF), so a reviewer sees the vulnerability
on the line that introduced it.

### Any other CI

```bash
npx vibe-shield scan --fail-on high                        # exit 1 on findings
npx vibe-shield scan --format compact                      # one line per finding
npx vibe-shield scan --format json > vibe-shield.json      # full report
npx vibe-shield scan --format summary                      # counts + grade
npx vibe-shield scan --format github                       # workflow annotations
```

Exit codes: **0** clean · **1** findings at/above `--fail-on` · **2** usage error.

---

## 🎯 The scorecard

Grades are **deliberately unforgiving**, because "B+" for a leaked production key is how security tools lose credibility:

| Finding present | Maximum score | Best possible grade |
| --- | --- | --- |
| any **critical** | 29 | **F** |
| any **high** | 58 | C |
| any **medium** | 76 | B |
| any **low** | 88 | A- |
| nothing | 100 | **A+** |

Penalties per finding: critical −30, high −12, medium −5, low −2, info −0.5. One leaked live key fails the build on its own; a handful of informational notes never will.

---

## 🪄 It scans itself

This repository runs its own gate on every commit and in CI:

```console
$ npx vibe-shield scan
🏆 GRADE A+ — 100/100

  19 files  ·  168 KiB  ·  198 files/s  ·  96 ms  ·  48 rules

  Nothing to fix. Keep the shield up. 🛡️

$ npx vibe-shield audit-skills
🏆 GRADE A+ — 100/100
```

The detector catalogue is the one place that must contain the exact vulnerable
shapes and vendor key formats the rules match on — exactly like gitleaks and
semgrep. Those files are listed explicitly in [`.vibe-shieldignore`](./.vibe-shieldignore)
with a comment explaining why, instead of weakening a rule.

---

## 🔇 Suppressing a finding (legitimately)

Inline, with a rule id and a reason — the reason is required by review culture even though the parser does not enforce it:

```ts
// vibe-shield-disable-next-line VSB-AI-001 -- path comes from a closed enum
exec(`convert ${KNOWN_FORMATS[format]} out.png`);
```

```ts
// vibe-shield-disable-line VSB-AUTH-008
// vibe-shield-disable VSB-AI-014
// vibe-shield-enable
// vibe-shield-disable-file VSB-DB-004 -- generated edge schema
```

Suppressed findings are **counted and reported** in the scorecard, never silently dropped. Whole-path exclusions belong in `.vibe-shieldignore` (gitignore syntax) and should be reserved for generated code.

---

## ⚙️ How it works

```
 discover ──▶ project context ──▶ rule gate ──▶ detect ──▶ suppress ──▶ score ──▶ report
   │              │                  │           │
   │              │                  │           └─ 60 rules, each a pure (FileContext) => RuleHit[]
   │              │                  └─ cheap content hints: most rules skip most files
   │              └─ manifests, framework flags, cross-file RLS index, git index, middleware matchers
   └─ one tree walk, gitignore/.vibe-shieldignore layering, binary + size + test/doc pruning
```

**Design constraints, in priority order:**

1. **Fast.** One `readdir` walk, one read per file, one comment-masking pass, and a cheap gate before any rule body runs. A 400-file project scans in ~200 ms; a typical Next.js app in under 100 ms. No AST, no parser, no dependency.
2. **Honest.** Every finding carries the exact snippet the developer wrote. Nothing is inferred from a filename alone, and every suppression is counted, not hidden.
3. **Composable.** `scanProject()` for the CLI, `runRulesOnFile()` for the auditor, `scoreFindings()` for anything that produces findings. The whole API is exported from `vibe-shield`.

**Zero runtime dependencies.** No network calls, no telemetry, no language server, no native binaries. `npx vibe-shield scan` works offline and in an air-gapped CI runner.

---

## 📖 CLI reference

```
vibe-shield scan [paths...]         Scan the project (default: `.`)
vibe-shield audit-skills [paths...] Audit agent skills, rules, AGENTS.md and MCP config
vibe-shield init                    Install the Agent Skill, AGENTS.md section and CI gate
vibe-shield rules                   List every detection rule
vibe-shield explain <RULE_ID>       Full documentation for one rule
vibe-shield version | help
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format <fmt>` | `console` | `console` `compact` `summary` `json` `sarif` `github` |
| `--fail-on <sev>` | `critical` | Exit 1 at/above this severity |
| `--severity <sev>` | — | Only report at/above this severity |
| `--fix-prompt` | off | Write `SECURITY_PATCH_PROMPT.md` |
| `--out <file>` | — | Write the report to a file |
| `--rules <ids>` | all | Comma-separated ids/slugs, supports `VSB-DB-*` |
| `--ignore <glob>` | — | Extra ignore pattern (repeatable) |
| `--include-tests` | off | Include test/fixture files |
| `--include-docs` | off | Include Markdown and `docs/` |
| `--cache` | off | Reuse `.vibe-shield-cache.json` |
| `--max-findings <n>` | 50 | Console list cap (`0` = all) |
| `--quiet` | off | One-line verdict |
| `--no-color` | auto | Disable ANSI (also honours `NO_COLOR`) |

---

## 🧩 Programmatic API

```ts
import { scanProject, formatSarif, buildPatchPrompt, auditSkills } from 'vibe-shield';

const result = await scanProject({ rootDir: process.cwd(), cache: true });

console.log(result.score.score, result.score.grade);  // 0 'F'
console.log(result.findings[0].ruleId);               // 'VSB-AUTH-001'
console.log(result.findings[0].cwe.id);               // 'CWE-306'

process.stdout.write(formatSarif(result));            // SARIF 2.1.0
process.stdout.write(buildPatchPrompt(result));       // agent-ready fix list

const agentReport = await auditSkills(process.cwd()); // VSB-AGENT-* surface
```

---

## ❓ FAQ

**Does it replace a real SAST tool?**
No. It replaces the *absence* of one. vibe-shield is a fast, zero-dependency gate you can put in front of every agent-written commit today. Pair it with a deeper scanner (CodeQL, Semgrep) if you have one; the rules overlap far less than you would expect, because these are agent-specific shapes.

**Will it flag my secure code?**
The secure fixture (`tests/fixtures/secure/`) is a real Next.js + Supabase + Stripe app with auth, RLS, sanitisation, rate limiting and webhook verification — it scores 100/100 and the suite asserts **zero findings** on it. Each rule has guard clauses for the legitimate patterns: `import "server-only"` suppresses the service-role rules, Prisma tagged templates suppress the SQLi rule, `DOMPurify` suppresses the XSS rule, `auth.uid()` policies suppress the RLS rules.

**Does it send my code anywhere?**
No. There is no network code in the runtime at all — the package has zero dependencies and makes no outbound requests.

**Why not an AST?**
Because a 1.5 MB minified bundle, a Vue SFC, a PHP legacy file and a SQL migration all need to be scanned with the same tool, and a parser handles exactly one of those. The rules use structural brace matching plus a comment-masker that preserves offsets, which is enough for the shapes that matter and roughly two orders of magnitude faster.

**Why "vibe"?**
Because the code was written by vibe and reviewed by nobody. This is the reviewer.

---

## 🛠 Development

```bash
git clone https://github.com/avivgerz-hue/vibe-shield
cd vibe-shield
npm ci
npm run typecheck   # tsc --noEmit (strict, noUnusedLocals)
npm test            # 163 Vitest tests
npm run build       # tsc + postbuild (shebang, chmod, CJS marker)
npm run verify      # typecheck + test + build + self-scan + self-audit
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the rule-authoring guide, and
[SECURITY.md](./SECURITY.md) for the threat model and disclosure policy.

---

## 📋 Requirements

- **Node.js ≥ 18.17** (uses `node:` builtins only — no polyfills, no native modules)
- Any OS: Linux, macOS, Windows
- No config file required; `package.json` is optional

---

## 📄 License

MIT © [VibeFoundry](./LICENSE) — use it, fork it, ship it.

---

## Part of the VibeFoundry Agent Suite

Three tools for the same problem: agents move fast, and something has to keep the output honest.

| | Tool | What it does |
| :---: | --- | --- |
| 🎨 | **[unslop](https://github.com/avivgerz-hue/unslop)** | Studio-grade UI design systems & Anti-Slop engine — stops agents from generating generic, interchangeable interfaces |
| 🛡️ | **[vibe-shield](https://github.com/avivgerz-hue/vibe-shield)** | Security scanner & MCP guard — stops agents from shipping leaked keys, unguarded routes and disabled RLS |
| 👻 | **[ghost-qa](https://github.com/avivgerz-hue/ghost-qa)** | Autonomous headless-browser QA & self-healing verification loop — stops agents from claiming a UI works when it does not |

```bash
npx vibe-shield init   # security gate
```
