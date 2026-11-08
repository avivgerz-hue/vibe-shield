# Awesome-list submissions — paste-ready

**Status:** the sandbox GitHub token is read-only for public repos (`POST /forks` → `403 Resource not accessible by integration`, empty `X-Oauth-Scopes`), so I cannot open these PRs for you. Everything below is pre-written and line-verified against the READMEs as fetched today.

Click **Edit** on the link, paste the line at the line number shown, commit — GitHub forks and opens the PR form for you in one flow ("Create a new branch for this commit and start a pull request").

> Line numbers drift as lists grow. If a line is off by one or two, match on the **neighbour entry named in bold** rather than the number — alphabetical position is what actually matters.

---

## 1. `mxschmitt/awesome-playwright` — 1,604★, active, `main`

**Where:** under `## AI & Agents` (line 93). The section's existing entries are Cutaway, Playwright Agent CLI, Playwright MCP, Webcmd (lines 95–98), then a blank line and `## Reporters` at line 100.

**Edit link:** <https://github.com/mxschmitt/awesome-playwright/edit/main/README.md>

**Paste after line 98** (after **Webcmd**):

```markdown
- [ghost-qa](https://github.com/avivgerz-hue/ghost-qa) - Headless browser QA loop for coding agents: crawls localhost, traps console, network and layout failures, and returns a structured self-healing bug report.
```

The section is not strictly alphabetical, so appending after `Webcmd` matches the existing order. If you prefer it sorted, place it directly after **Cutaway** instead.

**PR title**

```
Add ghost-qa to AI & Agents
```

**PR body**

```markdown
Adds [ghost-qa](https://github.com/avivgerz-hue/ghost-qa), an autonomous headless browser QA loop for coding agents.

It drives Playwright against a local dev server, crawls the DOM, safely exercises interactive elements, and traps runtime console errors, failed network requests and layout overflow — then hands the agent a structured self-healing bug report so it fixes real browser failures before declaring the task done.

Built on Playwright (Node ≥18). Install: `npx github:avivgerz-hue/ghost-qa test http://localhost:3000`. MIT licensed.
```

---

## 2. `wong2/awesome-mcp-servers` — 4,406★, active, `main`

**Where:** `## Community Servers` (line 293) is alphabetical. `**Gcore Cloud**` is line 137 and `**GitHub**` is line 138. `ghost-qa` sorts between them.

**Edit link:** <https://github.com/wong2/awesome-mcp-servers/edit/main/README.md>

**Paste before line 138** (immediately before **GitHub**):

```markdown
- **[ghost-qa](https://github.com/avivgerz-hue/ghost-qa)** - Headless browser QA loop for coding agents: crawls localhost, traps console, network and layout failures, and returns a structured self-healing bug report.
```

**PR title**

```
Add ghost-qa to Community Servers
```

**PR body**

```markdown
Adds `ghost-qa`, a local stdio MCP server that gives coding agents a feedback loop against a real browser.

Tools let an agent crawl a running app, exercise interactive elements, and read back structured diagnostics — console errors, HTTP failures, missing elements, layout overflow — instead of guessing whether a page works.

Runs locally via `npx github:avivgerz-hue/ghost-qa mcp` (zero config; `npx ... init` writes `.mcp.json`). Node ≥18, MIT.
```

---

## 3. `punkpeye/awesome-mcp-servers` — 97,456★, active, `main`

The largest and most actively maintained MCP directory, and the most format-strict: a **glama.ai score badge**, language emoji, scope emoji and OS emoji are all expected.

**Where:** `### 📂 Browser Automation` (line 524). Alphabetical by `owner/repo`. The neighbours are **`garlicKim21/ratatosk-mcp`** (line 706) and **`GeiserX/spinnaker-mcp`** (line 707), then **`gitayg/appcrane-mcp`** (line 708). `ghost-qa` sorts after `GeiserX` (g-e < g-h) and before `gitayg` — so it goes **between lines 707 and 708**.

**Edit link:** <https://github.com/punkpeye/awesome-mcp-servers/edit/main/README.md>

**Paste after line 707** (after **GeiserX/spinnaker-mcp**, before **gitayg/appcrane-mcp**):

```markdown
- [avivgerz-hue/ghost-qa](https://github.com/avivgerz-hue/ghost-qa) [![avivgerz-hue/ghost-qa MCP server](https://glama.ai/mcp/servers/avivgerz-hue/ghost-qa/badges/score.svg)](https://glama.ai/mcp/servers/avivgerz-hue/ghost-qa) 📇 🏠 🍎 🪟 🐧 - Headless browser QA loop for coding agents: crawls a running app, exercises interactive elements, and returns console errors, failed requests and layout overflow as a structured self-healing bug report.
```

**Legend justification** (from the README's own legend, lines 53–79):
- `📇` TypeScript codebase — yes
- `🏠` Local Service — yes, runs against your own dev server
- `🍎 🪟 🐧` macOS / Windows / Linux — Node + Playwright, and the code explicitly branches on `process.platform === 'win32'`

> ⚠️ **The glama badge 404s until glama.ai indexes the repo.** That is expected — glama crawls automatically. If you would rather not ship a broken image, delete both `[![...](...)](...)` badge clauses and submit the name link plus emoji only.

**`vibe-shield` alternative** — the same list has a `### 🔒 Security` section (line 4123). `vibe-shield` sorts in the `v` run: **`velvetway/minreestr-mcp`** (4332), **`vespo92/OPNSenseMCP`** (4333), **`vikasny30/aletheia-mcp`** (4334) — so after 4333, before 4334:

```markdown
- [avivgerz-hue/vibe-shield](https://github.com/avivgerz-hue/vibe-shield) [![avivgerz-hue/vibe-shield MCP server](https://glama.ai/mcp/servers/avivgerz-hue/vibe-shield/badges/score.svg)](https://glama.ai/mcp/servers/avivgerz-hue/vibe-shield) 📇 🏠 🍎 🪟 🐧 - Static security scanner for AI-generated codebases: 60 rules for leaked secrets, unguarded mutation routes, missing Postgres RLS, unverified webhooks and prompt-injection sinks, plus an MCP server and agent-skill audit gate.
```

> 🚀 **Fast-track:** CONTRIBUTING.md says automated agents get fast-tracked if you append `🤖🤖🤖` to the end of the PR title. If you submit yourself, **do not** add it — it is an opt-in marker for bots, not humans.

**PR title**

```
Add ghost-qa to Browser Automation
```

**PR body**

```markdown
Adds `ghost-qa` under Browser Automation.

Coding agents write frontend code blind and then declare success while the page has hydration errors, broken buttons, 500ing APIs or mobile overflow. `ghost-qa` launches a headless browser against the running app, crawls the DOM, safely exercises interactive elements and traps console/network/layout failures, returning a structured self-healing bug report the agent can act on.

- Language: TypeScript (`📇`)
- Scope: local (`🏠` — runs against your own dev server)
- OS: macOS / Windows / Linux
- Install: `npx github:avivgerz-hue/ghost-qa test http://localhost:3000`
- MCP: `npx github:avivgerz-hue/ghost-qa mcp`
- MIT
```

---

## 4. `ai-boost/awesome-harness-engineering` — 5,095★, active, `main`

**Why this one.** Your original fourth target, `e2b-dev/awesome-ai-agents`, explicitly redirects tooling elsewhere (line 58: tools → `awesome-ai-sdks`), and `awesome-ai-sdks` is a list of agent SDK frameworks (LangChain, Vercel AI SDK, LangSmith) — neither is a home for a QA tool, and a submission would likely be closed as off-topic.

This list has a **`## Evals & Verification`** section (line 613), which is exactly what both projects are, and it was pushed today.

**Where:** `## Evals & Verification` runs from line 613 to line 639; the last entry is **LevelBench-100** at line 639, then a blank line and `---` at 641. The section is **not** alphabetical — it is ordered by relevance, so append at the end.

**Edit link:** <https://github.com/ai-boost/awesome-harness-engineering/edit/main/README.md>

**Paste after line 639** (after **LevelBench-100**):

```markdown
- [ghost-qa](https://github.com/avivgerz-hue/ghost-qa) — Closes the verification loop for coding agents by testing the *running* app instead of the diff: headless crawl, exercised interactions, and structured console/network/layout failures returned as a self-healing bug report.
- [vibe-shield](https://github.com/avivgerz-hue/vibe-shield) — Static security gate for agent-written code: 60 rules covering leaked secrets, unguarded mutation routes, missing Postgres RLS, unverified webhooks and prompt-injection sinks, runnable as a CLI, MCP server or CI gate.
```

The repo's contributing note (line 704) asks for "a 1–2 sentence note explaining *why* it's worth including" — the em-dash clauses above satisfy that.

**PR title**

```
Add ghost-qa and vibe-shield to Evals & Verification
```

**PR body**

```markdown
Both entries address the same harness problem: an agent's claim that work is "done" is unverified.

`ghost-qa` verifies behaviour (the app actually runs — no console errors, no failed requests, no broken interactions), and `vibe-shield` verifies the security surface of what was written (no leaked secrets, no unauthenticated mutations, no missing RLS).

Together they cover runtime and static verification for agent output. Both MIT, Node ≥18, zero-install via `npx github:`.
```

---

## Why the original list of four had to change

| Original target | Verdict |
|---|---|
| `mxschmitt/awesome-playwright` | ✅ Good fit — submitted as-is |
| `wong2/awesome-mcp-servers` | ✅ Good fit — submitted as-is |
| `appcypher/awesome-mcp-servers` | ❌ **ARCHIVED** (5,825★, last push 2026-05-06). A PR is never merged. Replaced with `punkpeye/awesome-mcp-servers` (97,456★, actively synced) |
| `e2b-dev/awesome-ai-agents` | ❌ Explicitly excludes tools (line 58 redirects to `awesome-ai-sdks`, itself SDK-frameworks-only). Replaced with `ai-boost/awesome-harness-engineering`, which has an `Evals & Verification` section |

---

## One fix to make in `ghost-qa` before you submit

Reviewers will click through to the repo, and its README has the same defect just fixed in `vibe-shield` (PR #5):

- **`ghost-qa`'s npm badge is broken.** README line 6 is `img.shields.io/npm/v/ghost-qa.svg` → `npmjs.com/package/ghost-qa`, but `npm view ghost-qa` returns **404 — the package does not exist on npm**. The badge renders "package not found". Swap it for:

```markdown
[![version](https://img.shields.io/github/package-json/v/avivgerz-hue/ghost-qa?style=flat-square&label=version)](https://github.com/avivgerz-hue/ghost-qa/blob/main/package.json)
```

Everything else in `ghost-qa` is already correct: README, SKILL.md, smithery.yaml, glama.json, server.json and the `.mcp.json` generator (`src/mcp/server.ts:305`) all use `npx github:avivgerz-hue/ghost-qa`, with no `npx ghost-qa` or `@latest` anywhere. Step 1 needed no changes.
