# Contributing to vibe-shield

Thanks for being here. This project exists because agent-written code ships
vulnerabilities that reviewers miss, and the fastest way to make it better is a
new rule derived from a real bug you saw.

## The highest-value contribution: a new rule

Every rule in vibe-shield comes from a real failure. If you have seen an agent
produce something insecure, that is a rule waiting to be written.

### 1. Pick the family

| Module | Use it for |
| --- | --- |
| `src/scanner/rules/client-exposure.ts` | anything that reaches the browser bundle |
| `src/scanner/rules/unguarded-routes.ts` | authentication, authorisation, CSRF |
| `src/scanner/rules/database-exposure.ts` | RLS, SQL, grants, migrations |
| `src/scanner/rules/ai-vulnerabilities.ts` | LLM plumbing and classic web bugs |
| `src/scanner/rules/secret-entropy.ts` | credential shapes |
| `src/mcp-guard/skill-auditor.ts` | agent skills, MCP config, instruction files |

### 2. Claim the next id

Ids are never reused and never renumbered. `VSB-<FAMILY>-<NNN>` continues from
the last one in the family; `tests/scanner.test.ts` asserts the exact set, so a
missing or duplicated id fails the suite.

### 3. Write the rule

```ts
const myRule: Rule = defineRule({
  id: 'VSB-AI-016',
  slug: 'websocket-origin-not-checked',
  title: 'WebSocket connection accepts any origin',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.csrf,
  description:
    'A WebSocket server that upgrades every request lets any page open an authenticated socket on behalf of a signed-in user (cross-site WebSocket hijacking).',
  insecureExample: 'const wss = new WebSocketServer({ server }); // no origin check',
  secureExample:
    'wss.on("connection", (socket, req) => {\n  if (!allowed.has(req.headers.origin)) return socket.close();\n});',
  remediation: [
    'Validate `req.headers.origin` against an allow-list during the upgrade.',
    'Require a session token in the first message instead of relying on cookies.',
    'Reject the upgrade with 403 before the socket is established.',
  ],
  references: ['https://cwe.mitre.org/data/definitions/1385.html'],
  extensions: ['ts', 'js'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/WebSocketServer|wss\\.on/],
  detect(ctx) {
    // return RuleHit[] — { offset, matched, message, data }
    return [];
  },
});
```

Export it from the module's rule array. `rules/index.ts` picks it up
automatically through the family export, and the catalogue test enforces the id.

### Rule requirements (the suite checks these)

- [ ] **Stable id** that does not collide with an existing one.
- [ ] **`description` ≥ 40 chars** explaining *why* it is exploitable, not what the regex matches.
- [ ] **`insecureExample`** — the exact shape that triggers it.
- [ ] **`secureExample`** — the shape that does not (this becomes the agent's target).
- [ ] **`remediation` ≥ 2 steps**, ordered, actionable without further research.
- [ ] **`references` ≥ 1**, ideally a primary source and the CWE page.
- [ ] **A real `Cwe`** via the `CWES` record in `rules/shared.ts`.
- [ ] **`skipFlags: [...LOGIC_SKIP_FLAGS]`** unless the rule genuinely applies to tests/docs.
- [ ] **`contentHints`** so the rule is not run on every file (performance is a feature).
- [ ] **A guard clause for the legitimate pattern.** If `DOMPurify`, `auth.uid()`, `import "server-only"` or a tagged template makes the code safe, the rule must not fire.

### 4. Add both fixtures

- A **vulnerable** case in `tests/fixtures/vulnerable/` that triggers it.
- A **secure** case in `tests/fixtures/secure/` that does not.

`tests/scanner.test.ts` asserts the vulnerable fixture produces the finding
*and* that the secure fixture produces **zero findings overall**. A rule that
fires on the secure app breaks the build — that is deliberate.

### 5. Write the tests

```ts
it('detects an unchecked WebSocket origin', async () => {
  const result = await scan({
    'server/ws.ts': 'const wss = new WebSocketServer({ server });\n',
  });
  expectRule(result, 'VSB-AI-016');
});

it('accepts an origin allow-list', async () => {
  const result = await scan({
    'server/ws.ts': 'wss.on("connection", (s, req) => { if (!allowed.has(req.headers.origin)) s.close(); });\n',
  });
  expectNoRule(result, 'VSB-AI-016');
});
```

`scan()` and `makeProject()` from `tests/helpers.ts` write a throwaway project to
`os.tmpdir()` and clean up after themselves — never scan the repository itself in
a test.

## Fixture hygiene

Fixture secrets must look **real** to the entropy heuristic and **fake** to the
placeholder filter. `isPlaceholderSecret` rejects anything containing `fake`,
`test`, `your`, `xxxx`, `example`, `sample`, `dummy`, `changeme`, `redacted`,
`foo`/`bar`/`baz`, `hunter2`, or any low-entropy / repeated-character string.
A test with `sk_live_xxxx` passes vacuously because nothing is detected.

Use random-looking high-entropy alphanumerics instead:

```ts
sk_live_7Qm3Xk9Rb2Vt6Yw4Zp8Nd5Hj1Lc0Sg   // ✅ detected
sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx    // ❌ filtered as a placeholder
```

For the privileged-JWT test, build the token at test time so the payload is
readable in the source:

```ts
const payload = Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url');
```

## Development loop

```bash
npm ci
npm run typecheck   # must be zero errors (strict + noUnusedLocals + noUnusedParameters)
npm test            # 174 tests
npm run build       # tsc + postbuild
npm run verify      # everything, including the self-scan
```

`npm run verify` is the same gate CI runs. If it fails on the self-scan, the
finding is almost always in a documentation example — check whether the snippet
belongs inside a fenced block (markdown is excluded from code rules) before
reaching for `.vibe-shieldignore`.

## Code style

- **TypeScript strict**, no `any` unless it is a boundary with untyped JSON (use `unknown` + a narrowing cast).
- **No new runtime dependencies.** This is a hard rule: the package must install instantly and run offline. Dev dependencies are considered case by case and should be justified in the PR.
- **No placeholder text.** `TODO`, `FIXME`, `not implemented` and stubs fail the suite (`tests/scanner.test.ts` scans the source for them).
- **Comments explain *why*.** The code explains what; a comment earns its place by explaining a decision, a trade-off or a false-positive guard.
- **Errors never abort a scan.** A rule that throws is caught and skipped; a failure to read one file is not a failure to scan.

## Commit messages

Conventional commits, scoped to the area:

```
feat(rules): detect unchecked WebSocket origins
fix(engine): honour .vibe-shieldignore for explicit path targets
perf(scanner): skip lockfiles during discovery
docs(readme): add the coverage matrix
test(auditor): cover base64 pipe payloads
```

## Pull requests

1. Fork, branch from `main`, and keep the diff focused on one thing.
2. Run `npm run verify` and paste the summary in the PR description.
3. If you add a rule, include the vulnerable **and** secure fixture in the same PR.
4. If you change the scoring model or a public type, say so explicitly in the description — it is a breaking change for embedders.

## Reporting a false positive

Open a normal issue with the exact snippet that was flagged, the rule id, and why
it is safe. False positives are treated as bugs of equal priority to false
negatives: a scanner people do not trust is a scanner people turn off.

## Security issues

Do not open an issue. Follow [SECURITY.md](./SECURITY.md).

## License

By contributing you agree your work is licensed under the [MIT License](./LICENSE)
and that you have the right to submit it.
