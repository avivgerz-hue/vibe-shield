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
    /** Name of the MCP server map in JSON config files. */
    mergeKey?: 'mcpServers' | 'mcp' | 'servers' | 'context_servers';
}
export declare const AGENT_NAMES: readonly ["claude", "opencode", "codex", "generic", "cursor", "windsurf", "copilot", "cline", "roo", "zed"];
export type AgentName = (typeof AGENT_NAMES)[number];
export interface InitOptions {
    /** Repository root (absolute). */
    rootDir: string;
    /** Which agent integration to install. */
    agents?: AgentName | 'all' | readonly AgentName[];
    /** Write the GitHub Actions workflow. Default true. */
    workflow?: boolean;
    /** Overwrite existing files. Default false. */
    force?: boolean;
    /** Print what would happen without writing. */
    dryRun?: boolean;
    /**
     * Version to pin in both the workflow and the `.mcp.json` entry.
     *
     * Resolved from the installed package when omitted; see
     * `packageVersionFromDisk`.
     */
    version?: string | null;
    /** Environment to read the version override from. Defaults to `process.env`. */
    env?: NodeJS.ProcessEnv;
}
export interface InitResult {
    written: string[];
    appended: string[];
    skipped: string[];
    /** Files that exist but were left alone because they could not be merged. */
    blocked: string[];
    warnings: string[];
}
export declare const SKILL_TEMPLATE = "---\nname: vibe-shield\ndescription: Apply a six-phase defensive security review to changes affecting applications, APIs, data, AI agents, and MCP configuration. Use static evidence, preserve behavior, and report limitations.\nallowed-tools: Bash(npx -y @vibefoundry/vibe-shield scan*), Bash(npx -y @vibefoundry/vibe-shield audit-skills*), Bash(npx -y @vibefoundry/vibe-shield explain*), Read(./**), Grep, Glob\nlicense: MIT\nmetadata:\n  author: VibeFoundry\n  homepage: https://github.com/avivgerz-hue/vibe-shield\n  version: 2.0.0\n---\n\n# Defensive AppSec architect protocol\n\nWork only within the authorized project. Static findings are evidence for review, not proof of exploitability or a guarantee of safety. Do not transmit source code or secrets. Ask before changing production services, rotating credentials, or making destructive changes.\n\n## Phase 1: Attack-surface reconnaissance\n\nMap entrypoints and trust boundaries: API methods, authentication and authorization, middleware matchers, database tables and policies, storage, LLM inputs and tools, webhooks, and agent/MCP configuration. Check deployment configuration and exclusions. Identify what the scanner cannot see.\n\n## Phase 2: Automated static scan and skill audit\n\n```bash\nnpx -y @vibefoundry/vibe-shield scan . --format json\nnpx -y @vibefoundry/vibe-shield audit-skills . --format json\n```\n\nInspect findings, inventory, ignored paths, and the files scanned. The explicit `.` includes test and documentation files: review fixtures as examples rather than blindly changing them. Use `explain <RULE_ID>` to investigate a rule. These commands run locally; first-time installation with npx requires registry access.\n\n## Phase 3: Deep contextual threat modeling\n\nTrace untrusted input through authentication, ownership checks and tenant boundaries to database, filesystem, network, HTML, and LLM sinks. Inspect IDOR, business-logic bypasses, webhook signature verification and asynchronous jobs. Check cross-file guards and deployed database policies; absence of a static finding is not evidence of protection.\n\n## Phase 4: Surgical zero-regression remediation\n\n- On Next.js mutation routes, authenticate the session on the server and authorize the target resource against the session principal before writes. Do not trust identity from request bodies.\n- Enable Supabase RLS and write action-specific policies using the authenticated principal; test both permitted and denied tenants before deploying migrations.\n- Validate inputs at the boundary with a schema such as Zod, then use parameterized database queries. Treat LLM output as untrusted.\n- Use explicit CORS allowlists, secure cookie flags and a CSP appropriate for the application. Test login, redirects, and browser behavior.\n- Report exposed credentials to the owner for provider-side rotation; avoid reproducing their values in reports. Do not suppress findings or weaken controls to obtain a higher score. Ask for missing business or deployment decisions.\n\n### Supabase RLS and ownership policies (VSB-DB-001 / VSB-DB-002)\n\nAdapt the table, owner column, and policy names to your schema. First inspect **all** existing policies: permissive policies are OR-combined, so one leftover `USING (true)` can still expose rows. Replace or drop each broad policy in a reviewed migration; the example only drops the named policy. Enable RLS, use a non-null `user_id` referencing `auth.users(id)`, grant only needed table privileges to `authenticated`, and test allowed and denied access for two users. Owners, service roles and `BYPASSRLS` can bypass RLS: do not use those credentials in client-facing code.\n\n```sql\n-- Example: public.documents has id and NOT NULL user_id (uuid).\nBEGIN;\nALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;\nDROP POLICY IF EXISTS \"allow all\" ON public.documents;\nCREATE POLICY \"documents_select_own\" ON public.documents\n  FOR SELECT TO authenticated USING (auth.uid() = user_id);\nCREATE POLICY \"documents_insert_own\" ON public.documents\n  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);\nCREATE POLICY \"documents_update_own\" ON public.documents\n  FOR UPDATE TO authenticated\n  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);\nCREATE POLICY \"documents_delete_own\" ON public.documents\n  FOR DELETE TO authenticated USING (auth.uid() = user_id);\nCOMMIT;\n```\n\n### Next.js App Router: verified session and ownership (VSB-AUTH-001 / VSB-AUTH-004)\n\nThis example assumes your `@/lib/supabase/server` helper creates a request-scoped Supabase server client using the caller's cookies, not a service-role client. Install Zod and adapt the table and schema. Never accept `userId` or ownership from `await req.json()`: derive it from verified `getUser()`, then bind it to the database write. Use appropriate CSRF/origin protection for cookie-authenticated mutations.\n\n```typescript\n// app/api/documents/route.ts\nimport { z } from 'zod';\nimport { createClient } from '@/lib/supabase/server';\n\nconst Input = z.object({ id: z.string().uuid(), title: z.string().trim().min(1).max(200) }).strict();\n\nexport async function PATCH(req: Request): Promise<Response> {\n  const supabase = await createClient();\n  const { data: { user }, error: authError } = await supabase.auth.getUser();\n  if (authError || !user) return new Response('Unauthorized', { status: 401 });\n  const userId = user.id;\n  const body = Input.safeParse(await req.json().catch(() => null));\n  if (!body.success) return new Response('Invalid request', { status: 400 });\n  const documentId = body.data.id;\n  const { data, error } = await supabase.from('documents')\n    .update({ title: body.data.title })\n    .eq('id', documentId).eq('user_id', userId)\n    .select('id').maybeSingle();\n  if (error) return new Response('Update failed', { status: 500 });\n  if (!data) return new Response('Not found', { status: 404 });\n  return Response.json({ id: data.id });\n}\n```\n\n### AI routes: distributed rate limits and token caps (VSB-AI-014)\n\n`VSB-AI-001` is the existing **command injection** rule; rate limiting is `VSB-AI-014`. The example below shares one verified-user limit between `/api/chat` and `/api/completion`, rejects oversized bodies while reading, limits output tokens and times out the provider call. Install `openai`, `@upstash/redis`, `@upstash/ratelimit`, and `zod`; configure Redis and provider credentials as server-only environment variables, plus your request-scoped Supabase helper. The Redis limiter must be shared across instances and fail closed. Tune limits to the application, and separately enforce atomic per-user spending/token quotas, provider budget alerts, and an input-token/context limit using the model's tokenizer. Character and output caps alone are not a complete spend limit.\n\n```typescript\n// lib/guarded-ai.ts \u2014 reused by both routes\nimport 'server-only';\nimport OpenAI from 'openai';\nimport { Redis } from '@upstash/redis';\nimport { Ratelimit } from '@upstash/ratelimit';\nimport { z } from 'zod';\nimport { createClient } from '@/lib/supabase/server';\n\nconst limiter = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, '1 m') });\nconst openai = new OpenAI();\nconst Input = z.object({ prompt: z.string().trim().min(1).max(4000) }).strict();\n\nasync function readBody(req: Request): Promise<unknown> {\n  if (!req.body) throw new Error('Missing body');\n  const reader = req.body.getReader();\n  const chunks: Uint8Array[] = [];\n  let size = 0;\n  try {\n    for (;;) {\n      const { done, value } = await reader.read();\n      if (done) break;\n      size += value.byteLength;\n      if (size > 8192) { await reader.cancel(); throw new Error('Body too large'); }\n      chunks.push(value);\n    }\n  } finally { reader.releaseLock(); }\n  const bytes = new Uint8Array(size);\n  let offset = 0;\n  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }\n  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));\n}\n\nexport async function POST(req: Request): Promise<Response> {\n  const supabase = await createClient();\n  const { data: { user }, error } = await supabase.auth.getUser();\n  if (error || !user) return new Response('Unauthorized', { status: 401 });\n  try {\n    const { success } = await limiter.limit(`ai:${user.id}`);\n    if (!success) return new Response('Rate limit exceeded', { status: 429 });\n  } catch { return new Response('Rate limiter unavailable', { status: 503 }); }\n  let raw: unknown;\n  try { raw = await readBody(req); } catch { return new Response('Invalid body', { status: 400 }); }\n  const parsed = Input.safeParse(raw);\n  if (!parsed.success) return new Response('Invalid request', { status: 400 });\n  try {\n    const result = await openai.chat.completions.create({\n      model: 'gpt-4o-mini',\n      messages: [{ role: 'user', content: parsed.data.prompt }],\n      max_completion_tokens: 512,\n    }, { signal: AbortSignal.timeout(30_000) });\n    return Response.json({ text: result.choices[0]?.message.content ?? '' });\n  } catch { return new Response('AI provider unavailable', { status: 502 }); }\n}\n```\n\n```typescript\n// app/api/chat/route.ts and app/api/completion/route.ts\nexport { POST } from '@/lib/guarded-ai';\n```\n\n\n## Phase 5: Verification gate\n\nRun project tests and both audits again. Aim for 100/100 Grade A+ with no high or critical findings, but report any unresolved finding, exclusion, false positive, or verification limitation honestly rather than claiming success. Never equate a clean score with a complete security assessment.\n\n```bash\nnpx -y @vibefoundry/vibe-shield scan --fail-on high\nnpx -y @vibefoundry/vibe-shield audit-skills --fail-on high\n```\n\n## Phase 6: Executive security sign-off\n\nProduce a Markdown or HTML report with scope, inventory, risks prioritized by severity, evidence, actions, test results and remaining uncertainty. Illustrative code examples are not project-specific patches; review and adapt them. Obtain human approval before deployment or provider-side action.\n\n```bash\nnpx -y @vibefoundry/vibe-shield scan --report SECURITY-REPORT.md --patch-prompt PATCH-PROMPT.md\nnpx -y @vibefoundry/vibe-shield audit-skills --report AGENT-REPORT.html\n```\n";
export declare const AGENTS_SECTION = "## Security gate (vibe-shield)\n\nThis repository is guarded by [vibe-shield](https://github.com/avivgerz-hue/vibe-shield).\n\nBefore you report any task as complete:\n\n1. Run `npx -y @vibefoundry/vibe-shield scan --fail-on high` and fix every finding it reports.\n2. Never suppress a finding (`vibe-shield-disable`, `.vibe-shieldignore` edits,\n   `--ignore`) to make the gate pass \u2014 that is the human's call.\n3. If you touched `.claude/`, `.cursor/`, `AGENTS.md`, `mcp.json` or a skill,\n   also run `npx -y @vibefoundry/vibe-shield audit-skills`.\n4. Surface any exposed credential to the user for rotation. Do not \"fix\" it by\n   deleting the line and moving on.\n\nThe gate exists because the most common way AI-written code reaches production\nwith a leaked `SUPABASE_SERVICE_ROLE_KEY` or an unauthenticated `DELETE`\nendpoint is that nobody asked it a second question.\n";
/** Key this tool owns inside `mcpServers`; nothing else is ever touched. */
export declare const MCP_SERVER_KEY = "vibe-shield";
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
export declare const MCP_SERVER_SPEC = "@vibefoundry/vibe-shield";
/** Build the `.mcp.json` entry, pinned to `version` when one is known. */
export declare function mcpServerEntry(version?: string | null): {
    command: string;
    args: string[];
};
/**
 * The entry as this install writes it: pinned to the running package version.
 * Falls back to unpinned only in a stripped checkout where no `package.json`
 * names this package, which is the one case where no version is knowable.
 */
export declare const MCP_SERVER_ENTRY: {
    command: string;
    args: string[];
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
/**
 * The version of the running install, used to pin `.mcp.json`.
 *
 * Read from the nearest `package.json` that names this package. Falls back to
 * the range in `package.json` only if nothing is found, which keeps `init`
 * working in a stripped-down checkout rather than writing a nameless spec.
 */
export declare function packageVersionFromDisk(): string | null;
export declare function mergeMcpConfig(existing: string | null, options?: {
    force?: boolean;
    version?: string | null;
}): {
    contents: string;
    changed: boolean;
    error?: string;
};
export declare const WORKFLOW_TEMPLATE = "name: vibe-shield\n\non:\n  push:\n    branches: [main, master]\n  pull_request:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n  security-events: write\n  pull-requests: write\n\njobs:\n  scan:\n    name: Security audit\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n\n      - name: Scan for vulnerabilities\n        run: npx -y @vibefoundry/vibe-shield scan --format sarif --out vibe-shield.sarif --fail-on high\n        continue-on-error: true\n\n      - name: Upload SARIF to code scanning\n        if: always()\n        uses: github/codeql-action/upload-sarif@v3\n        with:\n          sarif_file: vibe-shield.sarif\n          category: vibe-shield\n\n      - name: Audit agent surface\n        run: npx -y @vibefoundry/vibe-shield audit-skills --fail-on high\n\n      - name: Enforce the gate\n        run: npx -y @vibefoundry/vibe-shield scan --fail-on high --quiet\n";
export declare const IGNORE_TEMPLATE = "# .vibe-shieldignore \u2014 gitignore syntax.\n#\n# Keep this file as short as possible: every line hides real code from the\n# security gate. Prefer an inline suppression with a reason where it applies:\n#\n#   // vibe-shield-disable-next-line VSB-AI-001 -- path comes from a fixed enum\n#\n# Generated code, vendored third-party sources and build output are the only\n# good reasons to ignore a path wholesale.\n\n# Generated / vendored\n# vendor/**\n# **/*.generated.ts\n# **/__generated__/**\n\n# Local-only scratch work\n# scratch/**\n";
/** Build the full set of files for a given target repository. */
export declare function buildScaffold(options: InitOptions): ScaffoldFile[];
/** Merge one owned server without replacing other entries or malformed files. */
export declare function mergeAgentConfig(existing: string | null, key: NonNullable<ScaffoldFile['mergeKey']>, options?: {
    force?: boolean;
    version?: string | null;
}): {
    contents: string;
    changed: boolean;
    error?: string;
};
/** Write the scaffold into `options.rootDir`. Idempotent unless `force`. */
export declare function installScaffold(options: InitOptions): Promise<InitResult>;
/** Locate the shipped `SKILL.md` (used by `init` to copy the canonical file). */
export declare function locateBundledSkill(startDir: string): Promise<string | null>;
