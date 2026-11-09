/**
 * vibe-shield :: ai-vulnerabilities rules
 * ---------------------------------------
 * Two families live here because they share a root cause: an agent that
 * "makes it work" on the happy path and never models an attacker.
 *
 *  - LLM-specific: tool calls that reach a shell, model output piped into
 *    `eval`, untrusted context promoted to the system prompt, expensive routes
 *    with no quota.
 *  - Classic web: command injection, webhook signature bypass, XSS, open
 *    redirect, SSRF, path traversal, unrestricted uploads, insecure
 *    deserialization.
 */

import {
  LLM_REGEX,
  RATE_LIMIT_REGEX,
  SANITIZER_REGEX,
  UNTRUSTED_SOURCE_REGEX,
} from '../lexicon';
import { balancedBlock, looksDynamic } from '../text';
import { defineRule, fileHit, regexHits } from './helpers';
import { CWES, LOGIC_SKIP_FLAGS } from './shared';
import type { FileContext, Rule, RuleHit } from '../types';

const APP_EXTENSIONS = ['ts', 'tsx', 'js', 'jsx', 'mts', 'mjs', 'cts', 'cjs', 'py', 'rb', 'php', 'go', 'java'];

/** Argument text of the call whose `(` is the first one at/after `offset`. */
function callArgs(ctx: FileContext, offset: number): string {
  const open = ctx.code.indexOf('(', offset);
  if (open === -1) return '';
  return balancedBlock(ctx.code, open, '(', ')');
}

/** Next.js route handlers are already covered by the auth rules; the LLM rules
 *  care about whether the endpoint can be called by a stranger at all. */
const isPublicEndpoint = (ctx: FileContext): boolean =>
  ctx.flags.isAppRouterRoute || ctx.flags.isPagesApiRoute || ctx.flags.isServerFrameworkFile || ctx.flags.isServerActionModule;

/* -------------------------------------------------------------------------- */
/* VSB-AI-001 - OS command injection                                          */
/* -------------------------------------------------------------------------- */

const commandInjection: Rule = defineRule({
  id: 'VSB-AI-001',
  slug: 'command-injection',
  title: 'OS command built from untrusted input',
  category: 'ai-vulnerabilities',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.commandInjection,
  description:
    '`child_process.exec`, `execSync`, `spawn({ shell: true })`, `os.system`, `subprocess(shell=True)` and PHP backticks all hand the string to a shell. If any part of that string comes from a request, a tool argument or model output, the caller can append `; rm -rf /`.',
  insecureExample: "exec(`convert ${req.body.file} -resize 200x200 out.png`)",
  secureExample: "execFile('convert', [req.body.file, '-resize', '200x200', 'out.png'])",
  remediation: [
    'Replace `exec`/`execSync` with `execFile`/`spawn` and pass arguments as an array — no shell parsing happens.',
    'Never pass `shell: true`; if you must, quote and allow-list every interpolated value first.',
    'In Python use `subprocess.run([...], shell=False)`; in PHP `escapeshellarg()` plus an allow-list.',
    'Validate the value against a strict pattern (`^[a-z0-9_-]{1,64}$`) before it reaches the process.',
  ],
  references: [
    'https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback',
    'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/78.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/\b(?:exec|execSync|spawn|execFile|system|popen|Runtime\.getRuntime|ProcessBuilder|shell_exec|passthru|subprocess)\b/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sinks: Array<{ regex: RegExp; note: string; needsDynamic: boolean }> = [
      { regex: /\bchild_process\.(?:exec|execSync)\s*\(/g, note: '`child_process.exec` runs through a shell.', needsDynamic: true },
      { regex: /(?<![\w.])exec\s*\(\s*`/g, note: '`exec()` with a template literal runs through a shell.', needsDynamic: true },
      { regex: /(?<![\w.])execSync\s*\(\s*`/g, note: '`execSync()` with a template literal runs through a shell.', needsDynamic: true },
      { regex: /\bspawn(?:Sync)?\s*\([^)]{0,400}?\bshell\s*:\s*true/g, note: '`spawn({ shell: true })` reintroduces shell parsing.', needsDynamic: false },
      { regex: /\bBun\s*\.\s*spawn\s*\(/g, note: 'Verify `Bun.spawn` receives an argv array, not a single command string.', needsDynamic: true },
      { regex: /\bos\s*\.\s*(?:system|popen)\s*\(/g, note: '`os.system`/`os.popen` pass the string to `/bin/sh`.', needsDynamic: true },
      { regex: /\bsubprocess\s*\.\s*(?:run|call|check_output|Popen)\s*\([^)]{0,300}?shell\s*=\s*True/g, note: '`subprocess(shell=True)` enables shell metacharacters.', needsDynamic: false },
      { regex: /\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/g, note: '`Runtime.exec` invokes a shell command.', needsDynamic: true },
      { regex: /\bProcessBuilder\s*\(/g, note: '`ProcessBuilder` with a single string uses a shell.', needsDynamic: true },
      { regex: /\b(?:shell_exec|passthru|system|popen|proc_open)\s*\(/g, note: 'A PHP shell function is called.', needsDynamic: true },
      { regex: /`\s*\$[A-Za-z_]/g, note: 'PHP backtick execution with an interpolated variable.', needsDynamic: false },
    ];
    for (const sink of sinks) {
      for (const match of ctx.code.matchAll(sink.regex)) {
        const args = callArgs(ctx, match.index);
        const dynamic = looksDynamic(args) || UNTRUSTED_SOURCE_REGEX.test(args);
        if (sink.needsDynamic && !dynamic) continue;
        if (!sink.needsDynamic && sink.regex.source.includes('shell') && !dynamic) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 160),
          message: sink.note,
          data: { sink: match[0].slice(0, 40) },
        });
        void args;
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-002 - LLM/MCP tool execute reaching a dangerous sink                */
/* -------------------------------------------------------------------------- */

const toolExecuteSink: Rule = defineRule({
  id: 'VSB-AI-002',
  slug: 'llm-tool-dangerous-execute',
  title: 'LLM/MCP tool `execute` reaches a shell, eval or filesystem sink',
  category: 'ai-vulnerabilities',
  severity: 'critical',
  confidence: 'medium',
  cwe: CWES.codeInjection,
  description:
    'A `tool({ ... execute })` is a remote-control surface for the model. If `execute` forwards its argument into `exec`, `eval`, `new Function`, `fetch` or `fs.writeFile`, then a prompt injection anywhere upstream becomes remote code execution on your server.',
  insecureExample: 'tool({ description: "run shell", execute: async ({ cmd }) => exec(cmd) })',
  secureExample: 'tool({ execute: async ({ file }) => execFile("wc", ["-l", allowListed(file)]) })',
  remediation: [
    'Do not expose a general shell to a model. Expose narrow, typed tools with a schema that constrains the argument.',
    'Allow-list the operations the tool may perform and validate every argument against a strict schema (`z.enum([...])`).',
    'Require human confirmation for destructive tools, and run them with the least-privilege credentials.',
    'Log every tool invocation with its arguments so an injected instruction is auditable.',
  ],
  references: [
    'https://sdk.vercel.ai/docs/ai-sdk-core/tools-and-tool-calling',
    'https://modelcontextprotocol.io/docs/concepts/tools',
    'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/\bexecute\s*:/, /\bexecute\s*\(/],
  detect(ctx) {
    if (!LLM_REGEX.test(ctx.code)) return [];
    const hits: RuleHit[] = [];
    const sinkRegex = /\b(?:exec|execSync|spawn|execFile|eval|Function|writeFile|writeFileSync|appendFile|unlink|rm|rmdir|readFile|readFileSync|fetch|axios|request)\s*\(/g;
    const dangerous = /(?:exec|execSync|spawn|execFile|eval|Function|writeFile|writeFileSync|appendFile|unlink|rm|rmdir|readFile|readFileSync)/;
    for (const match of ctx.code.matchAll(/\bexecute\s*(?::|\(|=\s*(?:async\s*)?\()/g)) {
      let body = '';
      const start = match.index + match[0].length;
      if (match[0].includes(':')) {
        // `execute: async ({ cmd }) => { ... }` — skip the parameter list, then
        // take the first block that follows the arrow.
        const params = balancedBlock(ctx.code, ctx.code.indexOf('(', start), '(', ')');
        const arrow = ctx.code.indexOf('=>', start + params.length);
        const brace = arrow === -1 ? -1 : ctx.code.indexOf('{', arrow);
        body = brace === -1 ? '' : balancedBlock(ctx.code, brace, '{', '}');
      } else {
        const open = ctx.code.indexOf('(', match.index);
        const params = balancedBlock(ctx.code, open, '(', ')');
        const brace = ctx.code.indexOf('{', open + params.length);
        body = brace === -1 ? '' : balancedBlock(ctx.code, brace, '{', '}');
      }
      if (!body) continue;
      const sinks = new Set<string>();
      for (const sink of body.matchAll(sinkRegex)) {
        if (!dangerous.test(sink[0])) continue;
        // Reading a caller-supplied path is also a traversal sink.
        sinks.add((sink[0] ?? '').replace(/\s*\($/, ''));
      }
      if (!sinks.size) continue;
      hits.push({
        offset: match.index,
        matched: `execute · ${[...sinks].slice(0, 3).join(', ')}`,
        message: `An LLM-callable tool forwards model-controlled input into ${[...sinks].slice(0, 3).map((s) => `\`${s}\``).join(', ')}.`,
        severity: sinks.has('exec') || sinks.has('eval') || sinks.has('execSync') || sinks.has('Function') ? 'critical' : 'high',
        confidence: 'medium',
        data: { sinks: [...sinks] },
      });
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-003 - model output into a code sink                                 */
/* -------------------------------------------------------------------------- */

const llmOutputEval: Rule = defineRule({
  id: 'VSB-AI-003',
  slug: 'llm-output-code-execution',
  title: 'Model output passed to `eval` / `new Function` / `vm`',
  category: 'ai-vulnerabilities',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.codeInjection,
  description:
    'Treating generated text as code turns prompt injection into remote code execution. The model is not a trusted compiler: any page, document or tool result it read can contain the payload.',
  insecureExample: 'const result = await openai.chat.completions.create({...});\neval(result.choices[0].message.content)',
  secureExample: 'const plan = PlanSchema.parse(result.choices[0].message.content);\nrunStep(plan.step); // closed set of steps',
  remediation: [
    'Never evaluate model output. Parse it into a typed structure (zod schema) and act on an allow-listed set of actions.',
    'If you must execute generated code, use a hardened sandbox (separate process/container, no network, CPU+memory limits) — never `eval`/`new Function` in your own process.',
    'Keep the model output out of `vm.runInNewContext` with the host realm, and out of `require`/`import` paths.',
  ],
  references: [
    'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    'https://cwe.mitre.org/data/definitions/94.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/\beval\s*\(/, /new\s+Function/, /runInNewContext|runInThisContext|compile\s*\(/],
  detect(ctx) {
    if (!LLM_REGEX.test(ctx.code)) return [];
    const hits: RuleHit[] = [];
    const assignment = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?[\s\S]{0,400}?(?:completion|choices?|content|generateText|generateObject|invoke|messages\.create|chat\.completions)[\s\S]{0,200}?;/g;
    const modelVars = new Set<string>();
    for (const match of ctx.code.matchAll(assignment)) {
      if (match[1]) modelVars.add(match[1]);
    }
    const sinks: Array<{ regex: RegExp; note: string }> = [
      { regex: /\beval\s*\(/g, note: 'Model output reaches `eval()`.' },
      { regex: /\bnew\s+Function\s*\(/g, note: 'Model output reaches `new Function()`.' },
      { regex: /\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext)\s*\(/g, note: 'Model output is executed in a `vm` context.' },
      { regex: /\brequire\s*\(\s*(?:completion|output|response|result|answer)\b/g, note: 'Model output is used as a module path.' },
    ];
    for (const sink of sinks) {
      for (const match of ctx.code.matchAll(sink.regex)) {
        const args = callArgs(ctx, match.index);
        const referencesModel = [...modelVars].some((name) => new RegExp(`\\b${name}\\b`).test(args));
        const inlineModel = /(?:completion|choices?\.\d+\.message\.content|\.content\b|generateText|generateObject)/.test(args);
        if (!referencesModel && !inlineModel) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 120),
          message: sink.note,
          data: { sink: match[0].slice(0, 40) },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-004 - prompt injection via untrusted context                        */
/* -------------------------------------------------------------------------- */

const promptInjection: Rule = defineRule({
  id: 'VSB-AI-004',
  slug: 'prompt-injection-untrusted-context',
  title: 'Untrusted content interpolated into the system prompt',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.promptInjection,
  description:
    'Request bodies, scraped pages, file contents and RAG chunks must never be concatenated into the `system` message. Whatever the attacker wrote there becomes an instruction the model treats as trusted (OWASP LLM01).',
  insecureExample: 'messages: [{ role: "system", content: `You are a support bot. Context: ${req.body.context}` }]',
  secureExample: 'messages: [\n  { role: "system", content: SYSTEM_PROMPT },\n  { role: "user", content: `<context>${userSupplied}</context>` },\n]',
  remediation: [
    'Keep the system prompt a constant. Put all variable content in a `user` message wrapped in explicit delimiters (`<context>…</context>`).',
    'Tell the model that delimited content is data, never instructions, and that it must ignore instruction-like text inside it.',
    'Validate and truncate the untrusted content; strip control sequences and "ignore previous instructions" style preambles.',
    'For tool-using agents, require explicit confirmation before side-effecting tools run on model-generated arguments.',
  ],
  references: [
    'https://genai.owasp.org/llmrisk/llm01-prompt-injection/',
    'https://simonwillison.net/2023/Apr/14/worst-that-can-happen/',
    'https://cwe.mitre.org/data/definitions/74.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/system/i],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const patterns: RegExp[] = [
      /role\s*:\s*['"]system['"][\s\S]{0,400}?content\s*:\s*(`[\s\S]{0,600}?`|"(?:[^"\\]|\\.){0,600}")/g,
      /\bsystem\s*:\s*(`[\s\S]{0,600}?`)/g,
      /system_prompt\s*[:=]\s*(?:f?['"`])/g,
      /\bmessages\s*:\s*\[\s*\{\s*role\s*:\s*['"]system['"]/g,
    ];
    for (const regex of patterns) {
      for (const match of ctx.code.matchAll(regex)) {
        const snippet = match[0];
        const interpolated = /\$\{[^}]+\}|['"]\s*\+\s*\w|\+\s*['"]/.test(snippet) || /\.format\(|%\s*\(|f['"]/.test(snippet);
        if (!interpolated) continue;
        if (!UNTRUSTED_SOURCE_REGEX.test(snippet) && !/\b(?:content|chunk|page|document|context|email|html|transcript|scraped|description|input|query|message)\b/.test(snippet)) continue;
        // A delimiter wrapper is the documented mitigation.
        const after = ctx.code.slice(match.index, match.index + snippet.length + 200);
        if (/<\/?[a-z-]+>|<context>|<data>|<documents?>|--\s*end/i.test(after) && /<\/?[a-z-]+>/.test(after)) continue;
        hits.push({
          offset: match.index,
          matched: snippet.slice(0, 140),
          message: 'Untrusted content is interpolated into a system message, so it is read as instructions.',
          data: { sink: 'system-prompt' },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-005/006/007 - webhook signature verification                        */
/* -------------------------------------------------------------------------- */

const stripeWebhookUnverified: Rule = defineRule({
  id: 'VSB-AI-005',
  slug: 'stripe-webhook-unverified',
  title: 'Stripe webhook handled without signature verification',
  category: 'ai-vulnerabilities',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.signatureVerification,
  description:
    'Without `stripe.webhooks.constructEvent`, anyone who learns the URL can POST a forged `checkout.session.completed` and be granted a paid plan for free. The raw request body is required — `req.json()` breaks the signature.',
  insecureExample: 'export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === "checkout.session.completed") upgrade(event.data.object);\n}',
  secureExample: 'const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);',
  remediation: [
    'Read the raw body (`await req.text()` in App Router, `express.raw({ type: "application/json" })` in Express) — never parse it before verifying.',
    'Call `stripe.webhooks.constructEvent(rawBody, signature, webhookSecret)` inside a try/catch and return 400 when it throws.',
    'Read the secret from the environment (`STRIPE_WEBHOOK_SECRET`), never from the request.',
    'Make the handler idempotent: Stripe retries, and a replayed event must not double-apply.',
  ],
  references: [
    'https://docs.stripe.com/webhooks#verify-manually',
    'https://cwe.mitre.org/data/definitions/345.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    // The provider name may appear only in the route path (`app/api/webhooks/stripe`).
    if (!/\bstripe\b/i.test(ctx.relativePath) && !/\bstripe\b/i.test(ctx.code)) return [];
    const isWebhook = /webhook/i.test(ctx.relativePath) || /\bwebhooks?\b/i.test(ctx.code);
    if (!isWebhook) return [];
    if (/constructEvent(?:Async)?\s*\(/.test(ctx.code)) return [];
    if (/(?:supabase|svix|clerk|polar|lemonsqueezy|paddle|github|shopify|slack|twilio|sendgrid)[\w.]*\.(?:verify|constructEvent|webhooks)/i.test(ctx.code)) return [];
    const offset = Math.max(0, ctx.code.search(/\bPOST\b|export\s+default|function\s+handler/i));
    return [
      fileHit(ctx.locate(offset).line, {
        matched: 'stripe webhook',
        message: 'Stripe webhook payloads are trusted without `stripe.webhooks.constructEvent()` — forged events are accepted.',
        data: { provider: 'stripe' },
      }),
    ];
  },
});

const webhookSecretFromRequest: Rule = defineRule({
  id: 'VSB-AI-006',
  slug: 'webhook-secret-from-request',
  title: 'Webhook signing secret read from the request',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.signatureVerification,
  description:
    'A signature check that compares against a secret taken from the same request proves nothing: the attacker sends both halves. Secrets must come from the environment or a secret manager.',
  insecureExample: "const secret = req.headers['x-webhook-secret'];\nif (body.secret === secret) process(body);",
  secureExample: 'const secret = process.env.WEBHOOK_SECRET!;\nif (!timingSafeEqual(body.sig, hmac(secret, raw))) return badRequest();',
  remediation: [
    'Read the signing secret from `process.env` (or your secret manager) only.',
    'Compare signatures with a constant-time function (`crypto.timingSafeEqual`) over the raw body.',
    'Reject requests with a missing or malformed signature header before doing any work.',
  ],
  references: ['https://cwe.mitre.org/data/definitions/345.html'],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    return regexHits(
      ctx.code,
      /\b(?:const|let|var)\s+(?:webhookSecret|signingSecret|signatureSecret|endpointSecret|whsec)\s*=\s*(?:req|request|c|ctx|event)\s*\.\s*(?:headers|body|query)[^\n;]*/gi,
      (match) => ({
        matched: match[0].slice(0, 140),
        message: 'The webhook signing secret is read from the incoming request, which makes the signature check meaningless.',
      }),
    );
  },
});

const webhookUnverifiedGeneric: Rule = defineRule({
  id: 'VSB-AI-007',
  slug: 'webhook-signature-not-verified',
  title: 'Webhook endpoint does not verify the provider signature',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.signatureVerification,
  description:
    'GitHub (`x-hub-signature-256`), Slack, Shopify, Clerk and Svix all sign their deliveries. A handler that parses the body and acts on it without an HMAC comparison accepts forged events from anyone.',
  insecureExample: "export async function POST(req) {\n  const payload = await req.json();\n  await syncUser(payload);\n}",
  secureExample: 'const ok = verifyHmac(await req.text(), sig, process.env.GITHUB_WEBHOOK_SECRET!);\nif (!ok) return new Response(null, { status: 401 });',
  remediation: [
    'Verify the provider\'s signature header against the raw body before parsing it.',
    'Use the provider SDK\'s helper where one exists (`@octokit/webhooks`, `@slack/web-api` verifier, `svix`).',
    'Return 401 for bad signatures and 200 only after the event is durably processed.',
  ],
  references: [
    'https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries',
    'https://docs.svix.com/receiving/verifying-payloads/how',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const provider = /(?:github|slack|shopify|clerk|svix|linear|discord|twilio|resend|sendgrid|hubspot|salesforce)/i.exec(ctx.relativePath) ??
      /(?:x-hub-signature|x-slack-signature|x-shopify-hmac|svix-signature|stripe-signature|x-signature)/i.exec(ctx.code);
    if (!provider) return [];
    if (!/\bwebhook|\/hooks?\//i.test(ctx.relativePath + ctx.code)) return [];
    if (/(?:verify|constructEvent|timingSafeEqual|createHmac|hmac|SignatureVerification|WebhookVerification)/i.test(ctx.code)) return [];
    const offset = Math.max(0, ctx.code.search(/export\s+(?:async\s+)?function\s+POST|export\s+default|app\.post|router\.post/i));
    return [
      fileHit(ctx.locate(offset).line, {
        matched: provider[0],
        message: 'Webhook handler processes the payload without verifying the provider signature.',
        data: { provider: provider[0].toLowerCase() },
      }),
    ];
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-008 - HTML injection / XSS                                          */
/* -------------------------------------------------------------------------- */

const htmlInjection: Rule = defineRule({
  id: 'VSB-AI-008',
  slug: 'html-injection',
  title: 'Untrusted content rendered as raw HTML',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.xss,
  description:
    '`dangerouslySetInnerHTML`, `v-html`, `{@html}`, `innerHTML`, `document.write` and jQuery `.html()` all skip the framework\'s escaping. Rendering user or model output that way is stored XSS with a step counter.',
  insecureExample: '<div dangerouslySetInnerHTML={{ __html: post.body }} />',
  secureExample: '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />',
  remediation: [
    'Render text as text (`{post.body}`) instead of HTML.',
    'If HTML is unavoidable, sanitise with DOMPurify before rendering, and keep the sanitiser on the server where possible.',
    'Add a strict Content-Security-Policy so an injected `<script>` cannot execute.',
    'Sanitise on write *and* on read — legacy rows may already contain a payload.',
  ],
  references: [
    'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html',
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/79.html',
  ],
  extensions: [...APP_EXTENSIONS, 'vue', 'svelte', 'html'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/dangerouslySetInnerHTML|v-html|innerHTML|insertAdjacentHTML|document\.write|\{@html\}|\.html\s*\(/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sinks: Array<{ regex: RegExp; note: string }> = [
      { regex: /\bdangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([\s\S]{0,300}?)\}\s*\}/g, note: '`dangerouslySetInnerHTML` renders unescaped HTML.' },
      { regex: /\bv-html\s*=\s*["']([^"']{1,200})["']/g, note: '`v-html` renders unescaped HTML.' },
      { regex: /\{@html\s+([^}]{1,200})\}/g, note: 'Svelte `{@html}` renders unescaped HTML.' },
      { regex: /\.\s*innerHTML\s*=\s*([^;\n]{1,200})/g, note: 'Assigning to `innerHTML` parses the string as HTML.' },
      { regex: /\binsertAdjacentHTML\s*\(([^;]{1,200})/g, note: '`insertAdjacentHTML` parses the string as HTML.' },
      { regex: /\bdocument\s*\.\s*write(?:ln)?\s*\(([^;]{1,200})/g, note: '`document.write` parses the string as HTML.' },
      { regex: /\$\s*\([^)]{0,80}\)\s*\.\s*html\s*\(\s*([^)]{1,200})/g, note: 'jQuery `.html()` parses the string as HTML.' },
    ];
    for (const sink of sinks) {
      for (const match of ctx.code.matchAll(sink.regex)) {
        const rawValue = match[1] ?? '';
        // `__html: safe` hides the sanitiser one line up, so resolve single-hop
        // aliases and look at the statement that produced them.
        const alias = /^\s*([A-Za-z_$][\w$]*)\s*$/.exec(rawValue);
        let value = rawValue;
        if (alias && alias[1]) {
          const binding = new RegExp(
            `(?:const|let|var)\\s+${alias[1]}\\s*=\\s*([^;\\n]{0,300})`,
          ).exec(ctx.code);
          if (binding && binding[1]) value = `${rawValue} ${binding[1]}`;
        }
        if (!value.trim()) continue;
        if (SANITIZER_REGEX.test(value)) continue;
        if (/^\s*(?:['"`][^$'"{]*['"`]|\{\s*['"`][^$'"{]*['"`]\s*\})\s*$/.test(value)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 160),
          message: sink.note,
          data: { sink: match[0].slice(0, 40) },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-009 - client-side code execution sinks                              */
/* -------------------------------------------------------------------------- */

const clientEval: Rule = defineRule({
  id: 'VSB-AI-009',
  slug: 'dynamic-code-execution',
  title: 'Dynamic code execution in application code',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.codeInjection,
  description:
    '`eval`, `new Function`, string `setTimeout` and `javascript:` URLs execute a string as code. In a browser bundle this is DOM XSS; on the server it is RCE. Almost every use has a safe, boring replacement.',
  insecureExample: 'const value = eval(`(${rule})`);',
  secureExample: 'switch (rule) {\n  case "double": return (n) => n * 2;\n}',
  remediation: [
    'Replace `eval`/`new Function` with a lookup table of real functions.',
    'Pass a function reference to `setTimeout`/`setInterval`, never a string.',
    'Validate `href`/`src` values: only `http:`, `https:` and same-origin relative paths; reject `javascript:` and `data:`.',
    'If dynamic evaluation is a product requirement, run it in a sandboxed worker with no access to cookies or the DOM.',
  ],
  references: [
    'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval',
    'https://cwe.mitre.org/data/definitions/95.html',
  ],
  extensions: [...APP_EXTENSIONS, 'html'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/\beval\s*\(|new\s+Function|setTimeout\s*\(\s*['"`]|javascript:/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/(?<![\w.$])eval\s*\(/g)) {
      const args = callArgs(ctx, match.index);
      if (!looksDynamic(args) && !UNTRUSTED_SOURCE_REGEX.test(args)) continue;
      // The AI-003 rule already reports model output reaching eval.
      if (LLM_REGEX.test(ctx.code) && /(?:completion|choices|\.content|generateText)/.test(args)) continue;
      hits.push({ offset: match.index, matched: 'eval(', message: '`eval()` executes a dynamically built string.', data: { sink: 'eval' } });
    }
    for (const match of ctx.code.matchAll(/\bnew\s+Function\s*\(/g)) {
      hits.push({ offset: match.index, matched: 'new Function(', message: '`new Function()` compiles a string into executable code.', data: { sink: 'Function' } });
    }
    for (const match of ctx.code.matchAll(/\b(?:setTimeout|setInterval)\s*\(\s*(['"`])/g)) {
      hits.push({ offset: match.index, matched: match[0].slice(0, 40), message: 'A string passed to `setTimeout` is evaluated as code.', data: { sink: 'setTimeout-string' } });
    }
    for (const match of ctx.code.matchAll(/\b(?:href|src|action|formAction)\s*[:=]\s*\{?\s*[`'"]\s*javascript:/gi)) {
      hits.push({ offset: match.index, matched: match[0].slice(0, 80), message: 'A `javascript:` URL executes code when clicked.', data: { sink: 'javascript-url' } });
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-010 - open redirect                                                 */
/* -------------------------------------------------------------------------- */

const openRedirect: Rule = defineRule({
  id: 'VSB-AI-010',
  slug: 'open-redirect',
  title: 'Redirect target taken from the request',
  category: 'ai-vulnerabilities',
  severity: 'medium',
  confidence: 'medium',
  cwe: CWES.openRedirect,
  description:
    'Passing a request parameter straight into `redirect()`/`res.redirect()` lets an attacker craft `https://yourapp.com/login?next=https://evil.example` — a perfect phishing link on your own domain. It is also the standard first step of an OAuth token-theft chain.',
  insecureExample: 'return redirect(searchParams.get("next") ?? "/");',
  secureExample: 'const next = searchParams.get("next");\nreturn redirect(next?.startsWith("/") && !next.startsWith("//") ? next : "/");',
  remediation: [
    'Only allow relative paths: reject anything that starts with `//`, `/\\`, or matches `^[a-z]+:` .',
    'Better: map an allow-list of known destinations (`{ dashboard: "/dashboard" }`).',
    'For OAuth flows, keep the post-login target server-side in the session instead of the query string.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/601.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/redirect/i],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const patterns: RegExp[] = [
      /\bredirect\s*\(\s*(?:searchParams|req|request|ctx|params)[^)]{0,120}\)/g,
      /\b(?:res|response|reply)\s*\.\s*redirect\s*\(\s*(?:req|request|ctx)[^)]{0,120}\)/gi,
      /\b(?:res|response)\s*\.\s*(?:writeHead|status)\s*\([^)]{0,40}\{[^}]{0,80}\bLocation\s*:\s*(?:req|request|params|searchParams)/gi,
      /\bNextResponse\s*\.\s*redirect\s*\(\s*(?:new\s+URL\s*\()?\s*(?:req|request|searchParams|params)/g,
    ];
    for (const regex of patterns) {
      for (const match of ctx.code.matchAll(regex)) {
        // A guard on the same or the previous line neutralises it.
        const window = ctx.code.slice(Math.max(0, match.index - 400), match.index + match[0].length + 200);
        if (/startsWith\s*\(\s*['"]\/['"]|isRelativeUrl|allowedRedirect|ALLOWED_REDIRECT|new URL\([^)]*,\s*process\.env|URL\([^)]*\)\.origin\s*===/.test(window)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: 'The redirect target comes from the request without an origin check (open redirect).',
          data: { sink: 'redirect' },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-011 - SSRF                                                          */
/* -------------------------------------------------------------------------- */

const ssrf: Rule = defineRule({
  id: 'VSB-AI-011',
  slug: 'server-side-request-forgery',
  title: 'Outbound request to a caller-supplied URL (SSRF)',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.ssrf,
  description:
    '`fetch(req.body.url)` reaches the cloud metadata endpoint (`169.254.169.254`), internal admin panels and `file://` paths from inside your network. It is the highest-value bug class in AI features that "fetch a URL and summarise it".',
  insecureExample: 'const page = await fetch(req.body.url);',
  secureExample: 'const url = new URL(input);\nif (!["http:", "https:"].includes(url.protocol) || isPrivateHost(url.hostname)) throw new Error("blocked");',
  remediation: [
    'Allow-list the hosts/schemes you will fetch, resolve the hostname and reject private, loopback and link-local ranges.',
    'Block redirects (`redirect: "manual"`) or re-validate the location on each hop.',
    'Never forward the response body verbatim; strip headers and enforce a size limit.',
    'Run fetchers in an egress-restricted network where cloud metadata is unreachable.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/918.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/\bfetch\s*\(/, /axios|got\(|request\(|urllib|httpx|net\/http/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sinks: RegExp[] = [
      /\bfetch\s*\(\s*(?:req|request|ctx|c|event|searchParams|params|query|body)[\w.\[\]'"]*/g,
      /\baxios\s*(?:\.\s*(?:get|post|put|delete|request))?\s*\(\s*(?:req|request|ctx|params|query|body)/g,
      /\b(?:got|superagent|needle|nodeFetch)\s*\(\s*(?:req|request|params|query|body)/g,
      /\brequests\s*\.\s*(?:get|post|put|delete|request)\s*\(\s*(?:request|self\.request|data\[|params\[|body)/g,
      /\burllib\s*\.\s*request\s*\.\s*urlopen\s*\(\s*(?:request|url)/g,
    ];
    for (const regex of sinks) {
      for (const match of ctx.code.matchAll(regex)) {
        const args = callArgs(ctx, match.index);
        const window = ctx.code.slice(Math.max(0, match.index - 500), match.index + args.length + 500);
        if (/allowlist|allowList|ALLOWED_HOSTS|isPrivate(?:Host|Ip|Address)|169\.254|startsWith\s*\(\s*['"]https?:\/\/[a-z0-9.-]+['"]/.test(window)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 140),
          message: 'An outbound request is made to a URL that comes from the caller — SSRF.',
          data: { sink: 'fetch' },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-012 - path traversal                                                */
/* -------------------------------------------------------------------------- */

const pathTraversal: Rule = defineRule({
  id: 'VSB-AI-012',
  slug: 'path-traversal',
  title: 'Filesystem path built from request data',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.pathTraversal,
  description:
    '`path.join(uploadDir, req.query.file)` with `file=../../.env` reads any file the process can see. `path.join` normalises `..` — it does not contain it.',
  insecureExample: 'res.sendFile(path.join(UPLOAD_DIR, req.params.name));',
  secureExample: 'const safe = path.basename(req.params.name);\nif (!/^[\\w.-]+$/.test(safe)) return res.sendStatus(400);\nres.sendFile(path.join(UPLOAD_DIR, safe));',
  remediation: [
    'Reduce the input to a basename (`path.basename`) and validate it against `^[A-Za-z0-9._-]+$`.',
    'Resolve the final path and assert it is still inside the intended root: `resolved.startsWith(rootResolved + path.sep)`.',
    'Prefer opaque ids over filenames: store the object key in the database and look it up server-side.',
    'Serve user content from object storage rather than the local filesystem.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/22.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/readFile|writeFile|sendFile|createReadStream|existsSync|open\s*\(|Path\s*\(/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const sinks: RegExp[] = [
      /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|sendFile|download)\s*\(\s*(?:path\s*\.\s*(?:join|resolve)\s*\(|`|\+\s*)?[^)]{0,160}(?:req|request|ctx|params|query|searchParams|body)[\w.\[\]'"]{0,40}/g,
      /\b(?:open|Path)\s*\(\s*(?:request|params|query|body|filename|file_path)[^)]{0,80}/g,
    ];
    for (const regex of sinks) {
      for (const match of ctx.code.matchAll(regex)) {
        const args = callArgs(ctx, match.index);
        if (/basename\s*\(|normalize\s*\(|startsWith\s*\(|resolve\s*\([^)]*\)\s*\.startsWith/.test(args)) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 150),
          message: 'A filesystem path is built from request-controlled data.',
          data: { sink: 'fs' },
        });
      }
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-013 - unrestricted file upload                                     */
/* -------------------------------------------------------------------------- */

const unrestrictedUpload: Rule = defineRule({
  id: 'VSB-AI-013',
  slug: 'unrestricted-file-upload',
  title: 'File upload accepted with no type, size or destination limits',
  category: 'ai-vulnerabilities',
  severity: 'medium',
  confidence: 'medium',
  cwe: CWES.unrestrictedUpload,
  description:
    'A multer/`formData()` handler with no `limits`, no `fileFilter` and a user-controlled destination stores anything anywhere. HTML/SVG uploads become stored XSS, `.js` uploads become hosting abuse, and an unbounded size is a free disk-exhaustion attack.',
  insecureExample: "const upload = multer({ dest: 'uploads/' });\napp.post('/upload', upload.single('file'), handler);",
  secureExample: "const upload = multer({\n  dest: 'uploads/',\n  limits: { fileSize: 5 * 1024 * 1024, files: 1 },\n  fileFilter: (_r, f, cb) => cb(null, /^image\\/(png|jpeg|webp)$/.test(f.mimetype)),\n});",
  remediation: [
    'Set `limits.fileSize` and `limits.files` on multer (or an equivalent guard on any other parser).',
    'Validate the MIME type *and* the magic bytes, and store under a generated filename with a fixed extension.',
    'Serve uploads from a separate origin or with `Content-Disposition: attachment` plus a strict CSP.',
    'Scan or re-encode images before serving them.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/434.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/multer|formidable|formData\(\)|multipart|busboy|formidable/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/\bmulter\s*\(\s*\{([\s\S]{0,300}?)\}\s*\)/g)) {
      const options = match[1] ?? '';
      if (/\blimits\s*:/.test(options) && /fileSize/.test(options)) continue;
      hits.push({
        offset: match.index,
        matched: match[0].slice(0, 140),
        message: 'Multer is configured without a `limits.fileSize` cap or a `fileFilter`.',
        data: { sink: 'multer' },
      });
    }
    for (const match of ctx.code.matchAll(/\bformidable\s*\(\s*\{([\s\S]{0,300}?)\}\s*\)/g)) {
      const options = match[1] ?? '';
      if (/maxFileSize/.test(options)) continue;
      hits.push({
        offset: match.index,
        matched: match[0].slice(0, 140),
        message: 'Formidable is configured without `maxFileSize`.',
        data: { sink: 'formidable' },
      });
    }
    for (const match of ctx.code.matchAll(/\b(?:await\s+)?(?:req|request)\s*\.\s*formData\s*\(\s*\)/g)) {
      const window = ctx.code.slice(match.index, match.index + 700);
      if (/MAX_(?:SIZE|BYTES)|maxSize|file\.size\s*>|content-length/i.test(window)) continue;
      if (!/\.\s*(?:arrayBuffer|stream|file|put|write)/.test(window)) continue;
      hits.push({
        offset: match.index,
        matched: 'await request.formData()',
        message: 'An uploaded file is persisted with no size or type validation.',
        data: { sink: 'formData' },
      });
    }
    return hits;
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-014 - LLM route without rate limiting                              */
/* -------------------------------------------------------------------------- */

const llmRateLimit: Rule = defineRule({
  id: 'VSB-AI-014',
  slug: 'llm-route-without-rate-limit',
  title: 'LLM endpoint has no rate limit or quota',
  category: 'ai-vulnerabilities',
  severity: 'medium',
  confidence: 'medium',
  cwe: CWES.resourceExhaustion,
  description:
    'A public route that calls a paid model costs real money per request. Without a per-user quota it is a free API for anyone who finds the URL — and one script can run your bill into the thousands before you notice.',
  insecureExample: 'export async function POST(req) {\n  const { messages } = await req.json();\n  return streamText({ model, messages });\n}',
  secureExample: 'const { success } = await ratelimit.limit(userId);\nif (!success) return new Response("Too many requests", { status: 429 });',
  remediation: [
    'Add a per-user (not per-IP) rate limit with `@upstash/ratelimit`, `express-rate-limit` or your platform\'s WAF.',
    'Set a hard `max_tokens` and a request timeout so a single call cannot run away.',
    'Require authentication and check a plan/quota before the provider call.',
    'Alert on spend anomalies at the provider level as a backstop.',
  ],
  references: [
    'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
    'https://cwe.mitre.org/data/definitions/770.html',
  ],
  extensions: APP_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: isPublicEndpoint,
  contentHints: [/openai|anthropic|generateText|streamText|chat\.completions|messages\.create/i],
  detect(ctx) {
    if (!LLM_REGEX.test(ctx.code)) return [];
    if (!/\b(?:completions|generateText|streamText|generateObject|streamObject|messages\.create|invokeModel|chat\.)\b/.test(ctx.code)) return [];
    if (RATE_LIMIT_REGEX.test(ctx.code)) return [];
    if (ctx.project.hasRateLimiting && RATE_LIMIT_REGEX.test(ctx.content)) return [];
    const offset = Math.max(0, ctx.code.search(/\b(?:POST|app\.post|export\s+default)\b/));
    return [
      fileHit(ctx.locate(offset).line, {
        matched: 'LLM endpoint',
        message: 'This endpoint calls a paid model with no rate limit or quota — an open invitation to burn your API budget.',
        data: { sink: 'llm-route' },
      }),
    ];
  },
});

/* -------------------------------------------------------------------------- */
/* VSB-AI-015 - insecure deserialization                                     */
/* -------------------------------------------------------------------------- */

const insecureDeserialization: Rule = defineRule({
  id: 'VSB-AI-015',
  slug: 'insecure-deserialization',
  title: 'Untrusted data deserialized with an unsafe loader',
  category: 'ai-vulnerabilities',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.deserialization,
  description:
    '`pickle.loads`, `yaml.load` without `SafeLoader`, PHP `unserialize` and `node-serialize` all construct arbitrary objects from bytes. When those bytes come from a cookie, body or cache they are a straight path to RCE.',
  insecureExample: 'const cfg = yaml.load(req.body.yaml);',
  secureExample: 'const cfg = yaml.load(req.body.yaml, { schema: yaml.JSON_SCHEMA });',
  remediation: [
    'Use a data-only format: JSON, or `yaml.safeLoad` / `yaml.load(..., { schema: JSON_SCHEMA })`.',
    'In Python use `yaml.safe_load` and never `pickle` on untrusted bytes (JSON or msgpack instead).',
    'In PHP use `json_decode` instead of `unserialize`, or pass `["allowed_classes" => false]`.',
    'If you inherit a serialised format, sign the payload and verify the signature before deserialising.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/502.html',
  ],
  extensions: [...APP_EXTENSIONS],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  contentHints: [/pickle|unserialize|yaml\.|node-serialize|v8\.deserialize|Marshal\.load/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const patterns: Array<{ regex: RegExp; note: string }> = [
      { regex: /\bpickle\s*\.\s*loads?\s*\(/g, note: '`pickle` executes arbitrary code while unpickling.' },
      { regex: /\byaml\s*\.\s*load\s*\(/g, note: '`yaml.load` without `SafeLoader` can instantiate arbitrary objects.' },
      { regex: /\bMarshal\s*\.\s*load\s*\(/g, note: 'Ruby `Marshal.load` on untrusted data is RCE.' },
      { regex: /\bunserialize\s*\(\s*[^)]{0,120}\)/g, note: 'PHP `unserialize` on request data allows object injection.' },
      { regex: /\bnode-serialize\b|\bserialize\s*\.\s*unserialize\s*\(/g, note: '`node-serialize` evaluates functions embedded in the payload.' },
      { regex: /\bv8\s*\.\s*deserialize\s*\(/g, note: '`v8.deserialize` on untrusted bytes is unsafe.' },
    ];
    for (const pattern of patterns) {
      for (const match of ctx.code.matchAll(pattern.regex)) {
        const args = callArgs(ctx, match.index);
        const tainted = UNTRUSTED_SOURCE_REGEX.test(args) || !/safe_load|SafeLoader|JSON_SCHEMA|allowed_classes/.test(ctx.code);
        if (!tainted) continue;
        if (/safe_load|SafeLoader|JSON_SCHEMA/.test(match[0])) continue;
        hits.push({
          offset: match.index,
          matched: match[0].slice(0, 120),
          message: pattern.note,
          data: { sink: match[0].slice(0, 40) },
        });
      }
    }
    return hits;
  },
});

/** A bounded local heuristic: it does not prove the cap is effective or affordable. */
const llmOutputTokenCap: Rule = defineRule({
  id: 'VSB-AI-016',
  slug: 'llm-route-without-output-token-cap',
  title: 'LLM route has no visible fixed output token cap',
  category: 'ai-vulnerabilities',
  severity: 'medium',
  confidence: 'low',
  cwe: CWES.resourceExhaustion,
  description: 'A paid model call without an observable output token cap can amplify the cost of each request. This heuristic only checks recognized calls for a positive numeric literal in the local call arguments; limits configured in shared code or provider settings require manual review.',
  insecureExample: 'await openai.chat.completions.create({ model, messages });',
  secureExample: 'await openai.chat.completions.create({ model, messages, max_completion_tokens: 512 });',
  remediation: [
    'Set a server-controlled output token limit on each model request, using the parameter supported by the model and SDK.',
    'Independently enforce input/context limits, per-user rate and spending quotas, timeouts, and provider budget alerts.',
    'Review shared wrappers, dynamic limits, SDK defaults and provider-side limits manually; this check cannot verify their effectiveness.',
  ],
  references: ['https://cwe.mitre.org/data/definitions/770.html', 'https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
  extensions: ['ts', 'tsx', 'js', 'jsx', 'mts', 'mjs', 'cts', 'cjs'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: isPublicEndpoint,
  contentHints: [/chat\.completions\.create|messages\.create|generateText|streamText|generateObject|streamObject/],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const calls = /\b(?:[\w$]+\.chat\.completions\.create|[\w$]+\.messages\.create|generateText|streamText|generateObject|streamObject)\s*\(/g;
    for (const match of ctx.code.matchAll(calls)) {
      const args = callArgs(ctx, match.index);
      // Numeric literals are a signal, not proof of execution order or a safe budget.
      const cap = /\b(?:max_tokens|max_completion_tokens|maxTokens|maxOutputTokens)\s*:\s*([1-9]\d*)\s*(?=[,}])/i;
      if (cap.test(args)) continue;
      hits.push({ offset: match.index, matched: match[0], message: 'No positive literal output token cap was observed in this model call. Review wrappers, dynamic values and provider-side limits.' });
    }
    return hits;
  },
});

export const AI_VULNERABILITY_RULES: readonly Rule[] = [
  commandInjection,
  toolExecuteSink,
  llmOutputEval,
  promptInjection,
  stripeWebhookUnverified,
  webhookSecretFromRequest,
  webhookUnverifiedGeneric,
  htmlInjection,
  clientEval,
  openRedirect,
  ssrf,
  pathTraversal,
  unrestrictedUpload,
  llmRateLimit,
  insecureDeserialization,
  llmOutputTokenCap,
];
