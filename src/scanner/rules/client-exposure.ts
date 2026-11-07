/**
 * vibe-shield :: client-exposure rules
 * ------------------------------------
 * The single most common way an AI coding agent leaks a production credential
 * is *not* a typo in a test fixture - it is a perfectly reasonable-looking
 * `process.env.NEXT_PUBLIC_OPENAI_API_KEY`. Next.js, Vite, Nuxt, Expo, Gatsby
 * and every other bundler inline those values into the JavaScript the browser
 * downloads, so the "environment variable" is really a hardcoded secret that
 * happens to live in `.env`.
 *
 * These seven rules cover that failure mode end to end: the variable name, the
 * server-only read that a client component still performs, the Supabase
 * service-role client, the admin SDK imported into the browser graph, the
 * "make the SDK work in the browser" escape hatch, the env file that carries a
 * real key, and the `next.config.js` `env` block that re-inlines one.
 */

import {
  PUBLIC_ENV_PREFIXES,
  PUBLIC_SAFE_NAME_SUFFIXES,
  SERVER_ONLY_SECRET_NAMES,
} from '../lexicon';
import { balancedBlock, escapeRegExp, isPlaceholderSecret, shannonEntropy } from '../text';
import { defineRule, fileHit, regexHits } from './helpers';
import { CWES } from './shared';
import type { FileContext, Rule, RuleHit } from '../types';

const PREFIX_SRC = PUBLIC_ENV_PREFIXES.map(escapeRegExp).join('|');
const SECRET_SRC = [...SERVER_ONLY_SECRET_NAMES]
  .slice()
  .sort((a, b) => b.length - a.length)
  .map(escapeRegExp)
  .join('|');

/**
 * Names that contain a "secret-looking" substring but are public by design.
 * `NEXT_PUBLIC_FIREBASE_API_KEY` and the Supabase anon key are the two the
 * ecosystem trips over most often; both are safe to ship to a browser.
 */
const SAFE_PUBLIC_NAME_REGEX = new RegExp(
  [
    ...PUBLIC_SAFE_NAME_SUFFIXES,
    'FIREBASE',
    'ALGOLIA',
    'MAPBOX',
    'GOOGLE_MAPS',
    'MAPS_API_KEY',
    'RECAPTCHA',
    'HCAPTCHA',
    'POSTHOG',
    'SEGMENT',
    'AMPLITUDE',
    'MIXPANEL',
    'SENTRY_DSN',
    'STRIPE_PUBLISHABLE',
    'SANITY',
    'CONTENTFUL',
    'CLOUDINARY_CLOUD_NAME',
    'TURNSTILE',
  ]
    .map(escapeRegExp)
    .join('|'),
  'i',
);

/** `NEXT_PUBLIC_OPENAI_API_KEY`, `VITE_STRIPE_SECRET_KEY`, ... */
const PUBLIC_SECRET_ENV_REGEX = new RegExp(`\\b(?:${PREFIX_SRC})[A-Za-z0-9_]*?(?:${SECRET_SRC})[A-Za-z0-9_]*\\b`, 'gi');

/** The build-time guard that keeps a module out of the client bundle. */
const SERVER_ONLY_GUARD_REGEX = /import\s+['"]server-only['"]|\brequire\(\s*['"]server-only['"]\s*\)/;

const hasPublicPrefix = (name: string): boolean =>
  PUBLIC_ENV_PREFIXES.some((prefix) => name.toUpperCase().startsWith(prefix));

/** Names that read as secrets but are intentionally shipped to browsers. */
const PUBLIC_BY_DESIGN_REGEX = /(?:ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY|SITE_KEY|CLIENT_ID|APP_ID|MEASUREMENT_ID|_URL|_URI|_HOST|_REGION)$/i;

const SERVER_ONLY_NAME_REGEX =
  /(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE_KEY|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|DATABASE_URL|DB_URL|CONNECTION_STRING|WEBHOOK_SECRET|MNEMONIC|SIGNING_KEY)/i;

const isBrowserFile = (ctx: FileContext): boolean => ctx.flags.isClientComponent || ctx.flags.isClientPath;

/**
 * Documentation shows the vulnerable shape on purpose. A rule that fires on
 * README/SKILL fenced blocks punishes the project for documenting the bug it
 * warns about, so examples are excluded from *code* rules.
 */
const isDocumentationExample = (ctx: FileContext): boolean =>
  ctx.language === 'markdown' || ctx.flags.isDocumentation;

/**
 * Same idea for templates shipped as code: `init/scaffold.ts` holds the SKILL.md
 * and AGENTS.md text, which necessarily quotes the vulnerable shapes it teaches
 * the agent to fix. The file is documentation in a .ts container.
 */
const isTemplateMaterial = (ctx: FileContext): boolean =>
  /(?:^|\/)src\/(?:init\/scaffold|mcp-guard\/skill-auditor)\.ts$/.test(ctx.relativePath);

const looksLikeRealSecret = (value: string): boolean => {
  const trimmed = value.trim();
  if (trimmed.length < 16) return false;
  if (isPlaceholderSecret(trimmed)) return false;
  return shannonEntropy(trimmed) >= 3.2;
};

const ENV_LINE_REGEX = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

/** VSB-CLIENT-001 - a server-only secret behind a public env prefix. */
const publicEnvSecret: Rule = defineRule({
  id: 'VSB-CLIENT-001',
  slug: 'public-env-secret-exposure',
  title: 'Server-only secret exposed through a public environment prefix',
  category: 'client-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.exposureOfSecrets,
  description:
    'Variables prefixed with NEXT_PUBLIC_ / VITE_ / PUBLIC_ / REACT_APP_ / EXPO_PUBLIC_ are string-replaced into the client bundle at build time. Naming a service-role key, API secret or database URL that way ships the credential to every visitor.',
  insecureExample: 'const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;',
  secureExample: '// server-only: app/api/chat/route.ts\nconst key = process.env.OPENAI_API_KEY;',
  remediation: [
    'Rename the variable so it is server-only (drop the NEXT_PUBLIC_/VITE_/PUBLIC_ prefix) in `.env`, `.env.local` and every deployment environment.',
    'Move every read of it into a server module: App Router route handler, Server Action, `getServerSideProps`, or an API route. Never import that module from a `"use client"` file.',
    'Rotate the credential. Anything that ever shipped in a bundle must be treated as public - deleting the line does not un-leak it from previous deploys.',
    'Expose only the value the browser genuinely needs (public URL, publishable key) under a name that ends in `_URL`, `_ANON_KEY` or `_PUBLISHABLE_KEY`.',
  ],
  references: [
    'https://nextjs.org/docs/app/building-your-application/configuring/environment-variables',
    'https://vitejs.dev/guide/env-and-mode#env-variables',
    'https://supabase.com/docs/guides/api/api-keys',
  ],
  pathPatterns: [/\.(?:[cm]?[jt]sx?|vue|svelte|json|ya?ml|toml|env|ex|exs|tf|[cm]?js)$|(?:^|\/)\.env/i],
  appliesTo: (ctx) => !isDocumentationExample(ctx) && !isTemplateMaterial(ctx),
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(PUBLIC_SECRET_ENV_REGEX)) {
      const name = match[0];
      if (SAFE_PUBLIC_NAME_REGEX.test(name)) continue;
      if (!SERVER_ONLY_NAME_REGEX.test(name.toUpperCase().replace(PREFIX_SRC.toUpperCase(), ''))) continue;
      hits.push({
        offset: match.index,
        matched: name,
        severity: 'critical',
        confidence: 'high',
        message: `\`${name}\` is inlined into the client bundle; anyone can read it from devtools.`,
        data: { variable: name },
      });
    }
    return hits;
  },
});

/** VSB-CLIENT-002 - server-only env read inside a client component. */
const clientProcessEnv: Rule = defineRule({
  id: 'VSB-CLIENT-002',
  slug: 'server-env-in-client-component',
  title: 'Client component reads a server-only environment variable',
  category: 'client-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.exposureOfSecrets,
  description:
    'A `"use client"` module can only see variables the bundler inlined. Reading `process.env.SOME_SECRET` there either returns `undefined` in production (a broken feature) or, in setups that inline all env vars, exposes the secret to the browser.',
  insecureExample: 'const stripeKey = process.env.STRIPE_SECRET_KEY;',
  secureExample: 'const { publishedKey } = await fetch("/api/stripe/config").then((r) => r.json());',
  remediation: [
    'Delete the client-side read and fetch the value you actually need from a server endpoint that authenticates and authorises the caller.',
    'If the value is genuinely public (publishable key, project URL), expose it under a `NEXT_PUBLIC_*` name instead of reading a server variable.',
    'Keep `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, `DATABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` and friends in server modules only.',
  ],
  references: [
    'https://nextjs.org/docs/app/building-your-application/rendering/client-components',
    'https://react.dev/reference/rsc/use-client',
  ],
  pathPatterns: [/\.(?:[cm]?[jt]sx?|vue|svelte)$/i],
  skipFlags: ['isTestFile', 'isDocumentation', 'isGenerated', 'isLockfile'],
  appliesTo: (ctx) => isBrowserFile(ctx) && !isDocumentationExample(ctx) && !isTemplateMaterial(ctx),
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
      const name = match[1] ?? '';
      if (!name || name === 'NODE_ENV') continue;
      if (hasPublicPrefix(name)) continue;
      if (!SERVER_ONLY_NAME_REGEX.test(name)) continue;
      if (PUBLIC_BY_DESIGN_REGEX.test(name)) continue;
      hits.push({
        offset: match.index,
        matched: match[0],
        message: `Client component reads \`${name}\`, which only exists on the server — it is \`undefined\` in the browser (or leaked if your bundler inlines it).`,
        data: { variable: name },
      });
    }
    return hits;
  },
});

/** VSB-CLIENT-003 - Supabase client constructed with the service-role key. */
const supabaseServiceRoleClient: Rule = defineRule({
  id: 'VSB-CLIENT-003',
  slug: 'supabase-client-with-service-role-key',
  title: 'Supabase client created with the service-role key',
  category: 'client-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.privilegeEscalation,
  description:
    'A Supabase client created with `SUPABASE_SERVICE_ROLE_KEY` bypasses Row Level Security entirely. If the module can reach the browser bundle, an attacker can read and write every row in the database.',
  insecureExample: 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)',
  secureExample: 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)',
  remediation: [
    'Create the privileged client only inside server code (`app/**/route.ts`, Server Actions, cron jobs) in a module that is never imported by a client component.',
    'For anything that runs in the browser, use the anon/publishable key and rely on RLS + policies for authorisation.',
    'Add `import "server-only";` to the top of the admin-client module so the build fails if it is ever pulled into the client graph.',
    'Rotate the service-role key if this file was ever shipped.',
  ],
  references: [
    'https://supabase.com/docs/guides/api/api-keys',
    'https://supabase.com/docs/guides/auth/server-side/creating-a-client',
  ],
  pathPatterns: [/\.(?:[cm]?[jt]sx?|vue|svelte)$/i],
  skipFlags: ['isTestFile', 'isDocumentation', 'isGenerated'],
  detect(ctx) {
    return regexHits(ctx.code, /\b(?:createClient|createBrowserClient|createServerClient|createClientComponentClient|createRouteHandlerClient|createServerActionClient)\s*\(([^)]{0,400})\)/g, (match) => {
      const args = match[1] ?? '';
      if (!/(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|SERVICE_ROLE_KEY|service_role|serviceRoleKey|SERVICE_KEY)/.test(args)) return null;
      // `import "server-only"` is the framework's own guard: the build fails if
      // this module is ever pulled into a client component.
      if (SERVER_ONLY_GUARD_REGEX.test(ctx.code)) return null;
      return {
        matched: match[0].slice(0, 160),
        severity: isBrowserFile(ctx) ? 'critical' : 'critical',
        confidence: 'high',
        message: isBrowserFile(ctx)
          ? 'This file reaches the browser bundle, and the client is built with the RLS-bypassing service-role key.'
          : 'Service-role clients must stay in server-only modules — confirm this file is never imported by a `"use client"` component.',
        data: { privilegedClient: true },
      };
    });
  },
});

/** VSB-CLIENT-004 - admin client imported into browser code. */
const adminClientInClient: Rule = defineRule({
  id: 'VSB-CLIENT-004',
  slug: 'admin-client-in-client-code',
  title: 'Admin/service-role client used in browser code',
  category: 'client-exposure',
  severity: 'critical',
  confidence: 'medium',
  cwe: CWES.privilegeEscalation,
  description:
    '`supabaseAdmin`, `adminClient`, `createServiceRoleClient` and friends execute with elevated privileges. Referencing one from a component, hook or page that ships to the browser hands the attacker the keys to the database.',
  insecureExample: 'const { data } = await supabaseAdmin.from("users").select("*");',
  secureExample: 'const { data } = await supabase.from("users").select("*"); // RLS applies',
  remediation: [
    'Move the privileged call into a server route/action and return only the fields the page needs.',
    'Import the admin client from a module guarded with `import "server-only";`.',
    'Audit the import graph of this file — an admin module imported "just for types" is still bundled unless it is `import type`.',
  ],
  references: ['https://supabase.com/docs/guides/auth/server-side/creating-a-client'],
  pathPatterns: [/\.(?:[cm]?[jt]sx?|vue|svelte)$/i],
  skipFlags: ['isTestFile', 'isDocumentation', 'isGenerated'],
  appliesTo: (ctx) => isBrowserFile(ctx) && !SERVER_ONLY_GUARD_REGEX.test(ctx.code),
  detect(ctx) {
    return regexHits(
      ctx.code,
      /\b(supabaseAdmin|adminClient|serviceRoleClient|serviceRoleSb|createAdminClient|createServiceRoleClient|getServiceRoleClient|getAdminClient|supabaseServiceRole)\b/g,
      (match) => ({
        matched: match[0],
        message: `\`${match[1]}\` is a privileged client referenced from browser code.`,
        data: { identifier: match[1] },
      }),
    );
  },
});

/** VSB-CLIENT-005 - `dangerouslyAllowBrowser` / provider SDK keyed in the browser. */
const browserSdkKey: Rule = defineRule({
  id: 'VSB-CLIENT-005',
  slug: 'provider-sdk-keyed-in-browser',
  title: 'LLM/payment SDK instantiated with a secret key in browser code',
  category: 'client-exposure',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.dangerousFunction,
  description:
    '`dangerouslyAllowBrowser: true` disables the SDK guard that stops API keys reaching the browser. It is almost always paired with a long-lived secret key that the visitor can extract in one line of devtools JavaScript.',
  insecureExample: 'new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true })',
  secureExample: 'await fetch("/api/chat", { method: "POST", body }); // key stays on the server',
  remediation: [
    'Remove `dangerouslyAllowBrowser: true` and call your own authenticated server endpoint instead.',
    'Proxy the provider request from a route handler that enforces session auth, rate limiting and a per-user quota.',
    'Rotate the key — it was readable by anyone with the page open.',
  ],
  references: [
    'https://github.com/openai/openai-node#browser-support',
    'https://platform.openai.com/docs/guides/production-best-practices/api-keys',
  ],
  pathPatterns: [/\.(?:[cm]?[jt]sx?|vue|svelte)$/i],
  skipFlags: ['isTestFile', 'isDocumentation', 'isGenerated'],
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/\bdangerouslyAllowBrowser\s*:\s*(true|!0)\b/g)) {
      hits.push({
        offset: match.index,
        matched: 'dangerouslyAllowBrowser: true',
        message: 'Provider SDK key is exposed to the browser because `dangerouslyAllowBrowser` is enabled.',
        data: { sink: 'dangerouslyAllowBrowser' },
      });
    }
    for (const match of ctx.code.matchAll(/\bnew\s+(?:OpenAI|Anthropic|Groq|MistralClient|CohereClient|GoogleGenerativeAI)\s*\(/g)) {
      if (!isBrowserFile(ctx)) continue;
      const body = balancedBlock(ctx.code, ctx.code.indexOf('(', match.index), '(', ')');
      if (!/apiKey\s*:/.test(body)) continue;
      hits.push({
        offset: match.index,
        matched: match[0],
        message: 'A provider SDK is constructed with an API key inside browser code.',
        data: { sink: 'provider-sdk' },
      });
    }
    return hits;
  },
});

/** VSB-CLIENT-006 - real secret stored behind a public prefix in an env file. */
const envFilePublicSecret: Rule = defineRule({
  id: 'VSB-CLIENT-006',
  slug: 'env-file-public-secret-value',
  title: 'Env file assigns a real secret to a public variable',
  category: 'client-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.credentialLeak,
  description:
    'A `.env*` file declares a browser-visible variable whose value looks like a live credential. Everything behind a public prefix is published to every visitor at build time, so this is equivalent to committing the key to the README.',
  insecureExample: 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  secureExample: 'SUPABASE_SERVICE_ROLE_KEY=<server-only value>\nNEXT_PUBLIC_SUPABASE_URL=https://project.supabase.co',
  remediation: [
    'Rename the variable to drop the public prefix, or delete it if the browser does not need it.',
    'Rotate the credential and purge it from build logs, CDN caches and any artifact that already shipped.',
    'Add a unit test or CI check that fails when a public env var name matches `SECRET|SERVICE_ROLE|PASSWORD|PRIVATE`.',
  ],
  references: [
    'https://nextjs.org/docs/pages/building-your-application/configuring/environment-variables',
    'https://cwe.mitre.org/data/definitions/540.html',
  ],
  appliesTo: (ctx) => ctx.flags.isEnvFile,
  detect(ctx) {
    if (/(?:example|sample|template|dist|schema)$/i.test(ctx.fileName)) return [];
    const hits: RuleHit[] = [];
    ctx.lines.forEach((line, index) => {
      const match = ENV_LINE_REGEX.exec(line);
      if (!match) return;
      const [, name = '', rawValue = ''] = match;
      if (!hasPublicPrefix(name)) return;
      if (SAFE_PUBLIC_NAME_REGEX.test(name)) return;
      if (!SERVER_ONLY_NAME_REGEX.test(name.toUpperCase().slice(name.indexOf('_') + 1))) return;
      const value = rawValue.trim().replace(/^['"]|['"]$/g, '');
      if (!looksLikeRealSecret(value)) return;
      hits.push(
        fileHit(index + 1, {
          matched: name,
          severity: 'critical',
          confidence: 'high',
          message: `\`${name}\` is published to the browser and is set to what looks like a live credential.`,
          data: { variable: name },
        }),
      );
    });
    return hits;
  },
});

/** VSB-CLIENT-007 - secret literal inlined through a bundler config. */
const bundlerConfigInline: Rule = defineRule({
  id: 'VSB-CLIENT-007',
  slug: 'bundler-config-inlines-secret',
  title: 'Build config inlines a secret into the client bundle',
  category: 'client-exposure',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.hardcodedCredentials,
  description:
    '`next.config.js` `env`, `publicRuntimeConfig` and Vite `define` copy their values into the browser bundle verbatim, regardless of the variable name. A literal key here is a hardcoded credential in every build artifact.',
  insecureExample: "module.exports = { env: { STRIPE_SECRET_KEY: 'sk_live_51...' } };",
  secureExample: "module.exports = {}; // secrets are read at runtime from process.env on the server",
  remediation: [
    'Remove the secret from the config file and read it at runtime inside a server module.',
    'If a value must reach the browser, expose the *publishable* counterpart only.',
    'Rotate the key: the previous build artifacts keep shipping it forever.',
  ],
  references: [
    'https://nextjs.org/docs/pages/api-reference/next-config-js/env',
    'https://nextjs.org/docs/pages/api-reference/next-config-js/runtime-configuration',
    'https://vitejs.dev/config/shared-options#define',
  ],
  pathPatterns: [/(?:^|\/)(?:next|nuxt|vite|astro|svelte|webpack|rollup|rsbuild|rslib|expo)\.config\.[cm]?[jt]s$/i],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const blocks: Array<{ start: number; source: string }> = [];
    for (const marker of [/env\s*:\s*\{/g, /publicRuntimeConfig\s*:\s*\{/g, /define\s*:\s*\{/g]) {
      for (const match of ctx.code.matchAll(marker)) {
        const open = ctx.code.indexOf('{', match.index);
        blocks.push({ start: match.index, source: balancedBlock(ctx.code, open, '{', '}') });
      }
    }
    for (const block of blocks) {
      for (const entry of block.source.matchAll(/['"`]?([A-Za-z_][A-Za-z0-9_.]*)['"`]?\s*:\s*(['"`])([^'"`\n]{8,})(\2)/g)) {
        const [, name = '', , value = ''] = entry;
        const serverOnlyName = SERVER_ONLY_NAME_REGEX.test(name.toUpperCase());
        const looksLive = looksLikeRealSecret(value) || /^(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/.test(value) || /^gh[pousr]_[A-Za-z0-9]{20,}/.test(value);
        if (!serverOnlyName && !looksLive) continue;
        hits.push({
          offset: block.start,
          matched: `${name}: '${value.slice(0, 6)}…'`,
          message: `\`${name}\` is a hardcoded credential inlined into the client bundle by the build config.`,
          data: { variable: name },
        });
      }
    }
    return hits;
  },
});

export const CLIENT_EXPOSURE_RULES: readonly Rule[] = [
  publicEnvSecret,
  clientProcessEnv,
  supabaseServiceRoleClient,
  adminClientInClient,
  browserSdkKey,
  envFilePublicSecret,
  bundlerConfigInline,
];
