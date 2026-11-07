/**
 * vibe-shield :: unguarded-routes rules
 * -------------------------------------
 * The second great AI failure mode: an endpoint that does exactly what it was
 * asked to do, with no check on *who* is asking. An agent asked to "add a
 * delete endpoint" happily writes `export async function DELETE(req)` with no
 * session lookup at all, and a route that deletes by `req.body.id` is a
 * one-request account takeover.
 *
 * Nine rules cover the space: App Router handlers, Pages Router handlers,
 * Express/Fastify/Koa/Hono routes, object-level authorisation (IDOR), Server
 * Actions, identity taken from an unverified source, admin surfaces without a
 * role check, auth that is fetched but never enforced, and cookie-session CSRF.
 */

import {
  AUTH_VERIFICATION_REGEX,
  MUTATION_REGEX,
  OWNERSHIP_KEY_REGEX,
  ROLE_CHECK_REGEX,
  ROUTE_AUTH_MIDDLEWARE_REGEX,
  SESSION_OWNERSHIP_REGEX,
  UNTRUSTED_SOURCE_REGEX,
} from '../lexicon';
import { balancedBlock, escapeRegExp } from '../text';
import { defineRule, fileHit } from './helpers';
import { CWES, LOGIC_SKIP_FLAGS, verifiesAuth } from './shared';
import type { FileContext, Rule, RuleHit } from '../types';

const JS_ROUTE_EXTENSIONS = ['ts', 'tsx', 'js', 'jsx', 'mts', 'mjs', 'cts', 'cjs'];

/** Next.js App Router verb exports. */
const APP_ROUTER_VERB_REGEX =
  /export\s+(?:async\s+)?(?:function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|const\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*[:=])/g;

const MUTATING_VERBS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Extract `{ verb, offset, body }` for every HTTP handler in an App Router file. */
function appRouterHandlers(ctx: FileContext): Array<{ verb: string; offset: number; body: string }> {
  const handlers: Array<{ verb: string; offset: number; body: string }> = [];
  for (const match of ctx.code.matchAll(APP_ROUTER_VERB_REGEX)) {
    const verb = (match[1] ?? match[2] ?? '').toUpperCase();
    const open = ctx.code.indexOf('{', match.index);
    const body = open === -1 ? '' : balancedBlock(ctx.code, open, '{', '}');
    handlers.push({ verb, offset: match.index, body });
  }
  return handlers;
}

/** Express/Fastify/Koa/Hono route registrations, with the handler body. */
function serverFrameworkHandlers(ctx: FileContext): Array<{ verb: string; offset: number; body: string; path: string }> {
  const out: Array<{ verb: string; offset: number; body: string; path: string }> = [];
  const regex =
    /\b(?:app|router|server|fastify|api|routes?|hono|route)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]{0,200})\2/g;
  for (const match of ctx.code.matchAll(regex)) {
    const verb = (match[1] ?? '').toLowerCase();
    if (!['post', 'put', 'patch', 'delete', 'all'].includes(verb)) continue;
    const open = ctx.code.indexOf('(', match.index);
    // The whole argument list of the registration, not just the path.
    const body = balancedBlock(ctx.code, open, '(', ')');
    out.push({ verb, offset: match.index, body, path: match[3] ?? '' });
  }
  return out;
}

const ADMIN_PATH_REGEX = /\b(?:admin|superuser|internal|backoffice|manage|staff|root|ops)(?:\b|\/|_|-)/i;
const DESTRUCTIVE_CODE_REGEX =
  /\b(?:\.delete\(|\.deleteMany\(|\.destroy\(|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE|deleteUser|removeUser|refund|payout|transferFunds|impersonate|setRole|updateRole|grantAdmin|disableMfa|resetPassword)\b/i;

/** VSB-AUTH-001 - App Router mutation handler with no auth check. */
const appRouterMutationNoAuth: Rule = defineRule({
  id: 'VSB-AUTH-001',
  slug: 'app-router-mutation-without-auth',
  title: 'Next.js App Router mutation handler has no authentication check',
  category: 'unguarded-routes',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.missingAuth,
  description:
    'A `POST`/`PUT`/`PATCH`/`DELETE` handler under `app/**/route.ts` runs on the public internet. Without a session lookup (`auth()`, `getServerSession`, `currentUser`) plus an authorisation check, anyone who guesses the URL can mutate your database.',
  insecureExample: 'export async function DELETE(req: Request) {\n  const { id } = await req.json();\n  await db.users.delete({ where: { id } });\n}',
  secureExample: 'export async function DELETE(req: Request) {\n  const session = await auth();\n  if (!session?.user) return new Response("Unauthorized", { status: 401 });\n  ...\n}',
  remediation: [
    'Call your auth helper (`auth()`, `getServerSession`, `currentUser`, Clerk `auth()`) at the top of the handler and return 401 when there is no session.',
    'Authorise the action, not just the request: verify the caller owns (or has an explicit role for) the resource identified in the body or URL.',
    'Validate the request body with a schema (zod/valibot) before it reaches the database.',
    'If the endpoint really must be public, gate it with a shared secret header comparison or a signed token and document why.',
  ],
  references: [
    'https://nextjs.org/docs/app/building-your-application/routing/route-handlers',
    'https://cwe.mitre.org/data/definitions/306.html',
    'https://nextjs.org/docs/app/building-your-application/authentication',
  ],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isAppRouterRoute,
  detect(ctx) {
    if (ctx.project.hasGlobalAuthMiddleware && ctx.project.authMiddlewareMatchers.length === 0) return [];
    const hits: RuleHit[] = [];
    for (const handler of appRouterHandlers(ctx)) {
      if (!MUTATING_VERBS.has(handler.verb)) continue;
      if (AUTH_VERIFICATION_REGEX.test(handler.body)) continue;
      if (ROUTE_AUTH_MIDDLEWARE_REGEX.test(handler.body)) continue;
      // A webhook endpoint is authenticated by its signature, not a session.
      if (/\b(?:webhook|stripe|svix|github|clerk|lemonsqueezy|paddle)\b/i.test(ctx.relativePath) && /constructEvent|verifyWebhook|verifySignature|webhooks?\.|timingSafeEqual/i.test(handler.body)) continue;
      hits.push({
        offset: handler.offset,
        matched: `export async function ${handler.verb}`,
        message: `\`${handler.verb}\` handler has no session check — the endpoint is open to anonymous callers.`,
        data: { verb: handler.verb },
      });
    }
    return hits;
  },
});

/** VSB-AUTH-002 - Pages Router API mutation without auth. */
const pagesApiMutationNoAuth: Rule = defineRule({
  id: 'VSB-AUTH-002',
  slug: 'pages-api-mutation-without-auth',
  title: 'Next.js Pages API mutation handler has no authentication check',
  category: 'unguarded-routes',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.missingAuth,
  description:
    'A `pages/api/**` handler that branches on `req.method === "POST"` and mutates state without calling `getSession`/`getServerSession`/`req.auth` is publicly writable.',
  insecureExample: 'export default async function handler(req, res) {\n  if (req.method === "POST") await db.update(...);\n}',
  secureExample: 'export default async function handler(req, res) {\n  const session = await getServerSession(req, res, authOptions);\n  if (!session) return res.status(401).json({ error: "Unauthorized" });\n  ...\n}',
  remediation: [
    'Call `getServerSession(req, res, authOptions)` (or your provider equivalent) before any mutation and return 401 when absent.',
    'Reject methods you do not implement explicitly instead of falling through to a default branch.',
    'Authorise the concrete record: compare the session user id against the row owner, do not trust `req.body.userId`.',
  ],
  references: [
    'https://nextjs.org/docs/pages/building-your-application/routing/api-routes',
    'https://cwe.mitre.org/data/definitions/306.html',
  ],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isPagesApiRoute,
  detect(ctx) {
    if (!/req\.method|request\.method|method\s*===|method\s*==/.test(ctx.code)) return [];
    if (!MUTATION_REGEX.test(ctx.code)) return [];
    if (AUTH_VERIFICATION_REGEX.test(ctx.code)) return [];
    if (ctx.project.hasGlobalAuthMiddleware && ctx.project.authMiddlewareMatchers.length === 0) return [];
    const offset = ctx.code.search(/req\.method|request\.method/);
    return [
      fileHit(ctx.locate(offset === -1 ? 0 : offset).line, {
        matched: 'req.method',
        message: 'Pages API handler branches on the HTTP method and mutates state, but never resolves a session.',
      }),
    ];
  },
});

/** VSB-AUTH-003 - Express-family mutation route with no auth middleware. */
const serverRouteNoAuth: Rule = defineRule({
  id: 'VSB-AUTH-003',
  slug: 'server-route-mutation-without-auth',
  title: 'Mutation route registered without auth middleware',
  category: 'unguarded-routes',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.missingAuthz,
  description:
    'An Express/Fastify/Koa/Hono route mutates state but its middleware chain contains neither an auth guard nor an in-handler session check. Middleware is the *only* thing between the public internet and the handler.',
  insecureExample: "app.post('/api/users/:id', async (req, res) => { await db.users.update(...) })",
  secureExample: "app.post('/api/users/:id', requireAuth, async (req, res) => { ... })",
  remediation: [
    'Add your auth middleware to the route: `app.post(path, requireAuth, handler)` — or call the session helper inside the handler before touching data.',
    'For role-gated operations add a second guard (`requireAdmin`) after authentication.',
    'Prefer mounting the guard on the router (`router.use(requireAuth)`) so new routes cannot forget it.',
  ],
  references: [
    'https://expressjs.com/en/guide/using-middleware.html',
    'https://cwe.mitre.org/data/definitions/862.html',
  ],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isServerFrameworkFile,
  detect(ctx) {
    const hits: RuleHit[] = [];
    const routerGuarded = /\b(?:app|router|server|fastify|api)\s*\.\s*(?:use|register|addHook)\s*\(\s*[^)]{0,120}(?:requireAuth|isAuthenticated|authenticate|authMiddleware|authGuard|verifyToken|ensureAuth|jwt\(|passport\.authenticate)/i.test(ctx.code);
    if (routerGuarded) return [];
    for (const handler of serverFrameworkHandlers(ctx)) {
      if (AUTH_VERIFICATION_REGEX.test(handler.body)) continue;
      if (ROUTE_AUTH_MIDDLEWARE_REGEX.test(handler.body)) continue;
      if (!MUTATION_REGEX.test(handler.body)) continue;
      // Public-by-design endpoints: login/register/webhook/health/metrics.
      if (/\/(?:login|signin|sign-in|signup|sign-up|register|auth|oauth|callback|webhook|health|healthz|ping|metrics|public)(?:\/|['"`]|$)/i.test(handler.path)) continue;
      hits.push({
        offset: handler.offset,
        matched: handler.body.slice(0, 120).trim(),
        message: `\`${handler.verb.toUpperCase()} ${handler.path || '/'}\` mutates state with no auth middleware and no session check.`,
        data: { verb: handler.verb.toUpperCase(), route: handler.path },
      });
    }
    return hits;
  },
});

/** VSB-AUTH-004 - IDOR: ownership key taken from the request. */
const idorOwnershipFromRequest: Rule = defineRule({
  id: 'VSB-AUTH-004',
  slug: 'idor-ownership-from-request',
  title: 'Record ownership taken from the request instead of the session (IDOR)',
  category: 'unguarded-routes',
  severity: 'critical',
  confidence: 'medium',
  cwe: CWES.idor,
  description:
    'When `userId`/`tenantId`/`accountId` comes from the body, query string or headers, the caller decides whose data they touch. This is the classic Insecure Direct Object Reference: change one field and you are operating inside someone else\'s account.',
  insecureExample: 'await db.orders.delete({ where: { id: req.body.id, userId: req.body.userId } })',
  secureExample: 'const session = await auth();\nawait db.orders.delete({ where: { id, userId: session.user.id } })',
  remediation: [
    'Derive the owner from the verified session (`session.user.id`, `auth().userId`, `req.user.id`) — never from request input.',
    'Add the ownership predicate to the database query itself (`where: { id, userId: session.user.id }`) so a wrong id is a no-op rather than a leak.',
    'Do not accept `userId` in the request body at all; validate the schema with `.strict()` so extra fields are rejected.',
    'Return 404 (not 403) for records the caller cannot see, to avoid an enumeration oracle.',
  ],
  references: [
    'https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control',
    'https://cwe.mitre.org/data/definitions/639.html',
  ],
  extensions: [...JS_ROUTE_EXTENSIONS, 'php', 'py', 'rb', 'go'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    if (!ctx.flags.mentionsMutation) return [];
    const hits: RuleHit[] = [];
    const ownershipNames = OWNERSHIP_KEY_REGEX.source.replace(/^\\b\(|\)\\b$/g, '');

    // 1. Direct read: `req.body.userId`, `searchParams.get("tenantId")`, ...
    const direct = new RegExp(
      `(?:${UNTRUSTED_SOURCE_REGEX.source})[^\\n;]{0,40}\\b(${ownershipNames})\\b`,
      'gi',
    );
    for (const match of ctx.code.matchAll(direct)) {
      const key = match[1] ?? '';
      const line = ctx.lines[ctx.locate(match.index).line - 1] ?? '';
      if (SESSION_OWNERSHIP_REGEX.test(line)) continue;
      if (!/(?:where|filter|eq\(|match|delete|update|select|findFirst|findUnique|findOne|destroy|remove|insert|create)/i.test(line) && !ctx.flags.mentionsMutation) continue;
      hits.push({
        offset: match.index,
        matched: match[0].slice(0, 120),
        message: `\`${key}\` is read from the request and used for an ownership decision.`,
        data: { key },
      });
    }

    // 2. Indirect: `const { userId } = await req.json()` then `where: { userId }`.
    //    This is the shape agents actually write, so resolving the local binding
    //    is the difference between catching IDOR and catching nothing.
    const taintedVars = new Map<string, string>();
    const destructure = new RegExp(
      `const\\s*\\{([^}]{1,200})\\}\\s*=\\s*(?:await\\s+)?(?:${UNTRUSTED_SOURCE_REGEX.source})`,
      'gi',
    );
    for (const match of ctx.code.matchAll(destructure)) {
      for (const field of (match[1] ?? '').split(',')) {
        const name = field.split(':').pop()?.split('=')[0]?.trim() ?? '';
        if (!name || !OWNERSHIP_KEY_REGEX.test(name)) continue;
        taintedVars.set(name, name);
      }
    }
    for (const match of ctx.code.matchAll(
      /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,120})/g,
    )) {
      const name = match[1] ?? '';
      const value = match[2] ?? '';
      if (!OWNERSHIP_KEY_REGEX.test(name)) continue;
      if (!UNTRUSTED_SOURCE_REGEX.test(value)) continue;
      taintedVars.set(name, name);
    }
    for (const [variable, key] of taintedVars) {
      const usage = new RegExp(
        `(?:where|filter|eq\(|match|delete|update|select|findFirst|findUnique|findOne|destroy|remove|insert|create)[^\\n;]{0,80}\\b${escapeRegExp(variable)}\\b|\\b${escapeRegExp(variable)}\\b[^\\n;]{0,40}(?:where|filter)`,
        'i',
      );
      const hit = usage.exec(ctx.code);
      if (!hit) continue;
      const line = ctx.lines[ctx.locate(hit.index).line - 1] ?? '';
      if (SESSION_OWNERSHIP_REGEX.test(line)) continue;
      hits.push({
        offset: hit.index,
        matched: line.trim().slice(0, 120),
        message: `\`${key}\` is taken from the request body and used as the ownership predicate — any caller can address another user's record.`,
        data: { key, variable },
      });
    }
    return hits;
  },
});

/** VSB-AUTH-005 - Server Action mutating without auth. */
const serverActionNoAuth: Rule = defineRule({
  id: 'VSB-AUTH-005',
  slug: 'server-action-without-auth',
  title: 'Next.js Server Action mutates data without authentication',
  category: 'unguarded-routes',
  severity: 'high',
  confidence: 'high',
  cwe: CWES.missingAuth,
  description:
    'A `"use server"` module compiles to a publicly reachable RPC endpoint. The "it is only called from my own component" assumption is false: the action id is in the client bundle and can be invoked directly.',
  insecureExample: '"use server";\nexport async function deleteAccount(id: string) { await db.users.delete({ where: { id } }); }',
  secureExample: '"use server";\nexport async function deleteAccount(id: string) {\n  const session = await auth();\n  if (!session?.user) throw new Error("Unauthorized");\n  ...\n}',
  remediation: [
    'Resolve the session at the top of every Server Action that mutates data, and throw/return early when it is missing.',
    'Check that the session user may act on the argument (ownership or role) — the argument is attacker-controlled.',
    'Validate every argument with a schema; Server Action arguments are serialised from the client and are not trusted input.',
    'Add `import "server-only";` to modules that must never be imported by a client component.',
  ],
  references: [
    'https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#security',
    'https://cwe.mitre.org/data/definitions/306.html',
  ],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isServerActionModule,
  detect(ctx) {
    const hits: RuleHit[] = [];
    for (const match of ctx.code.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g)) {
      const open = ctx.code.indexOf('{', match.index + match[0].length);
      const body = open === -1 ? '' : balancedBlock(ctx.code, open, '{', '}');
      if (!MUTATION_REGEX.test(body)) continue;
      if (AUTH_VERIFICATION_REGEX.test(body)) continue;
      hits.push({
        offset: match.index,
        matched: match[0].trim(),
        message: `Server Action \`${match[1]}\` mutates data without checking the session.`,
        data: { action: match[1] },
      });
    }
    return hits;
  },
});

/** VSB-AUTH-006 - identity accepted from an unverified source. */
const unverifiedIdentity: Rule = defineRule({
  id: 'VSB-AUTH-006',
  slug: 'unverified-identity-source',
  title: 'Identity derived from an unverified token, header or decode() call',
  category: 'unguarded-routes',
  severity: 'critical',
  confidence: 'high',
  cwe: CWES.improperCertValidation,
  description:
    '`jwt.decode()` does not verify the signature, `atob(token.split(".")[1])` is just base64 decoding, and `x-user-id` is a header the caller writes. Any of these used as the identity is a full authentication bypass.',
  insecureExample: 'const { sub } = jwt.decode(req.headers.authorization);\nreq.user = { id: sub };',
  secureExample: 'const { sub } = await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET));\nreq.user = { id: sub };',
  remediation: [
    'Replace `jwt.decode` with a verifying call: `jwtVerify` (jose), `jwt.verify` with an explicit algorithm allow-list, or your auth framework\'s session helper.',
    'Never accept identity from `x-user-id`, `x-forwarded-user` or any custom header unless a trusted proxy sets it *and* strips client-supplied values.',
    'Remove `verify: false` and `algorithms: ["none"]` — both disable signature checking by construction.',
    'Derive the identity from a session cookie or a verified signature only.',
  ],
  references: [
    'https://github.com/panva/jose/blob/main/docs/functions/jwt_verify.jwtVerify.md',
    'https://cwe.mitre.org/data/definitions/347.html',
    'https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/',
  ],
  extensions: [...JS_ROUTE_EXTENSIONS, 'php', 'py'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const hits: RuleHit[] = [];
    const patterns: Array<{ regex: RegExp; note: string }> = [
      { regex: /\bjwt\s*\.\s*decode\s*\(/g, note: '`jwt.decode()` parses the payload without verifying the signature.' },
      { regex: /\batob\s*\(\s*[^)]*split\s*\(\s*['"]\.['"]/g, note: 'Base64-decoding the JWT payload is not verification.' },
      { regex: /\b(?:req|request)\.headers(?:\.|\[)\s*['"`]?x-(?:user|auth|forwarded-user|uid|user-id|account-id|tenant-id|admin)['"`]?/gi, note: 'A request header is attacker-controlled; it cannot establish identity.' },
      { regex: /\bverify\s*:\s*false\b/g, note: '`verify: false` disables signature validation.' },
      { regex: /algorithms\s*:\s*\[\s*['"`]none['"`]/gi, note: 'The `none` algorithm accepts unsigned tokens.' },
      { regex: /\bbase64url?Decode\s*\(\s*[^)]*token/gi, note: 'Decoding a token is not verifying it.' },
    ];
    for (const pattern of patterns) {
      for (const match of ctx.code.matchAll(pattern.regex)) {
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

/** VSB-AUTH-007 - admin/destructive surface with no role check. */
const adminWithoutRoleCheck: Rule = defineRule({
  id: 'VSB-AUTH-007',
  slug: 'admin-route-without-role-check',
  title: 'Administrative or destructive endpoint has no role check',
  category: 'unguarded-routes',
  severity: 'high',
  confidence: 'medium',
  cwe: CWES.incorrectAuthz,
  description:
    'An admin-only or destructive operation that authenticates the caller but never checks a role lets any signed-in user — including one who self-registered a minute ago — perform it.',
  insecureExample: 'export async function POST() {\n  const session = await auth();\n  if (!session) return unauthorized();\n  await db.users.deleteMany({});\n}',
  secureExample: 'if (session.user.role !== "admin") return forbidden();',
  remediation: [
    'Add an explicit role/permission assertion after authentication: `requireRole("admin")`, `if (!user.isAdmin) return forbidden()`, or a CASL/authorisation-policy check.',
    'Do not rely on hiding the UI — the endpoint is public regardless of which button renders it.',
    'Log privileged operations with the acting user id for auditability.',
  ],
  references: [
    'https://cwe.mitre.org/data/definitions/863.html',
    'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html',
  ],
  extensions: [...JS_ROUTE_EXTENSIONS, 'php', 'py', 'rb', 'go'],
  skipFlags: [...LOGIC_SKIP_FLAGS],
  detect(ctx) {
    const privilegedPath = ADMIN_PATH_REGEX.test(ctx.relativePath);
    const destructive = DESTRUCTIVE_CODE_REGEX.test(ctx.code);
    if (!privilegedPath && !destructive) return [];
    if (!ctx.flags.mentionsAuth) return [];
    if (ROLE_CHECK_REGEX.test(ctx.code)) return [];
    if (!verifiesAuth(ctx)) return [];
    // Ownership checks are a different (also valid) authorisation model.
    if (SESSION_OWNERSHIP_REGEX.test(ctx.code) && !privilegedPath) return [];
    const offset = ctx.code.search(AUTH_VERIFICATION_REGEX);
    return [
      fileHit(ctx.locate(offset === -1 ? 0 : offset).line, {
        matched: privilegedPath ? 'admin route' : 'destructive operation',
        message: privilegedPath
          ? 'Admin surface authenticates the caller but never verifies an admin role.'
          : 'Destructive operation authenticates the caller but performs no role or ownership check.',
        severity: 'high',
        confidence: privilegedPath ? 'high' : 'medium',
      }),
    ];
  },
});

/** VSB-AUTH-008 - auth result fetched but discarded. */
const authUnused: Rule = defineRule({
  id: 'VSB-AUTH-008',
  slug: 'auth-fetched-but-not-enforced',
  title: 'Session is fetched but the result is never enforced',
  category: 'unguarded-routes',
  severity: 'medium',
  confidence: 'medium',
  cwe: CWES.improperAuthn,
  description:
    '`const session = await auth();` followed by no branch on `session` is dead code that *looks* like security. Reviewers and agents both move on assuming the route is protected.',
  insecureExample: 'const session = await auth();\nawait db.projects.create({ data: req.body });',
  secureExample: 'const session = await auth();\nif (!session?.user) return new Response("Unauthorized", { status: 401 });',
  remediation: [
    'Branch on the session: `if (!session?.user) return new Response("Unauthorized", { status: 401 })`.',
    'If the endpoint is intentionally public, delete the session lookup so nobody mistakes it for a guard.',
  ],
  references: ['https://cwe.mitre.org/data/definitions/287.html'],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isAppRouterRoute || ctx.flags.isServerActionModule || ctx.flags.isPagesApiRoute,
  detect(ctx) {
    const hits: RuleHit[] = [];
    const assignment =
      /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:auth|getServerSession|getSession|currentUser|getCurrentUser|requireUser|getAuth)\s*\(([^)]*)\)\s*;?/g;
    for (const match of ctx.code.matchAll(assignment)) {
      const name = match[1] ?? '';
      if (!name) continue;
      const rest = ctx.code.slice(match.index + match[0].length);
      const enforced = new RegExp(
        `\\b(?:if\\s*\\(\\s*!?\\s*${name}\\b|!\\s*${name}\\s*[).]|${name}\\s*(?:\\?\\.|\\.)\\s*(?:user|userId|id|session|sub)\\b|${name}\\s*&&|return\\s+${name}\\b|throw\\b[^;]{0,80}${name})`,
      );
      if (enforced.test(rest.slice(0, 2000))) continue;
      // `auth()` used purely to satisfy a redirect() helper still counts.
      if (new RegExp(`redirect\\(`).test(rest.slice(0, 2000)) && new RegExp(`${name}\\s*\\?\\.`).test(rest.slice(0, 2000))) continue;
      hits.push({
        offset: match.index,
        matched: match[0].trim().slice(0, 120),
        message: `\`${name}\` is captured from the auth helper but never checked — the route is effectively public.`,
        data: { variable: name },
      });
    }
    return hits;
  },
});

/** VSB-AUTH-009 - cookie-session mutation without CSRF protection. */
const missingCsrf: Rule = defineRule({
  id: 'VSB-AUTH-009',
  slug: 'cookie-session-mutation-without-csrf',
  title: 'Cookie-authenticated mutation has no CSRF protection',
  category: 'unguarded-routes',
  severity: 'medium',
  confidence: 'low',
  cwe: CWES.csrf,
  description:
    'A mutation endpoint authenticated by a cookie accepts cross-site form posts by default. If the session cookie is `SameSite=None` (or the project sets none), a malicious page can trigger the mutation on behalf of a signed-in user.',
  insecureExample: "app.post('/api/transfer', requireAuth, handler) // no csrf middleware",
  secureExample: "app.post('/api/transfer', requireAuth, csrfProtection, handler)",
  remediation: [
    'Mount CSRF middleware (`csurf`, `csrf-csrf`, `@fastify/csrf-protection`) on cookie-authenticated mutating routes.',
    'Set the session cookie to `SameSite=Lax` or `Strict`; use `SameSite=None; Secure` only when a cross-site flow truly requires it.',
    'Require a custom header (`X-Requested-With`) or a double-submit token for state-changing requests.',
    'Prefer bearer tokens in `Authorization` for machine clients — they are not sent automatically.',
  ],
  references: [
    'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
    'https://cwe.mitre.org/data/definitions/352.html',
  ],
  extensions: JS_ROUTE_EXTENSIONS,
  skipFlags: [...LOGIC_SKIP_FLAGS],
  appliesTo: (ctx) => ctx.flags.isServerFrameworkFile && !ctx.project.hasCsrfProtection,
  detect(ctx) {
    if (!/session|cookie/i.test(ctx.code)) return [];
    if (/\bcsrf|xsrf|_token\s*===|sameSite\s*[:=]\s*['"`]?(?:strict|lax)/i.test(ctx.code)) return [];
    const hits: RuleHit[] = [];
    for (const handler of serverFrameworkHandlers(ctx)) {
      if (!['post', 'put', 'patch', 'delete'].includes(handler.verb)) continue;
      if (!/session\b|cookie/i.test(handler.body)) continue;
      if (!MUTATION_REGEX.test(handler.body)) continue;
      if (/\/(?:webhook|api\/v\d|graphql|login|signin|signup|register|oauth|callback)(?:\/|['"`]|$)/i.test(handler.path)) continue;
      hits.push({
        offset: handler.offset,
        matched: handler.body.slice(0, 120).trim(),
        message: `\`${handler.verb.toUpperCase()} ${handler.path || '/'}\` mutates state using a cookie session with no CSRF token check.`,
        data: { verb: handler.verb.toUpperCase(), route: handler.path },
      });
    }
    return hits;
  },
});

export const UNGUARDED_ROUTE_RULES: readonly Rule[] = [
  appRouterMutationNoAuth,
  pagesApiMutationNoAuth,
  serverRouteNoAuth,
  idorOwnershipFromRequest,
  serverActionNoAuth,
  unverifiedIdentity,
  adminWithoutRoleCheck,
  authUnused,
  missingCsrf,
];
