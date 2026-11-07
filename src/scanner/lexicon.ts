/**
 * vibe-shield :: detection lexicon
 * --------------------------------
 * The vocabulary every rule agrees on: what counts as "authentication was
 * verified", what counts as "this route mutates state", which helpers count as
 * sanitisation, and which identifiers are attacker-controlled.
 *
 * Centralising it means adding support for a new auth library (Auth.js, Clerk,
 * Lucia, Supabase SSR, Passport, Firebase, Kinvey...) is a one-line change
 * that instantly improves six different rules.
 */

/** Server-side session / identity verification helpers. */
export const AUTH_VERIFICATION_TOKENS = [
  // NextAuth / Auth.js
  'getServerSession',
  'getSession',
  'auth()',
  'auth(req',
  'await auth',
  'getAuth',
  'authOptions',
  'withAuth',
  'withPageAuth',
  'withApiAuth',
  'getServerSideSession',
  // Clerk
  'currentUser',
  'auth().userId',
  'clerkClient',
  'getAuth(',
  'requireAuth',
  'protect',
  'verifyToken',
  // Lucia / custom
  'validateSession',
  'getSessionUser',
  'sessionUser',
  'requireUser',
  'requireLogin',
  'requireAdmin',
  'assertAuthenticated',
  'assertUser',
  'isAuthenticated',
  'authenticate',
  'authenticated',
  'verifySession',
  'resolveSession',
  'readSessionCookie',
  'parseSessionToken',
  // Supabase
  'getUser()',
  'supabase.auth.getUser',
  'auth.getUser',
  'createServerClient',
  'createRouteHandlerClient',
  'getSessionFromRequest',
  // Passport / Express
  'passport.authenticate',
  'ensureLoggedIn',
  'ensureAuthenticated',
  'req.isAuthenticated',
  'req.user',
  'request.user',
  'ctx.state.user',
  'c.get(\'user\')',
  'c.var.user',
  // Firebase / JWT
  'verifyIdToken',
  'getAuth().verifyIdToken',
  'jwt.verify',
  'jwtVerify',
  'jsonwebtoken.verify',
  'decodeJwt',
  'validateJwt',
  'session.user',
  'session.userId',
  'user.id',
  'userId = session',
  'bearerToken',
  'authorizationHeader',
  // Generic guard helpers
  'checkPermission',
  'hasPermission',
  'hasRole',
  'can(',
  'authorize(',
  'guardRoute',
  'routeGuard',
  'middlewareAuth',
  'authMiddleware',
  'authGuard',
] as const;

/** Compiled matcher: does this file verify the caller's identity? */
export const AUTH_VERIFICATION_REGEX = new RegExp(
  AUTH_VERIFICATION_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
  'i',
);

/** Middleware names commonly mounted in front of a route handler. */
export const ROUTE_AUTH_MIDDLEWARE_REGEX =
  /\b(?:require|ensure|verify|check|assert|protect|guard)[A-Za-z]*(?:Auth|User|Session|Login|Token|Role|Admin|Permission)[A-Za-z]*\b|\b(?:isAuthenticated|authenticate|authMiddleware|authGuard|withAuth|passport\.authenticate)\b/i;

/** State-mutating operations (database writes, HTTP mutations, fs writes). */
export const MUTATION_TOKENS = [
  '.insert(',
  '.upsert(',
  '.update(',
  '.updateMany(',
  '.delete(',
  '.deleteMany(',
  '.destroy(',
  '.remove(',
  '.create(',
  '.createMany(',
  '.save(',
  '.patch(',
  '.write(',
  '.rpc(',
  '.execute(',
  'INSERT INTO',
  'UPDATE ',
  'DELETE FROM',
  'DROP TABLE',
  'ALTER TABLE',
  'TRUNCATE',
  'method: \'POST\'',
  'method: "POST"',
  'method: \'PUT\'',
  'method: "PUT"',
  'method: \'PATCH\'',
  'method: "PATCH"',
  'method: \'DELETE\'',
  'method: "DELETE"',
  'writeFile',
  'appendFile',
  'unlink',
  'mkdir',
  'rm(',
  'rmdir',
  'rename',
  'send(',
  'transfer(',
  'checkout.sessions.create',
  'refunds.create',
  'publish(',
  'emit(',
] as const;

export const MUTATION_REGEX = new RegExp(
  MUTATION_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
  'i',
);

/** SQL mutation verbs (uppercase-insensitive, used by the SQL rules). */
export const SQL_MUTATION_REGEX = /\b(?:INSERT\s+INTO|UPDATE\s+[`"'\w.]+\s+SET|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE|CREATE\s+POLICY|GRANT\s+|MERGE\s+INTO)\b/i;

/** Libraries / helpers that mark output as sanitised. */
export const SANITIZER_TOKENS = [
  'DOMPurify',
  'dompurify',
  'sanitizeHtml',
  'sanitize-html',
  'xss(',
  'isomorphic-dompurify',
  'escapeHtml',
  'escape(',
  'he.encode',
  'encodeHTML',
  'htmlEntities',
  'bleach.clean',
  'marked.parse',
  'remark',
  'rehype-sanitize',
  'sanitize(',
  'sanitizeMarkdown',
  'purify.sanitize',
];

export const SANITIZER_REGEX = new RegExp(
  SANITIZER_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
);

/** Values that are provably constant (and therefore safe) inside a sink. */
export const CONSTANT_VALUE_REGEX =
  /^(['"`][^'"`${]*['"`]|\d+(?:\.\d+)?|true|false|null|undefined|\[\]|\{\}|i18n|t\(|__\(|env\.[A-Z0-9_]+)$/;

/** LLM provider / SDK markers. */
export const LLM_TOKENS = [
  'openai',
  'OpenAI(',
  'anthropic',
  'Anthropic(',
  'generateText',
  'streamText',
  'generateObject',
  'streamObject',
  'tool(',
  'chat.completions.create',
  'messages.create',
  'llm.',
  'groq',
  'mistral',
  'cohere',
  'google/generative-ai',
  'bedrock',
  'langchain',
  'ollama',
  'together.ai',
  'xai',
  'completion',
  'prompt',
];

export const LLM_REGEX = new RegExp(
  LLM_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
  'i',
);

/** Identifiers whose value is controlled by the caller of an HTTP endpoint. */
export const UNTRUSTED_SOURCES = [
  'req.body',
  'req.query',
  'req.params',
  'request.body',
  'request.query',
  'request.params',
  'request.json()',
  'req.json()',
  'searchParams',
  'formData',
  'req.headers',
  'request.headers',
  'cookies()',
  'c.req.',
  'ctx.request.body',
  'ctx.params',
  'event.body',
  'event.queryStringParameters',
  'useBody',
  'readBody',
  'getQuery',
  'body.',
  'payload',
  'input.',
  'args.',
  'variables.',
];

export const UNTRUSTED_SOURCE_REGEX = new RegExp(
  UNTRUSTED_SOURCES.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
);

/** Object-identity keys that must come from the session, never the request. */
export const OWNERSHIP_KEYS = [
  'userId',
  'user_id',
  'uid',
  'accountId',
  'account_id',
  'customerId',
  'customer_id',
  'tenantId',
  'tenant_id',
  'organizationId',
  'organization_id',
  'orgId',
  'org_id',
  'teamId',
  'team_id',
  'workspaceId',
  'workspace_id',
  'projectId',
  'project_id',
  'ownerId',
  'owner_id',
  'authorId',
  'author_id',
  'profileId',
  'profile_id',
];

export const OWNERSHIP_KEY_REGEX = new RegExp(`\\b(${OWNERSHIP_KEYS.join('|')})\\b`);

/** Session-derived ownership expressions (the safe counterpart). */
export const SESSION_OWNERSHIP_REGEX =
  /(?:session|auth|user|currentUser|identity|principal|claims|jwt|token|viewer|me)\s*(?:\.\s*(?:user|data|identity|payload|claims|subject))?\s*\.\s*(?:id|userId|user_id|uid|sub|accountId|customerId|tenantId|orgId|organizationId|teamId|workspaceId|email)\b/i;

/** Role / permission checks that protect administrative surfaces. */
export const ROLE_CHECK_REGEX =
  /\b(?:isAdmin|is_admin|isOwner|is_owner|isStaff|is_staff|isSuperuser|is_superuser|hasRole|requireRole|requireAdmin|checkRole|assertRole|role\s*===?\s*['"`](?:admin|owner|superadmin|super_admin|staff|root|manager)['"`]|roles?\.\s*includes|permissions?\.\s*includes|hasPermission|checkPermission|can\(['"`]|isAllowedTo|claim\.|app_metadata|user_metadata\.role|plan\s*===?\s*['"`](?:pro|team|enterprise)['"`])\b/i;

/** CSRF protection markers. */
export const CSRF_REGEX =
  /\bcsrf|xsrf|_token\s*===|doubleSubmit|sameSite\s*[:=]\s*['"`]?(?:strict|lax)|synchronizerToken/i;

/** Rate limiting markers. */
export const RATE_LIMIT_REGEX =
  /\brateLimit|rate_limit|ratelimiter|upstash|@upstash\/ratelimit|express-rate-limit|slowdown|throttle|tokenBucket|leakyBucket|kv\.incr|redis.*incr|tooManyRequests|429\b/i;

/** Client-only environment variable prefixes that get inlined into bundles. */
export const PUBLIC_ENV_PREFIXES = [
  'NEXT_PUBLIC_',
  'VITE_',
  'PUBLIC_',
  'NUXT_PUBLIC_',
  'SVELTEKIT_PUBLIC_',
  'REACT_APP_',
  'GATSBY_',
  'EXPO_PUBLIC_',
  'RSLIB_PUBLIC_',
  'RSBUILD_PUBLIC_',
  'WXT_PUBLIC_',
  'ANGULAR_',
] as const;

export const PUBLIC_ENV_PREFIX_REGEX = new RegExp(`\\b(${PUBLIC_ENV_PREFIXES.join('|')})`, 'g');

/**
 * Names that must never appear behind a public prefix. Matched
 * case-insensitively against the *suffix* of the variable name.
 */
export const SERVER_ONLY_SECRET_NAMES = [
  'SERVICE_ROLE_KEY',
  'SERVICE_ROLE',
  'SERVICE_KEY',
  'SECRET_KEY',
  'SECRETS',
  'SECRET',
  'PRIVATE_KEY',
  'PRIVKEY',
  'API_KEY',
  'APIKEY',
  'ACCESS_KEY',
  'ACCESS_TOKEN',
  'AUTH_TOKEN',
  'ADMIN_KEY',
  'DATABASE_URL',
  'DB_URL',
  'DB_PASSWORD',
  'POSTGRES_PASSWORD',
  'CONNECTION_STRING',
  'PASSWORD',
  'PASSWD',
  'PWD',
  'SIGNING_KEY',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'MASTER_KEY',
  'WEBHOOK_SECRET',
  'WHSEC',
  'SESSION_SECRET',
  'CLIENT_SECRET',
  'MNEMONIC',
  'SEED',
  'TOKEN',
] as const;

/** Names that are *expected* to be public even though they contain a keyword. */
export const PUBLIC_SAFE_NAME_SUFFIXES = [
  'ANON_KEY',
  'ANON',
  'PUBLISHABLE_KEY',
  'PUBLIC_KEY',
  'PK_',
  'SITE_KEY',
  'CLIENT_ID',
  'APP_ID',
  'MEASUREMENT_ID',
  'FIREBASE_CONFIG',
];

/** Well-known server-only providers that must never reach the browser. */
export const SERVER_ONLY_PROVIDERS = [
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'STRIPE_SECRET_KEY',
  'STRIPE_WEBHOOK_SECRET',
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'GITHUB_TOKEN',
  'DATABASE_URL',
  'POSTGRES_URL',
  'SENDGRID_API_KEY',
  'TWILIO_AUTH_TOKEN',
  'RESEND_API_KEY',
  'REPLICATE_API_TOKEN',
  'HF_TOKEN',
  'GOOGLE_API_KEY',
  'AZURE_OPENAI_API_KEY',
  'JWT_SECRET',
  'SESSION_SECRET',
  'ENCRYPTION_KEY',
] as const;
