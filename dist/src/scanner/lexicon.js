"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SERVER_ONLY_PROVIDERS = exports.PUBLIC_SAFE_NAME_SUFFIXES = exports.SERVER_ONLY_SECRET_NAMES = exports.PUBLIC_ENV_PREFIX_REGEX = exports.PUBLIC_ENV_PREFIXES = exports.RATE_LIMIT_REGEX = exports.CSRF_REGEX = exports.ROLE_CHECK_REGEX = exports.SESSION_OWNERSHIP_REGEX = exports.OWNERSHIP_KEY_REGEX = exports.OWNERSHIP_KEYS = exports.UNTRUSTED_SOURCE_REGEX = exports.UNTRUSTED_SOURCES = exports.LLM_REGEX = exports.LLM_TOKENS = exports.CONSTANT_VALUE_REGEX = exports.SANITIZER_REGEX = exports.SANITIZER_TOKENS = exports.SQL_MUTATION_REGEX = exports.MUTATION_REGEX = exports.MUTATION_TOKENS = exports.ROUTE_AUTH_MIDDLEWARE_REGEX = exports.AUTH_VERIFICATION_REGEX = exports.AUTH_VERIFICATION_TOKENS = void 0;
/** Server-side session / identity verification helpers. */
exports.AUTH_VERIFICATION_TOKENS = [
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
];
/** Compiled matcher: does this file verify the caller's identity? */
exports.AUTH_VERIFICATION_REGEX = new RegExp(exports.AUTH_VERIFICATION_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i');
/** Middleware names commonly mounted in front of a route handler. */
exports.ROUTE_AUTH_MIDDLEWARE_REGEX = /\b(?:require|ensure|verify|check|assert|protect|guard)[A-Za-z]*(?:Auth|User|Session|Login|Token|Role|Admin|Permission)[A-Za-z]*\b|\b(?:isAuthenticated|authenticate|authMiddleware|authGuard|withAuth|passport\.authenticate)\b/i;
/** State-mutating operations (database writes, HTTP mutations, fs writes). */
exports.MUTATION_TOKENS = [
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
];
exports.MUTATION_REGEX = new RegExp(exports.MUTATION_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i');
/** SQL mutation verbs (uppercase-insensitive, used by the SQL rules). */
exports.SQL_MUTATION_REGEX = /\b(?:INSERT\s+INTO|UPDATE\s+[`"'\w.]+\s+SET|DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE|CREATE\s+POLICY|GRANT\s+|MERGE\s+INTO)\b/i;
/** Libraries / helpers that mark output as sanitised. */
exports.SANITIZER_TOKENS = [
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
exports.SANITIZER_REGEX = new RegExp(exports.SANITIZER_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'));
/** Values that are provably constant (and therefore safe) inside a sink. */
exports.CONSTANT_VALUE_REGEX = /^(['"`][^'"`${]*['"`]|\d+(?:\.\d+)?|true|false|null|undefined|\[\]|\{\}|i18n|t\(|__\(|env\.[A-Z0-9_]+)$/;
/** LLM provider / SDK markers. */
exports.LLM_TOKENS = [
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
exports.LLM_REGEX = new RegExp(exports.LLM_TOKENS.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i');
/** Identifiers whose value is controlled by the caller of an HTTP endpoint. */
exports.UNTRUSTED_SOURCES = [
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
exports.UNTRUSTED_SOURCE_REGEX = new RegExp(exports.UNTRUSTED_SOURCES.map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'));
/** Object-identity keys that must come from the session, never the request. */
exports.OWNERSHIP_KEYS = [
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
exports.OWNERSHIP_KEY_REGEX = new RegExp(`\\b(${exports.OWNERSHIP_KEYS.join('|')})\\b`);
/** Session-derived ownership expressions (the safe counterpart). */
exports.SESSION_OWNERSHIP_REGEX = /(?:session|auth|user|currentUser|identity|principal|claims|jwt|token|viewer|me)\s*(?:\.\s*(?:user|data|identity|payload|claims|subject))?\s*\.\s*(?:id|userId|user_id|uid|sub|accountId|customerId|tenantId|orgId|organizationId|teamId|workspaceId|email)\b/i;
/** Role / permission checks that protect administrative surfaces. */
exports.ROLE_CHECK_REGEX = /\b(?:isAdmin|is_admin|isOwner|is_owner|isStaff|is_staff|isSuperuser|is_superuser|hasRole|requireRole|requireAdmin|checkRole|assertRole|role\s*===?\s*['"`](?:admin|owner|superadmin|super_admin|staff|root|manager)['"`]|roles?\.\s*includes|permissions?\.\s*includes|hasPermission|checkPermission|can\(['"`]|isAllowedTo|claim\.|app_metadata|user_metadata\.role|plan\s*===?\s*['"`](?:pro|team|enterprise)['"`])\b/i;
/** CSRF protection markers. */
exports.CSRF_REGEX = /\bcsrf|xsrf|_token\s*===|doubleSubmit|sameSite\s*[:=]\s*['"`]?(?:strict|lax)|synchronizerToken/i;
/** Rate limiting markers. */
exports.RATE_LIMIT_REGEX = /\brateLimit|rate_limit|ratelimiter|upstash|@upstash\/ratelimit|express-rate-limit|slowdown|throttle|tokenBucket|leakyBucket|kv\.incr|redis.*incr|tooManyRequests|429\b/i;
/** Client-only environment variable prefixes that get inlined into bundles. */
exports.PUBLIC_ENV_PREFIXES = [
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
];
exports.PUBLIC_ENV_PREFIX_REGEX = new RegExp(`\\b(${exports.PUBLIC_ENV_PREFIXES.join('|')})`, 'g');
/**
 * Names that must never appear behind a public prefix. Matched
 * case-insensitively against the *suffix* of the variable name.
 */
exports.SERVER_ONLY_SECRET_NAMES = [
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
];
/** Names that are *expected* to be public even though they contain a keyword. */
exports.PUBLIC_SAFE_NAME_SUFFIXES = [
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
exports.SERVER_ONLY_PROVIDERS = [
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
];
