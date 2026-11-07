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
export declare const AUTH_VERIFICATION_TOKENS: readonly ["getServerSession", "getSession", "auth()", "auth(req", "await auth", "getAuth", "authOptions", "withAuth", "withPageAuth", "withApiAuth", "getServerSideSession", "currentUser", "auth().userId", "clerkClient", "getAuth(", "requireAuth", "protect", "verifyToken", "validateSession", "getSessionUser", "sessionUser", "requireUser", "requireLogin", "requireAdmin", "assertAuthenticated", "assertUser", "isAuthenticated", "authenticate", "authenticated", "verifySession", "resolveSession", "readSessionCookie", "parseSessionToken", "getUser()", "supabase.auth.getUser", "auth.getUser", "createServerClient", "createRouteHandlerClient", "getSessionFromRequest", "passport.authenticate", "ensureLoggedIn", "ensureAuthenticated", "req.isAuthenticated", "req.user", "request.user", "ctx.state.user", "c.get('user')", "c.var.user", "verifyIdToken", "getAuth().verifyIdToken", "jwt.verify", "jwtVerify", "jsonwebtoken.verify", "decodeJwt", "validateJwt", "session.user", "session.userId", "user.id", "userId = session", "bearerToken", "authorizationHeader", "checkPermission", "hasPermission", "hasRole", "can(", "authorize(", "guardRoute", "routeGuard", "middlewareAuth", "authMiddleware", "authGuard"];
/** Compiled matcher: does this file verify the caller's identity? */
export declare const AUTH_VERIFICATION_REGEX: RegExp;
/** Middleware names commonly mounted in front of a route handler. */
export declare const ROUTE_AUTH_MIDDLEWARE_REGEX: RegExp;
/** State-mutating operations (database writes, HTTP mutations, fs writes). */
export declare const MUTATION_TOKENS: readonly [".insert(", ".upsert(", ".update(", ".updateMany(", ".delete(", ".deleteMany(", ".destroy(", ".remove(", ".create(", ".createMany(", ".save(", ".patch(", ".write(", ".rpc(", ".execute(", "INSERT INTO", "UPDATE ", "DELETE FROM", "DROP TABLE", "ALTER TABLE", "TRUNCATE", "method: 'POST'", "method: \"POST\"", "method: 'PUT'", "method: \"PUT\"", "method: 'PATCH'", "method: \"PATCH\"", "method: 'DELETE'", "method: \"DELETE\"", "writeFile", "appendFile", "unlink", "mkdir", "rm(", "rmdir", "rename", "send(", "transfer(", "checkout.sessions.create", "refunds.create", "publish(", "emit("];
export declare const MUTATION_REGEX: RegExp;
/** SQL mutation verbs (uppercase-insensitive, used by the SQL rules). */
export declare const SQL_MUTATION_REGEX: RegExp;
/** Libraries / helpers that mark output as sanitised. */
export declare const SANITIZER_TOKENS: string[];
export declare const SANITIZER_REGEX: RegExp;
/** Values that are provably constant (and therefore safe) inside a sink. */
export declare const CONSTANT_VALUE_REGEX: RegExp;
/** LLM provider / SDK markers. */
export declare const LLM_TOKENS: string[];
export declare const LLM_REGEX: RegExp;
/** Identifiers whose value is controlled by the caller of an HTTP endpoint. */
export declare const UNTRUSTED_SOURCES: string[];
export declare const UNTRUSTED_SOURCE_REGEX: RegExp;
/** Object-identity keys that must come from the session, never the request. */
export declare const OWNERSHIP_KEYS: string[];
export declare const OWNERSHIP_KEY_REGEX: RegExp;
/** Session-derived ownership expressions (the safe counterpart). */
export declare const SESSION_OWNERSHIP_REGEX: RegExp;
/** Role / permission checks that protect administrative surfaces. */
export declare const ROLE_CHECK_REGEX: RegExp;
/** CSRF protection markers. */
export declare const CSRF_REGEX: RegExp;
/** Rate limiting markers. */
export declare const RATE_LIMIT_REGEX: RegExp;
/** Client-only environment variable prefixes that get inlined into bundles. */
export declare const PUBLIC_ENV_PREFIXES: readonly ["NEXT_PUBLIC_", "VITE_", "PUBLIC_", "NUXT_PUBLIC_", "SVELTEKIT_PUBLIC_", "REACT_APP_", "GATSBY_", "EXPO_PUBLIC_", "RSLIB_PUBLIC_", "RSBUILD_PUBLIC_", "WXT_PUBLIC_", "ANGULAR_"];
export declare const PUBLIC_ENV_PREFIX_REGEX: RegExp;
/**
 * Names that must never appear behind a public prefix. Matched
 * case-insensitively against the *suffix* of the variable name.
 */
export declare const SERVER_ONLY_SECRET_NAMES: readonly ["SERVICE_ROLE_KEY", "SERVICE_ROLE", "SERVICE_KEY", "SECRET_KEY", "SECRETS", "SECRET", "PRIVATE_KEY", "PRIVKEY", "API_KEY", "APIKEY", "ACCESS_KEY", "ACCESS_TOKEN", "AUTH_TOKEN", "ADMIN_KEY", "DATABASE_URL", "DB_URL", "DB_PASSWORD", "POSTGRES_PASSWORD", "CONNECTION_STRING", "PASSWORD", "PASSWD", "PWD", "SIGNING_KEY", "JWT_SECRET", "ENCRYPTION_KEY", "MASTER_KEY", "WEBHOOK_SECRET", "WHSEC", "SESSION_SECRET", "CLIENT_SECRET", "MNEMONIC", "SEED", "TOKEN"];
/** Names that are *expected* to be public even though they contain a keyword. */
export declare const PUBLIC_SAFE_NAME_SUFFIXES: string[];
/** Well-known server-only providers that must never reach the browser. */
export declare const SERVER_ONLY_PROVIDERS: readonly ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GITHUB_TOKEN", "DATABASE_URL", "POSTGRES_URL", "SENDGRID_API_KEY", "TWILIO_AUTH_TOKEN", "RESEND_API_KEY", "REPLICATE_API_TOKEN", "HF_TOKEN", "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "JWT_SECRET", "SESSION_SECRET", "ENCRYPTION_KEY"];
