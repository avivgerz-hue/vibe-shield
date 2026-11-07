"use strict";
/**
 * vibe-shield :: secret-entropy rules
 * -----------------------------------
 * `src/secrets/patterns.ts` knows ~40 vendor signature formats (Stripe, OpenAI,
 * Anthropic, AWS, GitHub, Supabase, Slack...) plus a generic high-entropy
 * assignment heuristic. This module turns those matches into findings with the
 * right severity for *where* the secret sits:
 *
 *   - a live key in a server file is a critical hardcoded credential,
 *   - the same key in a browser-reachable file is an immediate data breach,
 *   - the same key inside a committed `.env` is a repository leak.
 *
 * Splitting rules by destination (instead of reporting one match three ways) is
 * what keeps the scorecard honest and the patch prompt actionable.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SECRET_ENTROPY_RULES = void 0;
const patterns_1 = require("../../secrets/patterns");
const text_1 = require("../text");
const helpers_1 = require("./helpers");
const shared_1 = require("./shared");
const CLIENT_EXTENSIONS = ['ts', 'tsx', 'js', 'jsx', 'mts', 'mjs', 'cts', 'cjs', 'vue', 'svelte', 'html', 'mdx'];
/** Destinations that are not shipped to users: docs, tests, fixtures, examples. */
const isNonShipping = (ctx) => ctx.flags.isTestFile || ctx.flags.isDocumentation || ctx.flags.isLockfile || ctx.flags.isGenerated || ctx.flags.isEnvFile;
/** Do not re-report secrets inside the detector catalogue or its fixtures. */
const isDetectorMaterial = (ctx) => ctx.language === 'markdown' ||
    /(?:^|\/)(?:tests?|fixtures?|__tests__)\//.test(ctx.relativePath) ||
    /(?:^|\/)src\/(?:secrets|mcp-guard\/skill-auditor)/.test(ctx.relativePath);
/** All secrets in the file's comment-masked code (so commented samples are ignored). */
const secretHits = (ctx, options = {}) => (0, patterns_1.findSecrets)(ctx.code, options);
const toHit = (match, extra = {}) => ({
    offset: match.offset,
    matched: match.display,
    severity: extra.severity ?? match.severity,
    confidence: extra.confidence ?? 'high',
    message: extra.message ?? match.note,
    data: {
        patternId: match.patternId,
        vendor: match.vendor,
        family: match.family,
        entropy: match.entropy,
        ...(extra.data ?? {}),
    },
});
/** VSB-SECRET-001 - vendor credential in a non-shipping (server) file. */
const vendorSecret = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-001',
    slug: 'hardcoded-vendor-credential',
    title: 'Hardcoded third-party credential in source code',
    category: 'secret-entropy',
    severity: 'high',
    confidence: 'high',
    cwe: shared_1.CWES.hardcodedCredentials,
    description: 'A live-looking provider key is committed as a literal. Source code is copied, forked, pasted into issues and archived in CI logs — treat the key as public the moment it lands in a commit.',
    insecureExample: 'const stripe = new Stripe("sk_live_51H8x…");',
    secureExample: 'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);',
    remediation: [
        'Rotate the credential at the provider *first* — assume it is already compromised.',
        'Move the value into an environment variable (`.env.local`, your host\'s secret store) and read it via `process.env`.',
        'Add a prefixed placeholder to `.env.example` so the next developer knows the variable is required.',
        'Enable secret scanning / push protection on the repository so the next commit is blocked, and purge the value from git history.',
    ],
    references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
        'https://cwe.mitre.org/data/definitions/798.html',
    ],
    extensions: [...CLIENT_EXTENSIONS, 'py', 'rb', 'php', 'go', 'sh', 'yml', 'yaml', 'json', 'toml', 'tf', 'env'],
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => !isNonShipping(ctx) && !isDetectorMaterial(ctx),
    contentHints: [/sk_|pk_live|AKIA|ghp_|xox[baprs]-|AIza|sk-ant-|eyJhbGciOi|whsec_|SG\./],
    detect(ctx) {
        return secretHits(ctx, { skipGeneric: true })
            .filter((match) => match.family !== 'private-key' && match.family !== 'jwt')
            .filter(() => !(0, shared_1.isBrowserFile)(ctx))
            .map((match) => toHit(match));
    },
});
/** VSB-SECRET-002 - generic high-entropy assignment. */
const genericSecret = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-002',
    slug: 'high-entropy-secret',
    title: 'High-entropy value assigned to a credential-shaped name',
    category: 'secret-entropy',
    severity: 'medium',
    confidence: 'medium',
    cwe: shared_1.CWES.hardcodedCredentials,
    description: 'The variable name says "secret" and the value has the entropy of a real key. There is no vendor signature to match — which is exactly why this class survives a naïve regex review.',
    insecureExample: 'const SIGNING_SECRET = "9f2b8c4e7a1d3f5b8c6e9a2d4f7b1c3e";',
    secureExample: 'const SIGNING_SECRET = process.env.SIGNING_SECRET!;',
    remediation: [
        'Move the value to an environment variable and rotate it at the provider.',
        'If the value is genuinely a constant (a salt for a public hash, a test fixture), move it to the test/fixture tree where it is not scanned.',
        'Prefer asymmetric signing so the verifying side never needs the secret at all.',
    ],
    references: ['https://cwe.mitre.org/data/definitions/798.html'],
    extensions: [...CLIENT_EXTENSIONS, 'py', 'rb', 'php', 'go', 'sh', 'yml', 'yaml', 'json', 'toml', 'env'],
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => !isNonShipping(ctx) && !isDetectorMaterial(ctx),
    contentHints: [/secret|token|key|password|credential/i],
    detect(ctx) {
        const vendorIds = new Set(secretHits(ctx, { skipGeneric: true }).map((match) => `${match.offset}:${match.length}`));
        return secretHits(ctx)
            .filter((match) => match.patternId === 'generic')
            .filter((match) => !vendorIds.has(`${match.offset}:${match.length}`))
            .filter((match) => !/(?:example|sample|placeholder)/i.test(match.vendor))
            .map((match) => {
            const severity = match.entropy >= 4.2 && match.value.length >= 32 ? 'high' : 'medium';
            return toHit(match, {
                severity,
                confidence: match.entropy >= 4 ? 'high' : 'medium',
                message: `\`${match.vendor}\` is assigned a literal with Shannon entropy ${match.entropy.toFixed(2)} — it looks like a real credential.`,
            });
        });
    },
});
/** VSB-SECRET-003 - private key material. */
const privateKeyMaterial = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-003',
    slug: 'private-key-material',
    title: 'Private key committed to the repository',
    category: 'secret-entropy',
    severity: 'critical',
    confidence: 'high',
    cwe: shared_1.CWES.privateKey,
    description: 'A PEM private key in the tree lets anyone holding the repository impersonate your service: sign JWTs, decrypt payloads, push to registries or SSH into hosts. Rotating is not optional.',
    insecureExample: '-----BEGIN RSA PRIVATE KEY-----\nMIIEow…',
    secureExample: 'const key = await fs.readFile(process.env.JWT_PRIVATE_KEY_PATH!, "utf8");',
    remediation: [
        'Treat the key as compromised: generate a new pair and revoke the old one with the relying party.',
        'Store private keys in a secret manager / KMS; load them at runtime, never from the repo.',
        'For JWT signing prefer a KMS-backed signer or short-lived tokens with a rotating key id (`kid`).',
        'Purge the key from git history (`git filter-repo`) and add `*.pem`, `*.key`, `id_rsa` to `.gitignore`.',
    ],
    references: [
        'https://cwe.mitre.org/data/definitions/321.html',
        'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
    ],
    extensions: ['ts', 'tsx', 'js', 'jsx', 'py', 'rb', 'php', 'go', 'sh', 'yml', 'yaml', 'json', 'env', 'pem', 'key', 'crt', 'txt'],
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => !isDetectorMaterial(ctx) && !ctx.flags.isDocumentation,
    contentHints: [/-----BEGIN/],
    detect(ctx) {
        return secretHits(ctx, { skipGeneric: true })
            .filter((match) => match.family === 'private-key' || /-----BEGIN[^-]+PRIVATE KEY(?: BLOCK)?-----/.test(match.value))
            .map((match) => toHit(match, { severity: 'critical', confidence: 'high', message: match.note }));
    },
});
/** VSB-SECRET-004 - hardcoded JWT with a privileged role. */
const privilegedJwt = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-004',
    slug: 'hardcoded-privileged-jwt',
    title: 'Hardcoded JWT grants a privileged role',
    category: 'secret-entropy',
    severity: 'critical',
    confidence: 'high',
    cwe: shared_1.CWES.privilegeEscalation,
    description: 'A literal JWT whose payload carries `role: service_role` / `admin` / `superuser` is a skeleton key. Supabase service-role tokens bypass RLS; admin JWTs bypass your authorisation layer at the database.',
    insecureExample: 'const key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.…";',
    secureExample: 'const key = process.env.SUPABASE_SERVICE_ROLE_KEY!; // server-only module',
    remediation: [
        'Rotate the JWT secret / service-role key immediately — this token is a full-access credential.',
        'Load privileged tokens from the environment in a module marked `import "server-only";`.',
        'Scope the token: use the anon key plus RLS for anything user-facing, and short-lived user tokens elsewhere.',
    ],
    references: [
        'https://supabase.com/docs/guides/api/api-keys',
        'https://cwe.mitre.org/data/definitions/250.html',
    ],
    extensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'yml', 'yaml', 'env', 'sh', 'py'],
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => !isDetectorMaterial(ctx) && !ctx.flags.isDocumentation,
    contentHints: [/eyJ/],
    detect(ctx) {
        const hits = [];
        for (const match of ctx.code.matchAll(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g)) {
            if (!(0, patterns_1.decodeJwtPayload)(match[0]))
                continue;
            const { privileged, role: detectedRole } = (0, patterns_1.jwtHasPrivilegedRole)(match[0]);
            if (!privileged)
                continue;
            const role = detectedRole ?? 'privileged';
            hits.push({
                offset: match.index,
                matched: `${match[0].slice(0, 12)}…${match[0].slice(-6)}`,
                severity: 'critical',
                confidence: 'high',
                message: `Hardcoded JWT carries the \`${role}\` role, which bypasses row-level security and authorisation checks.`,
                data: { role, patternId: 'jwt-privileged' },
            });
        }
        return hits;
    },
});
/** VSB-SECRET-005 - vendor credential in browser-reachable code. */
const clientVendorSecret = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-005',
    slug: 'credential-in-client-bundle',
    title: 'Live credential inside browser-reachable code',
    category: 'secret-entropy',
    severity: 'critical',
    confidence: 'high',
    cwe: shared_1.CWES.exposureOfSecrets,
    description: 'This file is part of the client graph, so the credential is in the JavaScript bundle. It is not a future risk: open devtools on the deployed site and it is there in plain text.',
    insecureExample: 'const stripe = new Stripe("sk_live_51H8x…"); // in a component',
    secureExample: 'await fetch("/api/checkout", { method: "POST" });',
    remediation: [
        'Remove the key from the client bundle and rotate it now.',
        'Proxy the privileged call through a server route that authenticates the user and enforces quotas.',
        'If the SDK must run in the browser, use the publishable/anon key and rely on RLS for data authorisation.',
    ],
    references: [
        'https://nextjs.org/docs/app/building-your-application/configuring/environment-variables',
        'https://cwe.mitre.org/data/definitions/200.html',
    ],
    extensions: CLIENT_EXTENSIONS,
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => (0, shared_1.isBrowserFile)(ctx) && !isNonShipping(ctx) && !isDetectorMaterial(ctx),
    contentHints: [/sk_|pk_live|AKIA|ghp_|xox[baprs]-|AIza|sk-ant-|eyJhbGciOi|whsec_/],
    detect(ctx) {
        return secretHits(ctx, { skipGeneric: true })
            .filter((match) => match.family !== 'private-key')
            .map((match) => toHit(match, {
            severity: 'critical',
            confidence: 'high',
            message: `A ${match.vendor} credential is bundled into the browser build — it is readable by every visitor.`,
        }));
    },
});
/** VSB-SECRET-006 - default / weak credentials. */
const defaultCredentials = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-006',
    slug: 'default-or-weak-credential',
    title: 'Default or trivially weak credential in configuration',
    category: 'secret-entropy',
    severity: 'medium',
    confidence: 'medium',
    cwe: shared_1.CWES.defaultCredentials,
    description: '`postgres:postgres@db` and `password = "admin"` work on every fresh container and are the first thing a scanner tries. Demo defaults survive into production far more often than anyone admits.',
    insecureExample: "DATABASE_URL='postgresql://postgres:postgres@localhost:5432/app'",
    secureExample: 'DATABASE_URL=process.env.DATABASE_URL',
    remediation: [
        'Generate a unique password for every environment and inject it from the platform secret store.',
        'Remove the default from `docker-compose.yml` and `.env.example` samples; use a placeholder the user must replace.',
        'If the credential authenticates a network service, bind it to a private network and rotate it.',
    ],
    references: [
        'https://cwe.mitre.org/data/definitions/1392.html',
        'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
    ],
    skipFlags: ['isLockfile', 'isGenerated'],
    appliesTo: (ctx) => !isDetectorMaterial(ctx) && !ctx.flags.isDocumentation,
    contentHints: [/postgres:|mysql:|mongodb:\/\/|redis:\/\/|password\s*[:=]/i],
    detect(ctx) {
        const hits = [];
        const weak = /^(?:admin|root|postgres|password|passwd|123456|changeme|secret|test|guest|user|sa|master|qwerty)$/i;
        for (const match of ctx.code.matchAll(/(?:DATABASE_URL|MONGO(?:DB)?_URL|REDIS_URL|POSTGRES_URL)\s*[:=]\s*['"]?([a-z][a-z0-9+.-]*):\/\/([^:'"@\s]{1,40}):([^'"@\s]{1,60})@/gi)) {
            const user = (match[2] ?? '').trim();
            const pass = (match[3] ?? '').trim();
            if (!weak.test(pass) && (0, text_1.shannonEntropy)(pass) >= 2.5)
                continue;
            hits.push({
                offset: match.index,
                matched: `${match[1]}://${user}:***@`,
                message: `Connection string uses the weak password \`${pass}\` for \`${user}\`.`,
                data: { user },
            });
        }
        for (const match of ctx.code.matchAll(/\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET)[A-Za-z0-9_]*)\s*[:=]\s*(['"])([^'"\n]{1,40})\2/gi)) {
            const name = match[1] ?? '';
            const value = match[3] ?? '';
            if (!weak.test(value))
                continue;
            hits.push({
                offset: match.index,
                matched: `${name} = "${value}"`,
                message: `\`${name}\` is set to the default value \`${value}\`.`,
                data: { variable: name },
            });
        }
        return hits;
    },
});
/** VSB-SECRET-007 - committed `.env` carrying credentials. */
const committedEnvFile = (0, helpers_1.defineRule)({
    id: 'VSB-SECRET-007',
    slug: 'env-file-with-credentials',
    title: '.env file with real credentials is tracked by git',
    category: 'secret-entropy',
    severity: 'critical',
    confidence: 'high',
    cwe: shared_1.CWES.credentialLeak,
    description: 'A `.env` file containing live values is in the working tree, and (per the git index) committed. Git history is immutable in practice: anyone with a clone has the keys, even after the file is deleted.',
    insecureExample: 'OPENAI_API_KEY=sk-proj-9xK…  # .env, committed',
    secureExample: '# .env.example\nOPENAI_API_KEY=sk-proj-your-key-here',
    remediation: [
        'Rotate every credential in the file, then delete the file from git (`git rm --cached .env`) and add it to `.gitignore`.',
        'Commit a `.env.example` with placeholder values instead.',
        'Purge the file from history with `git filter-repo --path .env --invert-paths`, then force-push and tell every collaborator to re-clone.',
        'Enable secret scanning + push protection on the repository.',
    ],
    references: [
        'https://cwe.mitre.org/data/definitions/540.html',
        'https://12factor.net/config',
    ],
    appliesTo: (ctx) => ctx.flags.isEnvFile && !/\.(?:example|sample|template|dist|schema)$/i.test(ctx.fileName),
    contentHints: [/=/],
    detect(ctx) {
        const matches = (0, patterns_1.findSecrets)(ctx.code, { skipGeneric: false }).filter((match) => match.family !== 'generic');
        if (!matches.length)
            return [];
        const tracked = ctx.project.gitAvailable
            ? ctx.project.trackedPaths.includes(ctx.relativePath)
            : undefined;
        const line = ctx.locate(matches[0]?.offset ?? 0).line;
        const severity = tracked === false ? 'medium' : 'critical';
        return [
            (0, helpers_1.fileHit)(line, {
                matched: ctx.fileName,
                severity,
                confidence: tracked === false ? 'medium' : 'high',
                message: tracked === false
                    ? `\`${ctx.fileName}\` contains ${matches.length} live credential(s) but is not tracked by git — one \`git add .\` away from a leak.`
                    : `\`${ctx.fileName}\` contains ${matches.length} live credential(s) and is committed to the repository.`,
                data: { secrets: matches.length, tracked: tracked ?? null },
            }),
        ];
    },
});
exports.SECRET_ENTROPY_RULES = [
    vendorSecret,
    genericSecret,
    privateKeyMaterial,
    privilegedJwt,
    clientVendorSecret,
    defaultCredentials,
    committedEnvFile,
];
