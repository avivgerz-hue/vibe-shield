"use strict";
/**
 * vibe-shield :: credential signature library
 * -------------------------------------------
 * Vendor-specific secret signatures plus a Shannon-entropy fallback. The same
 * table powers `VSB-SECRET-*` (source scanner) and the agent-skill auditor, so
 * a leaked key is reported identically no matter where it is found.
 *
 * Every regex is *deliberately* written so it cannot match its own source text
 * (that is why character classes appear as `[0-9A-Z]{16}` and never as a
 * literal example key) — vibe-shield scans itself in CI.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.GENERIC_ASSIGNMENT_REGEX = exports.SECRET_PATTERNS = void 0;
exports.findSecrets = findSecrets;
exports.decodeJwtPayload = decodeJwtPayload;
exports.jwtHasPrivilegedRole = jwtHasPrivilegedRole;
const text_1 = require("../scanner/text");
const q = (value) => value;
exports.SECRET_PATTERNS = [
    {
        id: 'private-key',
        vendor: 'Private key material',
        family: 'private-key',
        severity: 'critical',
        regex: /-----BEGIN[ \t]+(?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)[ \t]+)?PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----/g,
        raw: true,
        note: 'An unencrypted private key is committed to the repository.',
    },
    {
        id: 'anthropic',
        vendor: 'Anthropic',
        family: 'anthropic',
        severity: 'critical',
        regex: /\bsk-ant-(?:api|sid)\d{2}-[A-Za-z0-9_-]{20,}(?:-[A-Za-z0-9_-]{8,})?/g,
        minEntropy: 3,
        note: 'Anthropic API keys can be replayed for unlimited model spend.',
    },
    {
        id: 'openai-project',
        vendor: 'OpenAI',
        family: 'openai',
        severity: 'critical',
        regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}/g,
        minEntropy: 3,
        note: 'OpenAI project/service-account key.',
    },
    {
        id: 'openai',
        vendor: 'OpenAI',
        family: 'openai',
        severity: 'critical',
        regex: /\bsk-[A-Za-z0-9_-]{24,}\b/g,
        minEntropy: 3.2,
        note: 'OpenAI-compatible API key.',
    },
    {
        id: 'aws-access-key',
        vendor: 'AWS',
        family: 'aws',
        severity: 'critical',
        regex: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g,
        minEntropy: 3,
        note: 'AWS access key ID.',
    },
    {
        id: 'aws-secret-key',
        vendor: 'AWS',
        family: 'aws',
        severity: 'critical',
        regex: /\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key|secret[_-]?access[_-]?key)\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi,
        minEntropy: 3.5,
        note: 'AWS secret access key (40-char base64).',
    },
    {
        id: 'stripe-live-secret',
        vendor: 'Stripe',
        family: 'stripe',
        severity: 'critical',
        regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,
        minEntropy: 3,
        note: 'Live-mode Stripe secret/restricted key: full access to charges and refunds.',
    },
    {
        id: 'stripe-webhook-secret',
        vendor: 'Stripe',
        family: 'stripe',
        severity: 'high',
        regex: /\bwhsec_[0-9A-Za-z]{16,}\b/g,
        minEntropy: 3,
        note: 'Stripe webhook signing secret: allows forging webhook events.',
    },
    {
        id: 'github-token',
        vendor: 'GitHub',
        family: 'github',
        severity: 'critical',
        regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
        minEntropy: 3,
        note: 'GitHub personal access / OAuth / installation token.',
    },
    {
        id: 'supabase-access-token',
        vendor: 'Supabase',
        family: 'supabase',
        severity: 'critical',
        regex: /\bsbp_[a-f0-9]{40}\b|\bsb_secret_[A-Za-z0-9_]{20,}\b/g,
        minEntropy: 2.5,
        note: 'Supabase management API token / secret key.',
    },
    {
        id: 'google-api-key',
        vendor: 'Google',
        family: 'saas',
        severity: 'high',
        regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
        minEntropy: 3,
        note: 'Google API key (Maps / Gemini / Firebase).',
    },
    {
        id: 'slack-token',
        vendor: 'Slack',
        family: 'saas',
        severity: 'high',
        regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
        minEntropy: 3,
        note: 'Slack bot/user/app token.',
    },
    {
        id: 'twilio',
        vendor: 'Twilio',
        family: 'saas',
        severity: 'high',
        regex: /\bAC[0-9a-fA-F]{32}\b|\bSK[0-9a-fA-F]{32}\b/g,
        minEntropy: 3,
        note: 'Twilio Account SID / API key.',
    },
    {
        id: 'sendgrid',
        vendor: 'SendGrid',
        family: 'saas',
        severity: 'high',
        regex: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{24,}\b/g,
        minEntropy: 3.5,
        note: 'SendGrid API key.',
    },
    {
        id: 'telegram-bot',
        vendor: 'Telegram',
        family: 'saas',
        severity: 'high',
        regex: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g,
        minEntropy: 3,
        note: 'Telegram bot token.',
    },
    {
        id: 'npm-token',
        vendor: 'npm',
        family: 'registry',
        severity: 'critical',
        regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
        minEntropy: 3,
        note: 'npm automation/publish token (supply-chain risk).',
    },
    {
        id: 'pypi-token',
        vendor: 'PyPI',
        family: 'registry',
        severity: 'critical',
        regex: /\bpypi-AgEI[A-Za-z0-9_-]{20,}\b/g,
        minEntropy: 3,
        note: 'PyPI API token.',
    },
    {
        id: 'huggingface-token',
        vendor: 'Hugging Face',
        family: 'registry',
        severity: 'high',
        regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
        minEntropy: 3,
        note: 'Hugging Face access token.',
    },
    {
        id: 'docker-token',
        vendor: 'Docker Hub',
        family: 'registry',
        severity: 'high',
        regex: /\bdckr_pat_[A-Za-z0-9_-]{20,}\b/g,
        minEntropy: 3,
        note: 'Docker Hub personal access token.',
    },
    {
        id: 'vercel-token',
        vendor: 'Vercel',
        family: 'registry',
        severity: 'high',
        regex: /\bvc_[A-Za-z0-9]{24,}\b/g,
        minEntropy: 3,
        note: 'Vercel access token.',
    },
    {
        id: 'mailgun',
        vendor: 'Mailgun',
        family: 'saas',
        severity: 'high',
        regex: /\bkey-[0-9a-f]{32}\b/g,
        minEntropy: 3,
        note: 'Mailgun API key.',
    },
    {
        id: 'square',
        vendor: 'Square',
        family: 'saas',
        severity: 'high',
        regex: /\bsq0atp-[0-9A-Za-z_-]{22}\b|\bsq0csp-[0-9A-Za-z_-]{43}\b/g,
        minEntropy: 3,
        note: 'Square access token.',
    },
    {
        id: 'shopify',
        vendor: 'Shopify',
        family: 'saas',
        severity: 'high',
        regex: /\bshp(?:at|ca|pa)_[0-9A-Za-z]{32}\b/g,
        minEntropy: 3,
        note: 'Shopify access token.',
    },
    {
        id: 'datadog',
        vendor: 'Datadog',
        family: 'saas',
        severity: 'high',
        regex: /\b(?:api|app)[_-]?key\b["']?\s*[:=]\s*["']?([a-f0-9]{32,40})\b/gi,
        minEntropy: 3,
        note: 'Datadog API/application key.',
    },
    {
        id: 'gitlab-token', vendor: 'GitLab', family: 'saas', severity: 'high',
        regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, minEntropy: 3,
        note: 'GitLab personal access token.',
    },
    {
        id: 'digitalocean-token', vendor: 'DigitalOcean', family: 'saas', severity: 'high',
        regex: /\bdop_v1_[a-f0-9]{64}\b/g, minEntropy: 3,
        note: 'DigitalOcean API token.',
    },
    {
        id: 'linear-token', vendor: 'Linear', family: 'saas', severity: 'high',
        regex: /\blin_api_[A-Za-z0-9]{40}\b/g, minEntropy: 3,
        note: 'Linear API token.',
    },
    {
        id: 'cloudflare-token', vendor: 'Cloudflare', family: 'saas', severity: 'high',
        regex: /\bCLOUDFLARE_API_TOKEN\b["']?\s*[:=]\s*["']([A-Za-z0-9_-]{40})["']/gi, minEntropy: 3,
        note: 'A value assigned to a Cloudflare API token variable.',
    },
    {
        id: 'cohere-token', vendor: 'Cohere', family: 'saas', severity: 'high',
        regex: /\bCOHERE_API_KEY\b["']?\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/gi, minEntropy: 3,
        note: 'A value assigned to a Cohere API key variable.',
    },
    {
        id: 'mistral-token', vendor: 'Mistral', family: 'saas', severity: 'high',
        regex: /\bMISTRAL_API_KEY\b["']?\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/gi, minEntropy: 3,
        note: 'A value assigned to a Mistral API key variable.',
    },
    {
        id: 'groq-token', vendor: 'Groq', family: 'saas', severity: 'high',
        regex: /\bgsk_[A-Za-z0-9]{30,}\b/g, minEntropy: 3,
        note: 'Groq API key.',
    },
    {
        id: 'together-token', vendor: 'Together AI', family: 'saas', severity: 'high',
        regex: /\bTOGETHER_API_KEY\b["']?\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/gi, minEntropy: 3,
        note: 'A value assigned to a Together AI API key variable.',
    },
    {
        id: 'jwt',
        vendor: 'JSON Web Token',
        family: 'jwt',
        severity: 'high',
        regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
        minEntropy: 3.4,
        note: 'Signed JWT — decode it to check for `service_role` / `admin` claims.',
    },
    {
        id: 'database-url',
        vendor: 'Database connection string',
        family: 'database-url',
        severity: 'critical',
        regex: /\b(?:postgres(?:ql)?|mysql|mssql|mongodb(?:\+srv)?|redis|rediss|amqps?|cockroachdb|clickhouse):\/\/[^\s:/@'"]+:([^\s@/'"]{6,})@[^\s'"`)]+/gi,
        minEntropy: 2.2,
        note: 'Connection string with an embedded password.',
    },
];
/** Loose "assignment of a long opaque value" probe used by the generic rule. */
exports.GENERIC_ASSIGNMENT_REGEX = /(?:^|[^\w.])(?:"|')?([A-Za-z0-9_.\-\[\] ]{3,64}?(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|client[-_]?secret|auth[-_]?token|session[-_]?key|signing[-_]?key|encryption[-_]?key|master[-_]?key|webhook[-_]?secret|credential|passphrase|mnemonic|seed[-_]?phrase))(?:"|')?\s*[:=]\s*(?:"([^"\n]{8,256})"|'([^'\n]{8,256})'|([^\s"'`,;#)\]}]{8,256}))/gi;
const containsOverlap = (accepted, offset, length) => accepted.some((m) => offset < m.offset + m.length && offset + length > m.offset);
/** Find every credential in `text`, deduplicating overlapping matches. */
function findSecrets(text, options = {}) {
    const matches = [];
    for (const pattern of exports.SECRET_PATTERNS) {
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        let match;
        let guard = 0;
        while ((match = regex.exec(text)) !== null && guard < 5000) {
            guard += 1;
            const captured = (match[1] ?? match[0]).trim();
            if (match[0].length === 0) {
                regex.lastIndex += 1;
                continue;
            }
            if (!pattern.raw && (0, text_1.isPlaceholderSecret)(captured))
                continue;
            const entropy = (0, text_1.shannonEntropy)(captured);
            if (!pattern.raw && pattern.minEntropy !== undefined && entropy < pattern.minEntropy)
                continue;
            if (!pattern.raw && pattern.minEntropy !== undefined && (0, text_1.alphabetSize)(captured) < 4)
                continue;
            matches.push({
                patternId: pattern.id,
                vendor: pattern.vendor,
                family: pattern.family,
                severity: pattern.severity,
                value: captured,
                display: (0, text_1.redactSecret)(captured),
                offset: match.index,
                length: match[0].length,
                entropy: Number(entropy.toFixed(2)),
                note: pattern.note,
            });
            if (regex.lastIndex === match.index)
                regex.lastIndex += 1;
        }
    }
    if (!options.skipGeneric) {
        const regex = new RegExp(exports.GENERIC_ASSIGNMENT_REGEX.source, exports.GENERIC_ASSIGNMENT_REGEX.flags);
        let match;
        let guard = 0;
        while ((match = regex.exec(text)) !== null && guard < 5000) {
            guard += 1;
            const value = (match[2] ?? match[3] ?? match[4] ?? '').trim();
            const name = (match[1] ?? '').trim();
            if (!value || (0, text_1.isPlaceholderSecret)(value))
                continue;
            const entropy = (0, text_1.shannonEntropy)(value);
            const longValue = value.length >= 20;
            const threshold = longValue ? 3 : 3.6;
            if (entropy < threshold || (0, text_1.alphabetSize)(value) < 4)
                continue;
            const valueOffset = match.index + match[0].lastIndexOf(value);
            matches.push({
                patternId: 'generic',
                vendor: q(name.replace(/\s+/g, ' ')),
                family: 'generic',
                severity: longValue ? 'high' : 'medium',
                value,
                display: (0, text_1.redactSecret)(value),
                offset: valueOffset,
                length: value.length,
                entropy: Number(entropy.toFixed(2)),
                note: `High-entropy value assigned to \`${name}\` (Shannon entropy ${entropy.toFixed(2)}).`,
            });
            if (regex.lastIndex === match.index)
                regex.lastIndex += 1;
        }
    }
    // Specific vendor signatures win over generic/loose ones.
    const priority = (m) => {
        if (m.family === 'generic')
            return 0;
        if (m.family === 'jwt')
            return 1;
        return 2;
    };
    matches.sort((a, b) => priority(b) - priority(a) || b.length - a.length || a.offset - b.offset);
    const accepted = [];
    for (const candidate of matches) {
        if (containsOverlap(accepted, candidate.offset, candidate.length))
            continue;
        accepted.push(candidate);
    }
    accepted.sort((a, b) => a.offset - b.offset);
    return accepted;
}
/**
 * Decode a JWT payload without verifying it — used to spot `service_role`,
 * `admin` or `exp: never` claims sitting in source code.
 */
function decodeJwtPayload(token) {
    const parts = token.split('.');
    if (parts.length < 2)
        return null;
    const payload = parts[1];
    if (!payload)
        return null;
    try {
        const normalised = payload.replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
        const json = Buffer.from(padded, 'base64').toString('utf8');
        const parsed = JSON.parse(json);
        return parsed && typeof parsed === 'object' ? parsed : null;
    }
    catch {
        return null;
    }
}
/** True when a JWT carries a privileged role claim. */
function jwtHasPrivilegedRole(token) {
    const payload = decodeJwtPayload(token);
    if (!payload)
        return { privileged: false, role: null };
    const candidates = [
        payload['role'],
        payload['roles'],
        payload['app_metadata']?.['role'],
        payload['user_metadata']?.['role'],
        payload['claims']?.['role'],
    ];
    for (const candidate of candidates) {
        const values = Array.isArray(candidate) ? candidate : [candidate];
        for (const value of values) {
            if (typeof value !== 'string')
                continue;
            const lower = value.toLowerCase();
            if (['service_role', 'servicerole', 'admin', 'superadmin', 'root', 'staff', 'owner'].includes(lower)) {
                return { privileged: true, role: value };
            }
        }
    }
    return { privileged: false, role: null };
}
