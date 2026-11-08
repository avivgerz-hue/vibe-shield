"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isRuleCategory = exports.isSeverity = exports.meetsSeverity = exports.severityRank = exports.emptySeverityCounts = exports.emptyProjectContext = exports.LANGUAGE_EXTENSIONS = exports.GRADE_THRESHOLDS = exports.GRADES = exports.SEVERITY_SCORE_CEILING = exports.SEVERITY_SCORE_PENALTY = exports.SEVERITY_WEIGHT = exports.CATEGORY_TITLES = exports.RULE_CATEGORIES = exports.CONFIDENCES = exports.SEVERITIES = void 0;
/**
 * vibe-shield :: scanner type system
 * ----------------------------------
 * Every rule, finding and scan result in vibe-shield is described by the
 * interfaces below. They are intentionally serialisable (plain JSON) so that a
 * `ScanResult` can be cached to disk, emitted as SARIF, or handed to an agent
 * as a patch prompt without any transformation.
 */
/** Ordered list of severities, most severe first. */
exports.SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
/** Detection confidence reported alongside every finding. */
exports.CONFIDENCES = ['high', 'medium', 'low'];
/**
 * Rule families. Each family maps 1:1 to a module in `src/scanner/rules`
 * (plus `agent-integrity`, which is produced by the MCP / skill auditor).
 */
exports.RULE_CATEGORIES = [
    'client-exposure',
    'unguarded-routes',
    'database-exposure',
    'ai-vulnerabilities',
    'secret-entropy',
    'infrastructure',
    'dependencies',
    'agent-integrity',
];
exports.CATEGORY_TITLES = {
    'client-exposure': 'Client-side secret & data exposure',
    'unguarded-routes': 'Unguarded mutation routes (authZ / authN)',
    'database-exposure': 'Database exposure (RLS, SQLi, service role)',
    'ai-vulnerabilities': 'AI / LLM & classic web vulnerabilities',
    'secret-entropy': 'Hardcoded credentials & high-entropy secrets',
    infrastructure: 'Infrastructure, headers & containers',
    dependencies: 'Supply-chain & dependency hygiene',
    'agent-integrity': 'Agent skill & MCP poisoning',
};
/** Relative severity weight used by the scoring model. */
exports.SEVERITY_WEIGHT = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};
/**
 * Points deducted from the 100-point security score per finding. The curve is
 * deliberately steep: one leaked live key must be able to fail a build on its
 * own, while a handful of informational notes must not.
 */
exports.SEVERITY_SCORE_PENALTY = {
    critical: 30,
    high: 12,
    medium: 5,
    low: 2,
    info: 0.5,
};
/**
 * Score ceilings: the worst severity present caps the achievable score, so a
 * single severe finding can never yield a good grade no matter how clean the
 * rest of the repository is.
 *
 * - any critical -> at most 29 (grade F)
 * - any high     -> at most 58 (grade C)
 * - any medium   -> at most 76 (grade B)
 * - any low      -> at most 88 (grade A-)
 */
exports.SEVERITY_SCORE_CEILING = {
    critical: 29,
    high: 58,
    medium: 76,
    low: 88,
};
exports.GRADES = [
    'A+',
    'A',
    'A-',
    'B+',
    'B',
    'B-',
    'C+',
    'C',
    'C-',
    'D+',
    'D',
    'D-',
    'F',
];
/** Minimum score required for each grade. */
exports.GRADE_THRESHOLDS = [
    { grade: 'A+', min: 98 },
    { grade: 'A', min: 93 },
    { grade: 'A-', min: 88 },
    { grade: 'B+', min: 82 },
    { grade: 'B', min: 76 },
    { grade: 'B-', min: 70 },
    { grade: 'C+', min: 64 },
    { grade: 'C', min: 58 },
    { grade: 'C-', min: 52 },
    { grade: 'D+', min: 45 },
    { grade: 'D', min: 38 },
    { grade: 'D-', min: 30 },
    { grade: 'F', min: -Infinity },
];
exports.LANGUAGE_EXTENSIONS = {
    ts: 'typescript',
    mts: 'typescript',
    cts: 'typescript',
    tsx: 'jsx',
    js: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    jsx: 'jsx',
    vue: 'vue',
    svelte: 'svelte',
    html: 'html',
    htm: 'html',
    ejs: 'html',
    handlebars: 'html',
    hbs: 'html',
    css: 'css',
    scss: 'css',
    less: 'css',
    sql: 'sql',
    prisma: 'prisma',
    py: 'python',
    rb: 'ruby',
    php: 'php',
    go: 'go',
    rs: 'rust',
    java: 'java',
    kt: 'java',
    sh: 'shell',
    bash: 'shell',
    zsh: 'shell',
    yml: 'yaml',
    yaml: 'yaml',
    toml: 'toml',
    json: 'json',
    jsonc: 'json',
    json5: 'json',
    map: 'json',
    md: 'markdown',
    mdx: 'markdown',
    markdown: 'markdown',
    env: 'dotenv',
    tf: 'terraform',
    tfvars: 'terraform',
    graphql: 'graphql',
    gql: 'graphql',
    xml: 'xml',
    plist: 'xml',
    csproj: 'xml',
    dockerfile: 'dockerfile',
};
/** An empty project context, used by tests and single-file scans. */
const emptyProjectContext = (rootDir) => ({
    rootDir,
    frameworks: [],
    dependencies: [],
    hasExpressServer: false,
    hasFastifyServer: false,
    hasCookieSession: false,
    hasRateLimiting: false,
    hasCsrfProtection: false,
    hasSanitizer: false,
    hasAuthLibrary: false,
    hasAiSdk: false,
    hasSupabase: false,
    hasStripe: false,
    hasPrisma: false,
    migrationFiles: [],
    sqlTables: [],
    hasGlobalAuthMiddleware: false,
    authMiddlewareMatchers: [],
    trackedPaths: [],
    gitAvailable: false,
});
exports.emptyProjectContext = emptyProjectContext;
const emptySeverityCounts = () => ({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
});
exports.emptySeverityCounts = emptySeverityCounts;
/** Numeric rank so severities can be compared (`critical` = 5). */
const severityRank = (severity) => exports.SEVERITY_WEIGHT[severity];
exports.severityRank = severityRank;
/** True when `severity` is at least as severe as `threshold`. */
const meetsSeverity = (severity, threshold) => (0, exports.severityRank)(severity) >= (0, exports.severityRank)(threshold);
exports.meetsSeverity = meetsSeverity;
const isSeverity = (value) => typeof value === 'string' && exports.SEVERITIES.includes(value);
exports.isSeverity = isSeverity;
const isRuleCategory = (value) => typeof value === 'string' && exports.RULE_CATEGORIES.includes(value);
exports.isRuleCategory = isRuleCategory;
