"use strict";
/**
 * vibe-shield :: scan engine
 * --------------------------
 * A single-pass, dependency-free static analyser. Design constraints, in order:
 *
 *  1. **Fast.** A 5k-file Next.js repo must finish in well under a second. That
 *     means one `readdir` tree walk, one read per file, one comment-masking pass
 *     and a cheap `appliesTo` gate before any rule runs.
 *  2. **Honest.** Every finding carries the exact `file:line` and the snippet
 *     the developer wrote, and every suppression is counted, not hidden.
 *  3. **Composable.** `scanProject()` is the CLI entry point, `runRulesOnFile()`
 *     is reused by the agent auditor, and `discoverFiles()` is exported so tests
 *     can assert on file selection independent of the rules.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasFindingsAtOrAbove = exports.packageVersion = exports.contentHash = exports.CACHE_VERSION = exports.CACHE_FILE_NAME = exports.isDocPath = exports.isTestPath = exports.DEFAULT_CONCURRENCY = exports.MAX_FILE_SIZE_BYTES = exports.BINARY_EXTENSIONS = exports.DEFAULT_IGNORED_DIRS = void 0;
exports.discoverFiles = discoverFiles;
exports.parseSuppressions = parseSuppressions;
exports.suppressionFor = suppressionFor;
exports.applySuppressions = applySuppressions;
exports.scoreFindings = scoreFindings;
exports.runRulesOnFile = runRulesOnFile;
exports.scanProject = scanProject;
exports.dedupe = dedupe;
exports.gitTrackedPaths = gitTrackedPaths;
const node_fs_1 = require("node:fs");
const node_crypto_1 = require("node:crypto");
const node_child_process_1 = require("node:child_process");
const path = __importStar(require("node:path"));
const context_1 = require("./context");
const version_1 = require("./version");
const redact_1 = require("./redact");
const attack_surface_1 = require("./attack-surface");
const gitignore_1 = require("./gitignore");
const rules_1 = require("./rules");
const types_1 = require("./types");
/** Directories that never contain first-party source. */
exports.DEFAULT_IGNORED_DIRS = new Set([
    'node_modules',
    '.git',
    'dist',
    'build',
    'out',
    '.next',
    '.nuxt',
    '.output',
    '.svelte-kit',
    'coverage',
    '.turbo',
    '.vercel',
    '.cache',
    '__pycache__',
    '.venv',
    'venv',
    'target',
    '.gradle',
    '.idea',
    '.vscode',
    'vendor',
    'bower_components',
    '.terraform',
    '.parcel-cache',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    '.angular',
    'storybook-static',
    '.playwright',
    'tmp',
    'temp',
    '.tmp',
    '.vibe-shield',
]);
/** Extensions that are never source code (archives, media, binaries). */
exports.BINARY_EXTENSIONS = new Set([
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'ico', 'bmp', 'tiff', 'psd',
    'woff', 'woff2', 'ttf', 'otf', 'eot',
    'mp3', 'mp4', 'm4a', 'wav', 'ogg', 'flac', 'mov', 'avi', 'mkv', 'webm',
    'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'tar', 'jar', 'war',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'exe', 'dll', 'so', 'dylib', 'bin', 'class', 'o', 'a', 'obj', 'lib',
    'wasm', 'pyc', 'pyo', 'node', 'db', 'sqlite', 'sqlite3', 'parquet', 'avro',
    'map', 'lockb', 'DS_Store',
]);
/** Files larger than this are skipped (minified bundles, generated monsters). */
exports.MAX_FILE_SIZE_BYTES = 1_500_000;
/** Default concurrency for the read pool. I/O-bound, so higher than CPU count. */
exports.DEFAULT_CONCURRENCY = 32;
const IGNORE_FILE_NAMES = ['.gitignore', '.vibe-shieldignore', '.ignore'];
/** Lockfiles: huge, generated, and never a place a human writes a secret by hand. */
const LOCKFILE_REGEX = /^(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|npm-shrinkwrap\.json|composer\.lock|Gemfile\.lock|poetry\.lock|uv\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|mix\.lock|pubspec\.lock)$/i;
/* -------------------------------------------------------------------------- */
/* File discovery                                                             */
/* -------------------------------------------------------------------------- */
const toPosix = (value) => value.split(path.sep).join('/');
/** True when `relativePath` looks like a test/fixture/doc path. */
const isTestPath = (relativePath) => /(?:^|\/)(?:__tests__|__mocks__|tests?|specs?|e2e|cypress|playwright|fixtures?|stories|test-utils|testing)(?:\/|$)|\.(?:test|spec|stories|it)\.[cm]?[jt]sx?$|_test\.go$|_spec\.rb$|(?:^|\/)test_[^/]+\.py$/i.test(relativePath);
exports.isTestPath = isTestPath;
/** True when `relativePath` looks like documentation. */
const isDocPath = (relativePath) => /\.(?:md|mdx|markdown|rst|adoc)$|(?:^|\/)docs?(?:\/|$)/i.test(relativePath) &&
    !/(?:^|\/)(?:AGENTS?\.md|CLAUDE\.md|SKILL\.md|\.cursorrules|\.mdc)$/i.test(relativePath);
exports.isDocPath = isDocPath;
/**
 * Walk `rootDir` and return every file that should be scanned.
 * Directory ignores are layered: built-in defaults, then every
 * `.gitignore` / `.vibe-shieldignore` / `.ignore` found on the way down.
 */
async function discoverFiles(rootDir, options = { rootDir }) {
    const root = path.resolve(rootDir);
    const matcher = new gitignore_1.IgnoreMatcher();
    for (const pattern of options.ignorePatterns ?? [])
        matcher.addRule(pattern, '', '<cli>');
    const files = [];
    let skipped = 0;
    let pruned = 0;
    const maxBytes = options.maxFileSizeBytes ?? exports.MAX_FILE_SIZE_BYTES;
    // Naming a path explicitly is an instruction to scan it: the test/doc
    // heuristics only apply to the implicit whole-tree walk.
    const explicitTargets = Boolean(options.paths?.length);
    const includeTests = options.includeTests ?? explicitTargets;
    const includeDocs = options.includeDocs ?? explicitTargets;
    const loadIgnoreFiles = async (dir) => {
        if (options.useGitignore === false)
            return;
        for (const name of IGNORE_FILE_NAMES) {
            // `--no-shield-ignore` lets CI scan the fixtures this repo excludes.
            if (name === '.vibe-shieldignore' && options.useShieldIgnore === false)
                continue;
            const file = path.join(dir, name);
            try {
                const text = await node_fs_1.promises.readFile(file, 'utf8');
                matcher.addIgnoreFile(text, toPosix(path.relative(root, dir)), name);
            }
            catch {
                // Missing ignore files are the common case.
            }
        }
    };
    const walk = async (dir) => {
        await loadIgnoreFiles(dir);
        let entries;
        try {
            entries = await node_fs_1.promises.readdir(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            const absolutePath = path.join(dir, entry.name);
            const relativePath = toPosix(path.relative(root, absolutePath));
            if (entry.isSymbolicLink()) {
                skipped += 1;
                continue;
            }
            if (entry.isDirectory()) {
                if (exports.DEFAULT_IGNORED_DIRS.has(entry.name)) {
                    pruned += 1;
                    continue;
                }
                if (matcher.isIgnored(relativePath, true)) {
                    pruned += 1;
                    continue;
                }
                await walk(absolutePath);
                continue;
            }
            if (!entry.isFile())
                continue;
            if (matcher.isIgnored(relativePath, false)) {
                skipped += 1;
                continue;
            }
            if (LOCKFILE_REGEX.test(entry.name)) {
                skipped += 1;
                continue;
            }
            const extension = (entry.name.split('.').pop() ?? '').toLowerCase();
            if (exports.BINARY_EXTENSIONS.has(extension)) {
                skipped += 1;
                continue;
            }
            if (!includeTests && (0, exports.isTestPath)(relativePath)) {
                skipped += 1;
                continue;
            }
            if (!includeDocs && (0, exports.isDocPath)(relativePath)) {
                skipped += 1;
                continue;
            }
            let stat;
            try {
                stat = await node_fs_1.promises.stat(absolutePath);
            }
            catch {
                continue;
            }
            if (stat.size > maxBytes) {
                skipped += 1;
                continue;
            }
            files.push({ absolutePath, relativePath, bytes: stat.size });
        }
    };
    if (options.paths?.length) {
        // Ignore files are still loaded from the root so `.vibe-shieldignore`
        // applies to explicit targets too.
        await loadIgnoreFiles(root);
        for (const target of options.paths) {
            const absolute = path.resolve(root, target);
            let stat = null;
            try {
                stat = await node_fs_1.promises.stat(absolute);
            }
            catch {
                stat = null;
            }
            if (!stat) {
                skipped += 1;
                continue;
            }
            if (stat.isDirectory()) {
                await walk(absolute);
                // A target directory that the user named is never pruned by a parent
                // ignore rule, but its own contents still respect ignore files.
            }
            else {
                const relativePath = toPosix(path.relative(root, absolute));
                const extension = (absolute.split('.').pop() ?? '').toLowerCase();
                if (exports.BINARY_EXTENSIONS.has(extension) || stat.size > maxBytes) {
                    skipped += 1;
                    continue;
                }
                files.push({ absolutePath: absolute, relativePath, bytes: stat.size });
            }
        }
    }
    else {
        await walk(root);
    }
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
    // De-duplicate (a path can be reached twice when `paths` overlap).
    const unique = [];
    const seen = new Set();
    for (const file of files) {
        if (seen.has(file.relativePath))
            continue;
        seen.add(file.relativePath);
        unique.push(file);
    }
    return { files: unique, skipped, pruned };
}
/* -------------------------------------------------------------------------- */
/* Suppressions                                                               */
/* -------------------------------------------------------------------------- */
const SUPPRESSION_REGEX = /vibe-shield-(disable-next-line|disable-line|disable-file|disable|enable)\b([^\n]*)$/;
/**
 * Parse `vibe-shield-disable*` directives from a file.
 *
 *   // vibe-shield-disable-next-line VSB-DB-001 -- legacy table
 *   // vibe-shield-disable VSB-AI-014
 *   // vibe-shield-enable
 */
function parseSuppressions(lines) {
    const fileWide = [];
    const byLine = new Map();
    const ranges = [];
    // Held in an object so TypeScript's closure narrowing cannot collapse it.
    const state = { open: null };
    const closeRange = (to) => {
        const open = state.open;
        if (!open)
            return;
        ranges.push({ from: open.from, to, ruleIds: open.ruleIds, reason: open.reason });
        state.open = null;
    };
    lines.forEach((line, index) => {
        const match = SUPPRESSION_REGEX.exec(line);
        if (!match)
            return;
        const [, directive = '', tail = ''] = match;
        const [idsPart = '', reasonPart = ''] = tail.split('--');
        const ruleIds = idsPart
            .trim()
            .split(/[\s,]+/)
            .map((id) => id.trim())
            .filter((id) => /^VSB-[A-Z]+(?:-[A-Z]+)?-\d+$/i.test(id) || /^[A-Z]+-\d+$/i.test(id));
        const reason = reasonPart.trim();
        const lineNumber = index + 1;
        if (directive === 'disable-file') {
            fileWide.push({ line: lineNumber, ruleIds, reason });
            return;
        }
        if (directive === 'disable-next-line') {
            byLine.set(lineNumber + 1, { line: lineNumber, ruleIds, reason });
            return;
        }
        if (directive === 'disable-line') {
            byLine.set(lineNumber, { line: lineNumber, ruleIds, reason });
            return;
        }
        if (directive === 'disable') {
            closeRange(lineNumber);
            state.open = { from: lineNumber, ruleIds, reason };
            return;
        }
        if (directive === 'enable')
            closeRange(lineNumber);
    });
    if (state.open)
        closeRange(Number.POSITIVE_INFINITY);
    return { fileWide, byLine, ranges };
}
/** True when the finding at `line` is suppressed (and why). */
function suppressionFor(parsed, ruleId, line) {
    const matches = (ruleIds) => ruleIds.length === 0 || ruleIds.some((id) => id.toUpperCase() === ruleId.toUpperCase());
    for (const suppression of parsed.fileWide) {
        if (matches(suppression.ruleIds))
            return suppression;
    }
    const lineSuppression = parsed.byLine.get(line);
    if (lineSuppression && matches(lineSuppression.ruleIds))
        return lineSuppression;
    for (const range of parsed.ranges) {
        if (line >= range.from && line <= range.to && matches(range.ruleIds)) {
            return { line: range.from, ruleIds: range.ruleIds, reason: range.reason };
        }
    }
    return null;
}
/**
 * Apply suppressions to a finding list. Returns the kept findings plus the
 * number that were suppressed (the scorecard reports both).
 */
function applySuppressions(findings, parsed) {
    const kept = [];
    let suppressed = 0;
    for (const finding of findings) {
        if (suppressionFor(parsed, finding.ruleId, finding.line)) {
            suppressed += 1;
            continue;
        }
        kept.push(finding);
    }
    return { findings: kept, suppressed };
}
/* -------------------------------------------------------------------------- */
/* Scoring                                                                    */
/* -------------------------------------------------------------------------- */
/** Turn a finding list into a 0-100 score with an A+ → F grade. */
function scoreFindings(findings) {
    const counts = (0, types_1.emptySeverityCounts)();
    for (const finding of findings)
        counts[finding.severity] += 1;
    const total = findings.length;
    if (!total) {
        return { score: 100, grade: 'A+', counts, ceiling: null, total };
    }
    let score = 100;
    for (const finding of findings)
        score -= types_1.SEVERITY_SCORE_PENALTY[finding.severity];
    let ceiling = null;
    for (const severity of ['critical', 'high', 'medium', 'low']) {
        if (counts[severity] === 0)
            continue;
        const limit = types_1.SEVERITY_SCORE_CEILING[severity];
        if (limit === undefined)
            continue;
        if (score > limit || ceiling === null)
            ceiling = { severity, limit };
        score = Math.min(score, limit);
        break;
    }
    score = Math.max(0, Math.round(score * 10) / 10);
    const grade = types_1.GRADE_THRESHOLDS.find((entry) => score >= entry.min)?.grade ?? 'F';
    return { score, grade, counts, ceiling, total };
}
/* -------------------------------------------------------------------------- */
/* Cache                                                                      */
/* -------------------------------------------------------------------------- */
exports.CACHE_FILE_NAME = '.vibe-shield-cache.json';
exports.CACHE_VERSION = 2;
/** Content hash used as the cache key for one file. */
const contentHash = (content) => (0, node_crypto_1.createHash)('sha1').update(content).digest('hex').slice(0, 20);
exports.contentHash = contentHash;
/** Fingerprint of the whole project (manifests + layout) for cache validity. */
const projectFingerprint = (project) => {
    const payload = [
        project.frameworks.join(','),
        project.dependencies.sort().join(','),
        project.migrationFiles.join(','),
        project.hasGlobalAuthMiddleware ? 'mw' : '',
    ].join('|');
    return (0, node_crypto_1.createHash)('sha1').update(payload).digest('hex').slice(0, 16);
};
async function readCache(rootDir) {
    try {
        const raw = await node_fs_1.promises.readFile(path.join(rootDir, exports.CACHE_FILE_NAME), 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed.version !== exports.CACHE_VERSION)
            return null;
        if (parsed.rules !== rules_1.RULES_FINGERPRINT)
            return null;
        return parsed;
    }
    catch {
        return null;
    }
}
async function writeCache(rootDir, cache) {
    try {
        await node_fs_1.promises.writeFile(path.join(rootDir, exports.CACHE_FILE_NAME), `${JSON.stringify(cache)}\n`, 'utf8');
    }
    catch {
        // A read-only checkout is not an error.
    }
}
/* -------------------------------------------------------------------------- */
/* Rule execution                                                             */
/* -------------------------------------------------------------------------- */
/**
 * Run a rule set against one file context.
 * Exported because the MCP auditor reuses it: two scanners, one rule contract.
 */
function runRulesOnFile(ctx, rules) {
    const hits = [];
    for (const rule of rules) {
        if (rule.appliesTo && !rule.appliesTo(ctx))
            continue;
        if (rule.skipFlags?.some((flag) => ctx.flags[flag] === true))
            continue;
        if (rule.languages?.length && !rule.languages.includes(ctx.language))
            continue;
        if (rule.contentHints?.length && !rule.contentHints.some((hint) => hint.test(ctx.content)))
            continue;
        let ruleHits;
        try {
            ruleHits = rule.detect(ctx);
        }
        catch {
            // A throwing rule must never abort a scan over an unrelated file.
            continue;
        }
        for (const hit of ruleHits)
            hits.push(hit);
    }
    return hits;
}
/** Convert one rule's hits into fully-populated findings. */
function toFindings(ctx, rule, hits) {
    const findings = [];
    for (const hit of hits) {
        const located = hit.offset !== undefined ? ctx.locate(hit.offset) : { line: hit.line ?? 1, column: hit.column ?? 1 };
        const snippet = ['VSB-INFRA-003', 'VSB-AUTH-012'].includes(rule.id) ? '[secret value redacted]' : (0, redact_1.redactReportText)(ctx.lineText(located.line).trim()).slice(0, 200);
        findings.push({
            ruleId: rule.id,
            slug: rule.slug,
            title: rule.title,
            category: rule.category,
            severity: hit.severity ?? rule.severity,
            confidence: hit.confidence ?? rule.confidence,
            cwe: rule.cwe,
            owasp: rule.owasp,
            filePath: ctx.relativePath,
            file: ctx.relativePath,
            absolutePath: ctx.absolutePath,
            line: located.line,
            column: located.column,
            snippet,
            matched: ['VSB-INFRA-003', 'VSB-AUTH-012'].includes(rule.id) ? '[secret value redacted]' : (0, redact_1.redactReportText)(hit.matched ?? snippet),
            message: hit.message ?? rule.description,
            remediation: rule.remediate ? rule.remediate(ctx, hit) : rule.remediation,
            insecureExample: rule.insecureExample,
            secureExample: rule.secureExample,
            references: rule.references,
            data: hit.data,
        });
    }
    return findings;
}
/* -------------------------------------------------------------------------- */
/* Main scan                                                                  */
/* -------------------------------------------------------------------------- */
var version_2 = require("./version");
Object.defineProperty(exports, "packageVersion", { enumerable: true, get: function () { return version_2.packageVersion; } });
/**
 * Scan a project. This is the one function the CLI, the tests and any embedding
 * application call; everything else in this module is an implementation detail.
 */
async function scanProject(options) {
    const started = Date.now();
    const rootDir = path.resolve(options.rootDir || '.');
    const rules = (0, rules_1.selectRules)([], options.rules ?? rules_1.SCAN_RULES);
    const notices = [];
    let project;
    try {
        project = await (0, context_1.detectProject)(rootDir, {
            skip: (relativePath, isDirectory) => {
                const base = relativePath.split('/').pop() ?? '';
                return isDirectory && (exports.DEFAULT_IGNORED_DIRS.has(base) || base.startsWith('.git'));
            },
            readGitIndex: options.useGitIndex !== false,
        });
    }
    catch {
        project = (0, types_1.emptyProjectContext)(rootDir);
        notices.push('Project detection failed; project-wide rules (RLS, framework flags) were skipped.');
    }
    options.onProject?.(project);
    const discovered = await discoverFiles(rootDir, options);
    if (!discovered.files.length) {
        notices.push(options.paths?.length
            ? `No scannable files matched: ${options.paths.join(', ')}`
            : 'No scannable files were found. Check the path, or pass --include-docs for documentation.');
    }
    const cacheEnabled = options.cache === true;
    const existing = cacheEnabled ? await readCache(rootDir) : null;
    const cache = {
        version: exports.CACHE_VERSION,
        rules: rules_1.RULES_FINGERPRINT,
        project: projectFingerprint(project),
        files: {},
    };
    const concurrency = Math.max(1, Math.min(256, options.concurrency ?? exports.DEFAULT_CONCURRENCY));
    const findings = [];
    const attackSurface = (0, attack_surface_1.emptyAttackSurface)();
    let suppressedCount = 0;
    let cacheHits = 0;
    let bytesScanned = 0;
    let filesScanned = 0;
    let ruleInvocations = 0;
    let index = 0;
    const handleFile = async (file) => {
        let content;
        try {
            const buffer = await node_fs_1.promises.readFile(file.absolutePath);
            // NUL sniff: a text file never contains one in the first 8 KiB.
            if (buffer.subarray(0, 8192).includes(0))
                return;
            content = buffer.toString('utf8');
        }
        catch {
            return;
        }
        const ctx = (0, context_1.createFileContext)(file.absolutePath, rootDir, content, project);
        (0, attack_surface_1.inventoryFile)(ctx, attackSurface);
        const hash = (0, exports.contentHash)(content);
        const cached = existing?.files[file.relativePath];
        if (file.relativePath !== 'package.json' && cached && cached.hash === hash && existing?.project === cache.project && existing?.rules === rules_1.RULES_FINGERPRINT) {
            cacheHits += 1;
            filesScanned += 1;
            bytesScanned += file.bytes;
            findings.push(...cached.findings);
            cache.files[file.relativePath] = cached;
            options.onFile?.(file.relativePath, (index += 1), discovered.files.length);
            return;
        }
        const applicable = rules.filter((rule) => (!rule.appliesTo || rule.appliesTo(ctx)) && !rule.skipFlags?.some((flag) => ctx.flags[flag] === true));
        ruleInvocations += applicable.length;
        const fileFindings = [];
        for (const rule of applicable) {
            // Cheap probe first: most rules never run on most files.
            if (rule.contentHints?.length && !rule.contentHints.some((hint) => hint.test(content)))
                continue;
            let hits;
            try {
                hits = rule.detect(ctx);
            }
            catch {
                // A throwing rule must never abort a scan over an unrelated file.
                continue;
            }
            if (hits.length)
                fileFindings.push(...toFindings(ctx, rule, hits));
        }
        const parsed = parseSuppressions(ctx.lines);
        const { findings: kept, suppressed } = applySuppressions(fileFindings, parsed);
        suppressedCount += suppressed;
        const deduped = dedupe(kept);
        findings.push(...deduped);
        cache.files[file.relativePath] = { hash, findings: deduped, sizes: file.bytes };
        filesScanned += 1;
        bytesScanned += file.bytes;
        options.onFile?.(file.relativePath, (index += 1), discovered.files.length);
    };
    // Bounded-concurrency pool: I/O heavy, so a simple work queue beats threads.
    const queue = [...discovered.files];
    const workers = Array.from({ length: Math.min(concurrency, Math.max(1, queue.length)) }, async () => {
        for (;;) {
            const file = queue.shift();
            if (!file)
                return;
            await handleFile(file);
        }
    });
    await Promise.all(workers);
    (0, attack_surface_1.inventoryTables)(attackSurface, project, new Set(discovered.files.map(f => f.relativePath)));
    attackSurface.routes.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.method.localeCompare(b.method));
    attackSurface.aiEntrypoints.sort((a, b) => a.file.localeCompare(b.file));
    attackSurface.agentFiles.sort((a, b) => a.file.localeCompare(b.file));
    const unique = dedupe(findings);
    unique.sort((a, b) => types_1.SEVERITY_WEIGHT[b.severity] - types_1.SEVERITY_WEIGHT[a.severity] ||
        a.filePath.localeCompare(b.filePath) ||
        a.line - b.line ||
        a.column - b.column ||
        a.ruleId.localeCompare(b.ruleId));
    if (cacheEnabled)
        await writeCache(rootDir, cache);
    const finished = Date.now();
    const durationMs = Math.max(1, finished - started);
    const score = scoreFindings(unique);
    if (unique.length === 0 && discovered.files.length > 0) {
        notices.push(`No vulnerabilities found across ${discovered.files.length} files. Nice.`);
    }
    if (suppressedCount > 0) {
        notices.push(`${suppressedCount} finding${suppressedCount === 1 ? '' : 's'} suppressed by inline directives.`);
    }
    return {
        rootDir,
        command: 'scan',
        attackSurface,
        findings: unique,
        score,
        stats: {
            filesDiscovered: discovered.files.length + discovered.skipped,
            filesScanned,
            filesSkipped: discovered.skipped,
            bytesScanned,
            rulesExecuted: rules.length,
            ruleInvocations,
            cacheHits,
            durationMs,
            filesPerSecond: Math.round((filesScanned / durationMs) * 1000),
            megabytesPerSecond: Math.round((bytesScanned / 1024 / 1024 / durationMs) * 1000 * 100) / 100,
        },
        scannedPaths: discovered.files.map((file) => file.relativePath),
        startedAt: new Date(started).toISOString(),
        finishedAt: new Date(finished).toISOString(),
        version: await (0, version_1.packageVersion)(),
        ruleCount: rules.length,
        suppressedCount,
        notices,
    };
}
/** Remove duplicate findings (same rule, file, position and match). */
function dedupe(findings) {
    const seen = new Set();
    const out = [];
    for (const finding of findings) {
        const key = `${finding.ruleId}|${finding.filePath}|${finding.line}|${finding.column}|${finding.matched}`;
        if (seen.has(key))
            continue;
        seen.add(key);
        out.push(finding);
    }
    return out;
}
/** `--fail-on` helper shared by the CLI and the GitHub Action. */
const hasFindingsAtOrAbove = (result, threshold) => result.findings.some((finding) => (0, types_1.meetsSeverity)(finding.severity, threshold));
exports.hasFindingsAtOrAbove = hasFindingsAtOrAbove;
/** Paths tracked by git, used by the CLI's `--strict-gitignore` diagnostics. */
function gitTrackedPaths(rootDir) {
    try {
        const stdout = (0, node_child_process_1.execFileSync)('git', ['ls-files', '-z'], {
            cwd: rootDir,
            encoding: 'utf8',
            maxBuffer: 64 * 1024 * 1024,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        return stdout.split('\0').filter(Boolean).map(toPosix);
    }
    catch {
        return [];
    }
}
