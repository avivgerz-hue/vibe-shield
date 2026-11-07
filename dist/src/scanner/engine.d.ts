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
import { type FileContext, type Finding, type ProjectContext, type Rule, type RuleHit, type ScanResult, type SecurityScore, type Severity, type Suppression } from './types';
/** Directories that never contain first-party source. */
export declare const DEFAULT_IGNORED_DIRS: ReadonlySet<string>;
/** Extensions that are never source code (archives, media, binaries). */
export declare const BINARY_EXTENSIONS: ReadonlySet<string>;
/** Files larger than this are skipped (minified bundles, generated monsters). */
export declare const MAX_FILE_SIZE_BYTES = 1500000;
/** Default concurrency for the read pool. I/O-bound, so higher than CPU count. */
export declare const DEFAULT_CONCURRENCY = 32;
export interface ScanOptions {
    /** Root of the scan (absolute, or relative to `process.cwd()`). */
    rootDir: string;
    /** Explicit files/directories to scan (relative to `rootDir`). Default: all. */
    paths?: string[];
    /** Rule subset. Defaults to `SCAN_RULES`. */
    rules?: readonly Rule[];
    /** Extra gitignore-style patterns applied to the whole tree. */
    ignorePatterns?: string[];
    /** Include test/spec/fixture files (skipped by default). */
    includeTests?: boolean;
    /** Include docs/markdown (skipped by default, except agent files). */
    includeDocs?: boolean;
    /** Per-file size cap in bytes. */
    maxFileSizeBytes?: number;
    /** Read-pool size. */
    concurrency?: number;
    /** Persist and reuse `.vibe-shield-cache.json`. */
    cache?: boolean;
    /** Honour `.gitignore` files strictly (default: only the root ones). */
    strictGitignore?: boolean;
    /** Also honour `.gitignore` rules (default true). */
    useGitignore?: boolean;
    /** Disable the git-index lookup used by the `.env` rules. */
    useGitIndex?: boolean;
    /** Skip `.vibe-shieldignore` (still honours `.gitignore` unless disabled). */
    useShieldIgnore?: boolean;
    /** Extra suppression directives. */
    suppressions?: string[];
    /** Progress callback, one call per scanned file. */
    onFile?: (relativePath: string, index: number, total: number) => void;
    /** Called once the project context is resolved. */
    onProject?: (project: ProjectContext) => void;
}
/** A file selected for scanning. */
export interface DiscoveredFile {
    absolutePath: string;
    relativePath: string;
    bytes: number;
}
export interface DiscoverResult {
    files: DiscoveredFile[];
    skipped: number;
    /** Directories pruned during the walk. */
    pruned: number;
}
/** True when `relativePath` looks like a test/fixture/doc path. */
export declare const isTestPath: (relativePath: string) => boolean;
/** True when `relativePath` looks like documentation. */
export declare const isDocPath: (relativePath: string) => boolean;
/**
 * Walk `rootDir` and return every file that should be scanned.
 * Directory ignores are layered: built-in defaults, then every
 * `.gitignore` / `.vibe-shieldignore` / `.ignore` found on the way down.
 */
export declare function discoverFiles(rootDir: string, options?: ScanOptions): Promise<DiscoverResult>;
/**
 * Parse `vibe-shield-disable*` directives from a file.
 *
 *   // vibe-shield-disable-next-line VSB-DB-001 -- legacy table
 *   // vibe-shield-disable VSB-AI-014
 *   // vibe-shield-enable
 */
export declare function parseSuppressions(lines: readonly string[]): {
    fileWide: Suppression[];
    byLine: Map<number, Suppression>;
    ranges: Array<{
        from: number;
        to: number;
        ruleIds: string[];
        reason: string;
    }>;
};
/** True when the finding at `line` is suppressed (and why). */
export declare function suppressionFor(parsed: ReturnType<typeof parseSuppressions>, ruleId: string, line: number): Suppression | null;
/**
 * Apply suppressions to a finding list. Returns the kept findings plus the
 * number that were suppressed (the scorecard reports both).
 */
export declare function applySuppressions(findings: readonly Finding[], parsed: ReturnType<typeof parseSuppressions>): {
    findings: Finding[];
    suppressed: number;
};
/** Turn a finding list into a 0-100 score with an A+ → F grade. */
export declare function scoreFindings(findings: readonly Finding[]): SecurityScore;
export declare const CACHE_FILE_NAME = ".vibe-shield-cache.json";
export declare const CACHE_VERSION = 1;
/** Content hash used as the cache key for one file. */
export declare const contentHash: (content: string) => string;
/**
 * Run a rule set against one file context.
 * Exported because the MCP auditor reuses it: two scanners, one rule contract.
 */
export declare function runRulesOnFile(ctx: FileContext, rules: readonly Rule[]): RuleHit[];
/** Package version, resolved once from the nearest package.json. */
export declare function packageVersion(): Promise<string>;
/**
 * Scan a project. This is the one function the CLI, the tests and any embedding
 * application call; everything else in this module is an implementation detail.
 */
export declare function scanProject(options: ScanOptions): Promise<ScanResult>;
/** Remove duplicate findings (same rule, file, position and match). */
export declare function dedupe(findings: readonly Finding[]): Finding[];
/** `--fail-on` helper shared by the CLI and the GitHub Action. */
export declare const hasFindingsAtOrAbove: (result: ScanResult, threshold: Severity) => boolean;
/** Paths tracked by git, used by the CLI's `--strict-gitignore` diagnostics. */
export declare function gitTrackedPaths(rootDir: string): string[];
