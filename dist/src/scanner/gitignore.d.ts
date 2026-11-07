/**
 * vibe-shield :: .gitignore engine
 * --------------------------------
 * A dependency-free implementation of the gitignore specification:
 * negation (`!`), directory-only patterns (`foo/`), anchoring (`/foo`,
 * `a/b`), `**` wildcards, character classes and nested ignore files.
 *
 * Every ignore file is compiled once into an ordered rule list; lookups are
 * O(rules) with an early prefix check, which keeps a 100k-file tree fast.
 */
export interface IgnoreRule {
    /** Directory the rule is relative to (POSIX, '' = repo root). */
    base: string;
    regex: RegExp;
    negated: boolean;
    dirOnly: boolean;
    /** Original pattern, used in `--explain-ignores` style debugging. */
    pattern: string;
    /** Source file the rule came from. */
    source: string;
}
/** Compile a single gitignore pattern into a rule. Returns null for comments/blanks. */
export declare function compileIgnorePattern(rawPattern: string, base: string, source: string): IgnoreRule | null;
/** Parse the text of an ignore file into rules. */
export declare function parseIgnoreFile(text: string, base: string, source: string): IgnoreRule[];
export interface IgnoreMatcherOptions {
    /** Always-ignored directory names, regardless of ignore files. */
    alwaysIgnore?: string[];
    /** Extra CLI/config globs (treated as ignore rules rooted at the scan root). */
    extraPatterns?: string[];
}
/** Ordered, immutable ignore rule set for one scan. */
export declare class IgnoreMatcher {
    private readonly rules;
    private readonly alwaysIgnore;
    constructor(options?: IgnoreMatcherOptions);
    /** Add rules from an ignore file located at `base` (POSIX, '' for root). */
    addIgnoreFile(text: string, base: string, source: string): void;
    addRule(pattern: string, base?: string, source?: string): void;
    get ruleCount(): number;
    /** Result of a lookup: ignored, kept, or undecided (no rule matched). */
    private match;
    /**
     * True when `relPath` (POSIX, relative to the scan root) must be skipped.
     * Implements the git rule that a file inside an excluded directory can never
     * be re-included.
     */
    isIgnored(relPath: string, isDirectory: boolean): boolean;
}
