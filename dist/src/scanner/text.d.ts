/**
 * vibe-shield :: text primitives
 * ------------------------------
 * Zero-dependency helpers shared by every rule. The most important one is
 * `maskComments`: it blanks out comments while preserving the exact character
 * length of the file, so byte offsets (and therefore line/column numbers)
 * stay identical between the raw source and the "code only" view that rules
 * match against. That single trick removes the largest class of false
 * positives (vulnerabilities that only exist inside a comment) without a
 * real parser.
 */
import type { Language } from './types';
/** Incremental offset -> line/column resolver. */
export declare class LineIndex {
    private readonly content;
    private readonly starts;
    constructor(content: string);
    get lineCount(): number;
    /** 1-based line and column for a character offset. */
    locate(offset: number): {
        line: number;
        column: number;
    };
    /** Offset of the first character of a 1-based line. */
    lineStart(line: number): number;
}
/** Split content into lines without the trailing newline characters. */
export declare const splitLines: (content: string) => string[];
/**
 * Iterate every match of `regex` (which must be global) over `content`.
 * Guards against zero-length infinite loops.
 */
export declare function forEachMatch(content: string, regex: RegExp, handler: (match: RegExpExecArray) => void): void;
/** All matches of a global regex, as `{ text, offset }`. */
export declare function collectMatches(content: string, regex: RegExp): Array<{
    text: string;
    offset: number;
    match: RegExpExecArray;
}>;
/** Shannon entropy in bits per character. */
export declare function shannonEntropy(value: string): number;
/** Size of the character alphabet actually used (hex, base64, mixed-case...). */
export declare const alphabetSize: (value: string) => number;
/**
 * True when a candidate secret is obviously not a real credential: template
 * syntax, environment references, masked output, repeated characters or
 * documentation placeholders.
 */
export declare function isPlaceholderSecret(value: string): boolean;
/**
 * Mask a credential for terminal/JSON/SARIF output. Keeps a short prefix and
 * the final two characters so a human can identify *which* key leaked without
 * re-publishing the secret in a CI log.
 */
export declare function redactSecret(value: string, keepPrefix?: number): string;
/** Escape a string for safe inclusion in a RegExp. */
export declare const escapeRegExp: (value: string) => string;
/** Build a case-insensitive "any of these words" regex source fragment. */
export declare const alternation: (words: readonly string[]) => string;
/**
 * Blank out comments for C-like languages (JS/TS/JSX/Java/Go/Rust/C#/PHP-ish),
 * preserving string, template-literal and (best-effort) regex-literal bodies
 * and the overall character length of the input.
 */
export declare function maskCStyleComments(source: string): string;
/** Blank out `--` and `/* *\/` comments in SQL / Prisma. */
export declare function maskSqlComments(source: string): string;
/** Blank out `#` comments in shell / YAML / TOML / dotenv / Dockerfile. */
export declare function maskHashComments(source: string): string;
/** Blank out Python/Ruby `#` comments (strings preserved). */
export declare const maskPythonComments: typeof maskHashComments;
/**
 * Pick the right comment masker for a language. Markdown, HTML and JSON are
 * returned untouched on purpose: hidden instructions inside HTML comments are
 * exactly what the agent-integrity rules need to see.
 */
export declare function maskComments(source: string, language: Language): string;
/** Indentation-preserving trim used for snippets in reports. */
export declare function trimSnippet(line: string, max?: number): string;
/** Join a window of source lines around `line` (1-based) for context blocks. */
export declare function contextWindow(lines: string[], line: number, radius?: number): string[];
/**
 * Extract a balanced `{...}` / `(...)` block starting at `openIndex`.
 * Returns the slice (inclusive of both braces) or an empty string.
 */
export declare function balancedBlock(source: string, openIndex: number, open?: string, close?: string): string;
/** Find the offset of the first `{` at/after `from`. */
export declare const nextBrace: (source: string, from: number) => number;
/** Naive but effective "is this a dynamic string?" probe for injection rules. */
export declare const looksDynamic: (fragment: string) => boolean;
