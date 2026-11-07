/**
 * vibe-shield :: rule authoring helpers
 * -------------------------------------
 * `defineRule` removes all boilerplate: a rule declares *what it matches* and
 * the helper derives scope filtering (`extensions`, `languages`, path regexes,
 * skipped file kinds) so the engine can cheaply decide whether to run it.
 */
import type { FileContext, Rule, RuleHit } from '../types';
export type RuleDefinition = Omit<Rule, 'appliesTo'> & {
    /** Custom scope predicate; overrides the declarative fields when provided. */
    appliesTo?: (ctx: FileContext) => boolean;
};
/** Does this file match the declarative scope of a rule? */
export declare function inScope(def: RuleDefinition, ctx: FileContext): boolean;
/** Create a fully-formed rule object. */
export declare function defineRule(def: RuleDefinition): Rule;
/** Every match of `regex` inside `source` as rule hits. */
export declare function regexHits(source: string, regex: RegExp, map?: (match: RegExpExecArray) => Partial<RuleHit> | null | undefined): RuleHit[];
/** The `{...}` (or `(...)`) body that starts at/after `offset`. */
export declare function bodyFrom(source: string, offset: number, open?: '{' | '('): string;
/** Convenience: read one source line, trimmed for reporting. */
export declare const snippetAt: (ctx: FileContext, line: number) => string;
/** True when `needle` (regex) appears inside `haystack`. */
export declare const contains: (haystack: string, needle: RegExp) => boolean;
/** Build a message that always ends with a period and never leaks a secret. */
export declare const message: (base: string, detail?: string) => string;
/**
 * Some rules need to inspect the *rest of the file* rather than a single
 * match. `fileHit` produces exactly one hit anchored at `line`.
 */
export declare function fileHit(line: number, extra?: Partial<RuleHit>): RuleHit;
