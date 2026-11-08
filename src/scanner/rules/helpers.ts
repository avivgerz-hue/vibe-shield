/**
 * vibe-shield :: rule authoring helpers
 * -------------------------------------
 * `defineRule` removes all boilerplate: a rule declares *what it matches* and
 * the helper derives scope filtering (`extensions`, `languages`, path regexes,
 * skipped file kinds) so the engine can cheaply decide whether to run it.
 */

import { owaspMappings } from '../mappings';
import { balancedBlock, nextBrace, trimSnippet } from '../text';
import type { FileContext, Rule, RuleHit } from '../types';

export type RuleDefinition = Omit<Rule, 'appliesTo'> & {
  /** Custom scope predicate; overrides the declarative fields when provided. */
  appliesTo?: (ctx: FileContext) => boolean;
};

/** Does this file match the declarative scope of a rule? */
export function inScope(def: RuleDefinition, ctx: FileContext): boolean {
  if (def.skipFlags?.some((flag) => ctx.flags[flag] === true)) return false;
  if (def.languages?.length && !def.languages.includes(ctx.language)) return false;
  if (def.extensions?.length) {
    const extension = ctx.extension || ctx.fileName.toLowerCase();
    if (!def.extensions.includes(extension)) return false;
  }
  if (def.pathPatterns?.length && !def.pathPatterns.some((re) => re.test(ctx.relativePath))) return false;
  if (def.excludePathPatterns?.some((re) => re.test(ctx.relativePath))) return false;
  return true;
}

/** Create a fully-formed rule object. */
export function defineRule(def: RuleDefinition): Rule {
  const custom = def.appliesTo;
  const rule: Rule = {
    ...def,
    owasp: def.owasp ?? owaspMappings(def.id, def.cwe.id),
    appliesTo: (ctx) => (custom ? custom(ctx) && inScope(def, ctx) : inScope(def, ctx)),
  };
  return rule;
}

/** Every match of `regex` inside `source` as rule hits. */
export function regexHits(
  source: string,
  regex: RegExp,
  map?: (match: RegExpExecArray) => Partial<RuleHit> | null | undefined,
): RuleHit[] {
  const hits: RuleHit[] = [];
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  let match: RegExpExecArray | null;
  let guard = 0;
  while ((match = re.exec(source)) !== null && guard < 20_000) {
    guard += 1;
    if (match[0].length === 0) {
      re.lastIndex += 1;
      continue;
    }
    const extra = map ? map(match) : undefined;
    if (extra === null) {
      continue;
    }
    hits.push({ offset: match.index, matched: match[0], ...(extra ?? {}) });
    if (re.lastIndex === match.index) re.lastIndex += 1;
  }
  return hits;
}

/** The `{...}` (or `(...)`) body that starts at/after `offset`. */
export function bodyFrom(source: string, offset: number, open: '{' | '(' = '{'): string {
  const close = open === '{' ? '}' : ')';
  return balancedBlock(source, nextBrace(source, offset), open, close);
}

/** Convenience: read one source line, trimmed for reporting. */
export const snippetAt = (ctx: FileContext, line: number): string => trimSnippet(ctx.lineText(line));

/** True when `needle` (regex) appears inside `haystack`. */
export const contains = (haystack: string, needle: RegExp): boolean => needle.test(haystack);

/** Build a message that always ends with a period and never leaks a secret. */
export const message = (base: string, detail?: string): string =>
  detail ? `${base.replace(/\.$/, '')} — ${detail}` : base;

/**
 * Some rules need to inspect the *rest of the file* rather than a single
 * match. `fileHit` produces exactly one hit anchored at `line`.
 */
export function fileHit(line: number, extra: Partial<RuleHit> = {}): RuleHit {
  return { line, ...extra };
}
