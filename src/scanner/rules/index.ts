/**
 * vibe-shield :: rule registry
 * ----------------------------
 * A stable, ordered catalogue of every rule the scanner ships. The MCP/skill
 * auditor (`src/mcp-guard/skill-auditor.ts`) owns the `VSB-AGENT-*` family and
 * is composed here so the CLI, the SARIF reporter and `--list-rules` all see a
 * single list.
 */

import { HARDENING_RULES, MISSING_LOCKFILE_RULE, DOCKER_DEFAULT_ROOT_RULE } from './hardening';
import { AI_VULNERABILITY_RULES } from './ai-vulnerabilities';
import { CLIENT_EXPOSURE_RULES } from './client-exposure';
import { DATABASE_EXPOSURE_RULES } from './database-exposure';
import { SECRET_ENTROPY_RULES } from './secret-entropy';
import { UNGUARDED_ROUTE_RULES } from './unguarded-routes';
import { AGENT_RULES } from '../../mcp-guard/skill-auditor';
import type { Rule, RuleCategory } from '../types';

export { AI_VULNERABILITY_RULES } from './ai-vulnerabilities';
export { CLIENT_EXPOSURE_RULES } from './client-exposure';
export { DATABASE_EXPOSURE_RULES } from './database-exposure';
export { SECRET_ENTROPY_RULES } from './secret-entropy';
export { UNGUARDED_ROUTE_RULES } from './unguarded-routes';
export { defineRule, inScope, regexHits, bodyFrom, snippetAt, contains, message, fileHit } from './helpers';

/** Every rule that runs during `vibe-shield scan`. */
export const SCAN_RULES: readonly Rule[] = [
  ...CLIENT_EXPOSURE_RULES,
  ...UNGUARDED_ROUTE_RULES,
  ...DATABASE_EXPOSURE_RULES,
  ...AI_VULNERABILITY_RULES,
  ...SECRET_ENTROPY_RULES,
  ...HARDENING_RULES,
  MISSING_LOCKFILE_RULE,
  DOCKER_DEFAULT_ROOT_RULE,
];

/** Every rule the tool knows about, including the agent-integrity family. */
export const ALL_RULES: readonly Rule[] = [...SCAN_RULES, ...AGENT_RULES];

/** Lookup by exact rule id (case-insensitive). */
const BY_ID = new Map(ALL_RULES.map((rule) => [rule.id.toUpperCase(), rule]));

/** Lookup by slug (case-insensitive), for `explain <slug>` convenience. */
const BY_SLUG = new Map(ALL_RULES.map((rule) => [rule.slug.toLowerCase(), rule]));

export function getRule(idOrSlug: string): Rule | undefined {
  return BY_ID.get(idOrSlug.trim().toUpperCase()) ?? BY_SLUG.get(idOrSlug.trim().toLowerCase());
}

/** Rules in one category, in declaration order. */
export function rulesByCategory(category: RuleCategory): Rule[] {
  return ALL_RULES.filter((rule) => rule.category === category);
}

/** Filter a rule set by explicit ids/slugs (`--rules VSB-AI-001,VSB-DB-002`). */
export function selectRules(selectors: readonly string[], pool: readonly Rule[] = ALL_RULES): Rule[] {
  if (!selectors.length) return [...pool];
  const wanted = new Set<string>();
  for (const selector of selectors) {
    const rule = getRule(selector);
    if (rule) {
      wanted.add(rule.id);
      continue;
    }
    // Allow prefix / glob-ish selectors: `VSB-DB-*`, `VSB-AI`.
    const pattern = selector.trim().toUpperCase().replace(/[.+]/g, (c) => `\\${c}`).replace(/\*/g, '');
    const regex = new RegExp(`^${pattern}`, 'i');
    for (const candidate of pool) {
      if (regex.test(candidate.id)) wanted.add(candidate.id);
    }
  }
  return pool.filter((rule) => wanted.has(rule.id));
}

/**
 * Deterministic fingerprint of the rule catalogue. Cached scan results are
 * invalidated when this changes, so a rule edit can never silently reuse an
 * older verdict.
 */
export const RULES_FINGERPRINT: string = (() => {
  const payload = ALL_RULES.map((rule) => `${rule.id}:${rule.severity}:${rule.title}`).join('|');
  let hash = 0x811c9dc5;
  for (let i = 0; i < payload.length; i += 1) {
    hash ^= payload.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${ALL_RULES.length}-${hash.toString(16)}`;
})();
