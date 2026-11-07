/**
 * vibe-shield :: rule registry
 * ----------------------------
 * A stable, ordered catalogue of every rule the scanner ships. The MCP/skill
 * auditor (`src/mcp-guard/skill-auditor.ts`) owns the `VSB-AGENT-*` family and
 * is composed here so the CLI, the SARIF reporter and `--list-rules` all see a
 * single list.
 */
import type { Rule, RuleCategory } from '../types';
export { AI_VULNERABILITY_RULES } from './ai-vulnerabilities';
export { CLIENT_EXPOSURE_RULES } from './client-exposure';
export { DATABASE_EXPOSURE_RULES } from './database-exposure';
export { SECRET_ENTROPY_RULES } from './secret-entropy';
export { UNGUARDED_ROUTE_RULES } from './unguarded-routes';
export { defineRule, inScope, regexHits, bodyFrom, snippetAt, contains, message, fileHit } from './helpers';
/** Every rule that runs during `vibe-shield scan`. */
export declare const SCAN_RULES: readonly Rule[];
/** Every rule the tool knows about, including the agent-integrity family. */
export declare const ALL_RULES: readonly Rule[];
export declare function getRule(idOrSlug: string): Rule | undefined;
/** Rules in one category, in declaration order. */
export declare function rulesByCategory(category: RuleCategory): Rule[];
/** Filter a rule set by explicit ids/slugs (`--rules VSB-AI-001,VSB-DB-002`). */
export declare function selectRules(selectors: readonly string[], pool?: readonly Rule[]): Rule[];
/**
 * Deterministic fingerprint of the rule catalogue. Cached scan results are
 * invalidated when this changes, so a rule edit can never silently reuse an
 * older verdict.
 */
export declare const RULES_FINGERPRINT: string;
