"use strict";
/**
 * vibe-shield :: rule registry
 * ----------------------------
 * A stable, ordered catalogue of every rule the scanner ships. The MCP/skill
 * auditor (`src/mcp-guard/skill-auditor.ts`) owns the `VSB-AGENT-*` family and
 * is composed here so the CLI, the SARIF reporter and `--list-rules` all see a
 * single list.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULES_FINGERPRINT = exports.ALL_RULES = exports.SCAN_RULES = exports.fileHit = exports.message = exports.contains = exports.snippetAt = exports.bodyFrom = exports.regexHits = exports.inScope = exports.defineRule = exports.UNGUARDED_ROUTE_RULES = exports.SECRET_ENTROPY_RULES = exports.DATABASE_EXPOSURE_RULES = exports.CLIENT_EXPOSURE_RULES = exports.AI_VULNERABILITY_RULES = void 0;
exports.getRule = getRule;
exports.rulesByCategory = rulesByCategory;
exports.selectRules = selectRules;
const ai_vulnerabilities_1 = require("./ai-vulnerabilities");
const client_exposure_1 = require("./client-exposure");
const database_exposure_1 = require("./database-exposure");
const secret_entropy_1 = require("./secret-entropy");
const unguarded_routes_1 = require("./unguarded-routes");
const skill_auditor_1 = require("../../mcp-guard/skill-auditor");
var ai_vulnerabilities_2 = require("./ai-vulnerabilities");
Object.defineProperty(exports, "AI_VULNERABILITY_RULES", { enumerable: true, get: function () { return ai_vulnerabilities_2.AI_VULNERABILITY_RULES; } });
var client_exposure_2 = require("./client-exposure");
Object.defineProperty(exports, "CLIENT_EXPOSURE_RULES", { enumerable: true, get: function () { return client_exposure_2.CLIENT_EXPOSURE_RULES; } });
var database_exposure_2 = require("./database-exposure");
Object.defineProperty(exports, "DATABASE_EXPOSURE_RULES", { enumerable: true, get: function () { return database_exposure_2.DATABASE_EXPOSURE_RULES; } });
var secret_entropy_2 = require("./secret-entropy");
Object.defineProperty(exports, "SECRET_ENTROPY_RULES", { enumerable: true, get: function () { return secret_entropy_2.SECRET_ENTROPY_RULES; } });
var unguarded_routes_2 = require("./unguarded-routes");
Object.defineProperty(exports, "UNGUARDED_ROUTE_RULES", { enumerable: true, get: function () { return unguarded_routes_2.UNGUARDED_ROUTE_RULES; } });
var helpers_1 = require("./helpers");
Object.defineProperty(exports, "defineRule", { enumerable: true, get: function () { return helpers_1.defineRule; } });
Object.defineProperty(exports, "inScope", { enumerable: true, get: function () { return helpers_1.inScope; } });
Object.defineProperty(exports, "regexHits", { enumerable: true, get: function () { return helpers_1.regexHits; } });
Object.defineProperty(exports, "bodyFrom", { enumerable: true, get: function () { return helpers_1.bodyFrom; } });
Object.defineProperty(exports, "snippetAt", { enumerable: true, get: function () { return helpers_1.snippetAt; } });
Object.defineProperty(exports, "contains", { enumerable: true, get: function () { return helpers_1.contains; } });
Object.defineProperty(exports, "message", { enumerable: true, get: function () { return helpers_1.message; } });
Object.defineProperty(exports, "fileHit", { enumerable: true, get: function () { return helpers_1.fileHit; } });
/** Every rule that runs during `vibe-shield scan`. */
exports.SCAN_RULES = [
    ...client_exposure_1.CLIENT_EXPOSURE_RULES,
    ...unguarded_routes_1.UNGUARDED_ROUTE_RULES,
    ...database_exposure_1.DATABASE_EXPOSURE_RULES,
    ...ai_vulnerabilities_1.AI_VULNERABILITY_RULES,
    ...secret_entropy_1.SECRET_ENTROPY_RULES,
];
/** Every rule the tool knows about, including the agent-integrity family. */
exports.ALL_RULES = [...exports.SCAN_RULES, ...skill_auditor_1.AGENT_RULES];
/** Lookup by exact rule id (case-insensitive). */
const BY_ID = new Map(exports.ALL_RULES.map((rule) => [rule.id.toUpperCase(), rule]));
/** Lookup by slug (case-insensitive), for `explain <slug>` convenience. */
const BY_SLUG = new Map(exports.ALL_RULES.map((rule) => [rule.slug.toLowerCase(), rule]));
function getRule(idOrSlug) {
    return BY_ID.get(idOrSlug.trim().toUpperCase()) ?? BY_SLUG.get(idOrSlug.trim().toLowerCase());
}
/** Rules in one category, in declaration order. */
function rulesByCategory(category) {
    return exports.ALL_RULES.filter((rule) => rule.category === category);
}
/** Filter a rule set by explicit ids/slugs (`--rules VSB-AI-001,VSB-DB-002`). */
function selectRules(selectors, pool = exports.ALL_RULES) {
    if (!selectors.length)
        return [...pool];
    const wanted = new Set();
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
            if (regex.test(candidate.id))
                wanted.add(candidate.id);
        }
    }
    return pool.filter((rule) => wanted.has(rule.id));
}
/**
 * Deterministic fingerprint of the rule catalogue. Cached scan results are
 * invalidated when this changes, so a rule edit can never silently reuse an
 * older verdict.
 */
exports.RULES_FINGERPRINT = (() => {
    const payload = exports.ALL_RULES.map((rule) => `${rule.id}:${rule.severity}:${rule.title}`).join('|');
    let hash = 0x811c9dc5;
    for (let i = 0; i < payload.length; i += 1) {
        hash ^= payload.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return `${exports.ALL_RULES.length}-${hash.toString(16)}`;
})();
