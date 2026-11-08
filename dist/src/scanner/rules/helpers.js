"use strict";
/**
 * vibe-shield :: rule authoring helpers
 * -------------------------------------
 * `defineRule` removes all boilerplate: a rule declares *what it matches* and
 * the helper derives scope filtering (`extensions`, `languages`, path regexes,
 * skipped file kinds) so the engine can cheaply decide whether to run it.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.message = exports.contains = exports.snippetAt = void 0;
exports.inScope = inScope;
exports.defineRule = defineRule;
exports.regexHits = regexHits;
exports.bodyFrom = bodyFrom;
exports.fileHit = fileHit;
const mappings_1 = require("../mappings");
const text_1 = require("../text");
/** Does this file match the declarative scope of a rule? */
function inScope(def, ctx) {
    if (def.skipFlags?.some((flag) => ctx.flags[flag] === true))
        return false;
    if (def.languages?.length && !def.languages.includes(ctx.language))
        return false;
    if (def.extensions?.length) {
        const extension = ctx.extension || ctx.fileName.toLowerCase();
        if (!def.extensions.includes(extension))
            return false;
    }
    if (def.pathPatterns?.length && !def.pathPatterns.some((re) => re.test(ctx.relativePath)))
        return false;
    if (def.excludePathPatterns?.some((re) => re.test(ctx.relativePath)))
        return false;
    return true;
}
/** Create a fully-formed rule object. */
function defineRule(def) {
    const custom = def.appliesTo;
    const rule = {
        ...def,
        owasp: def.owasp ?? (0, mappings_1.owaspMappings)(def.id, def.cwe.id),
        appliesTo: (ctx) => (custom ? custom(ctx) && inScope(def, ctx) : inScope(def, ctx)),
    };
    return rule;
}
/** Every match of `regex` inside `source` as rule hits. */
function regexHits(source, regex, map) {
    const hits = [];
    const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
    let match;
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
        if (re.lastIndex === match.index)
            re.lastIndex += 1;
    }
    return hits;
}
/** The `{...}` (or `(...)`) body that starts at/after `offset`. */
function bodyFrom(source, offset, open = '{') {
    const close = open === '{' ? '}' : ')';
    return (0, text_1.balancedBlock)(source, (0, text_1.nextBrace)(source, offset), open, close);
}
/** Convenience: read one source line, trimmed for reporting. */
const snippetAt = (ctx, line) => (0, text_1.trimSnippet)(ctx.lineText(line));
exports.snippetAt = snippetAt;
/** True when `needle` (regex) appears inside `haystack`. */
const contains = (haystack, needle) => needle.test(haystack);
exports.contains = contains;
/** Build a message that always ends with a period and never leaks a secret. */
const message = (base, detail) => detail ? `${base.replace(/\.$/, '')} — ${detail}` : base;
exports.message = message;
/**
 * Some rules need to inspect the *rest of the file* rather than a single
 * match. `fileHit` produces exactly one hit anchored at `line`.
 */
function fileHit(line, extra = {}) {
    return { line, ...extra };
}
