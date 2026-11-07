"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.IgnoreMatcher = void 0;
exports.compileIgnorePattern = compileIgnorePattern;
exports.parseIgnoreFile = parseIgnoreFile;
const globToRegExpSource = (pattern) => {
    let source = '';
    for (let i = 0; i < pattern.length; i += 1) {
        const char = pattern[i];
        if (char === '*') {
            if (pattern[i + 1] === '*') {
                // consume the whole `**` run
                let j = i;
                while (pattern[j] === '*')
                    j += 1;
                const followedBySlash = pattern[j] === '/';
                const precededBySlash = i === 0 || pattern[i - 1] === '/';
                if (precededBySlash && followedBySlash) {
                    // `a/**/b` -> zero or more directories
                    source += '(?:[^/]+/)*';
                    i = j; // skip the trailing slash, it is part of the group
                    continue;
                }
                if (precededBySlash && j === pattern.length) {
                    // `a/**` -> everything below a
                    source += '.*';
                    i = j - 1;
                    continue;
                }
                if (i === 0 && followedBySlash) {
                    // `**/foo` -> foo at any depth
                    source += '(?:.*/)?';
                    i = j;
                    continue;
                }
                source += '.*';
                i = j - 1;
                continue;
            }
            source += '[^/]*';
            continue;
        }
        if (char === '?') {
            source += '[^/]';
            continue;
        }
        if (char === '[') {
            const end = pattern.indexOf(']', i + 1);
            if (end !== -1) {
                let body = pattern.slice(i + 1, end);
                if (body.startsWith('!') || body.startsWith('^'))
                    body = `^${body.slice(1)}`;
                source += `[${body.replace(/\\/g, '\\\\')}]`;
                i = end;
                continue;
            }
            source += '\\[';
            continue;
        }
        if (char === '\\') {
            const nxt = pattern[i + 1];
            if (nxt !== undefined) {
                source += nxt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                i += 1;
                continue;
            }
        }
        source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    return source;
};
/** Compile a single gitignore pattern into a rule. Returns null for comments/blanks. */
function compileIgnorePattern(rawPattern, base, source) {
    let pattern = rawPattern.replace(/\s+$/, '');
    if (!pattern.length || pattern.startsWith('#'))
        return null;
    let negated = false;
    if (pattern.startsWith('!')) {
        negated = true;
        pattern = pattern.slice(1);
    }
    else if (pattern.startsWith('\\#') || pattern.startsWith('\\!')) {
        pattern = pattern.slice(1);
    }
    if (!pattern.length)
        return null;
    let dirOnly = false;
    if (pattern.endsWith('/')) {
        dirOnly = true;
        pattern = pattern.slice(0, -1);
    }
    if (!pattern.length)
        return null;
    const anchored = pattern.startsWith('/') || pattern.slice(0, -1).includes('/');
    if (pattern.startsWith('/'))
        pattern = pattern.slice(1);
    if (!pattern.length)
        return null;
    const body = globToRegExpSource(pattern);
    const prefix = anchored ? '' : '(?:.*/)?';
    const regex = new RegExp(`^${prefix}${body}${dirOnly ? '(?:/.*)?' : '(?:/.*)?'}$`);
    return { base, regex, negated, dirOnly, pattern: rawPattern, source };
}
/** Parse the text of an ignore file into rules. */
function parseIgnoreFile(text, base, source) {
    const rules = [];
    for (const line of text.split(/\r?\n/)) {
        const rule = compileIgnorePattern(line, base, source);
        if (rule)
            rules.push(rule);
    }
    return rules;
}
/** Ordered, immutable ignore rule set for one scan. */
class IgnoreMatcher {
    rules = [];
    alwaysIgnore;
    constructor(options = {}) {
        this.alwaysIgnore = new Set(options.alwaysIgnore ?? ['.git']);
        for (const pattern of options.extraPatterns ?? []) {
            const rule = compileIgnorePattern(pattern, '', '<cli>');
            if (rule)
                this.rules.push(rule);
        }
    }
    /** Add rules from an ignore file located at `base` (POSIX, '' for root). */
    addIgnoreFile(text, base, source) {
        this.rules.push(...parseIgnoreFile(text, base, source));
    }
    addRule(pattern, base = '', source = '<config>') {
        const rule = compileIgnorePattern(pattern, base, source);
        if (rule)
            this.rules.push(rule);
    }
    get ruleCount() {
        return this.rules.length;
    }
    /** Result of a lookup: ignored, kept, or undecided (no rule matched). */
    match(relPath, isDirectory) {
        let result = null;
        for (const rule of this.rules) {
            if (rule.base) {
                if (!relPath.startsWith(`${rule.base}/`))
                    continue;
            }
            const scoped = rule.base ? relPath.slice(rule.base.length + 1) : relPath;
            if (!scoped.length)
                continue;
            if (rule.dirOnly && !isDirectory) {
                // A directory-only rule still excludes everything below that directory.
                const segments = scoped.split('/');
                let matchedParent = false;
                for (let i = 1; i < segments.length; i += 1) {
                    if (rule.regex.test(segments.slice(0, i).join('/'))) {
                        matchedParent = true;
                        break;
                    }
                }
                if (!matchedParent)
                    continue;
            }
            else if (!rule.regex.test(scoped)) {
                continue;
            }
            result = !rule.negated;
        }
        return result;
    }
    /**
     * True when `relPath` (POSIX, relative to the scan root) must be skipped.
     * Implements the git rule that a file inside an excluded directory can never
     * be re-included.
     */
    isIgnored(relPath, isDirectory) {
        const segments = relPath.split('/');
        if (segments.some((segment) => this.alwaysIgnore.has(segment)))
            return true;
        for (let i = 1; i < segments.length; i += 1) {
            if (this.match(segments.slice(0, i).join('/'), true) === true)
                return true;
        }
        return this.match(relPath, isDirectory) === true;
    }
}
exports.IgnoreMatcher = IgnoreMatcher;
