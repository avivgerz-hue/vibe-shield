"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.clientReachableModules = clientReachableModules;
/** Best-effort static client import graph; not a substitute for bundler analysis. */
const path = __importStar(require("node:path"));
/** Resolve relative and root tsconfig/jsconfig path aliases, then follow imports transitively. */
function clientReachableModules(modules, config = {}) {
    const files = new Map(modules.map(file => [file.path, file.code]));
    const base = path.posix.normalize(typeof config.baseUrl === 'string' ? config.baseUrl : '.');
    const paths = config.paths && typeof config.paths === 'object' && !Array.isArray(config.paths) ? config.paths : {};
    const extensions = ['', '.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs', '/index.ts', '/index.tsx', '/index.js', '/index.jsx'];
    const resolve = (from, spec) => {
        const candidates = [];
        if (spec.startsWith('.'))
            candidates.push(path.posix.join(path.posix.dirname(from), spec));
        else {
            for (const [pattern, targets] of Object.entries(paths)) {
                const star = pattern.indexOf('*');
                const before = star < 0 ? pattern : pattern.slice(0, star);
                const after = star < 0 ? '' : pattern.slice(star + 1);
                if (star < 0 ? spec !== pattern : !spec.startsWith(before) || !spec.endsWith(after))
                    continue;
                const part = star < 0 ? '' : spec.slice(before.length, spec.length - after.length);
                for (const target of Array.isArray(targets) ? targets : [])
                    if (typeof target === 'string')
                        candidates.push(path.posix.join(base, target.replace('*', part)));
            }
        }
        const resolved = [];
        for (const candidate of candidates) {
            // TS source commonly imports a .js path, resolved to .ts by the compiler.
            const variants = [candidate, candidate.replace(/\.(?:mjs|cjs|js)$/, '.ts')];
            for (const variant of variants)
                for (const extension of extensions) {
                    const file = path.posix.normalize(variant + extension).replace(/^\.\//, '');
                    if (files.has(file) && !resolved.includes(file))
                        resolved.push(file);
                }
        }
        return resolved;
    };
    const imports = (code) => {
        const found = [];
        const patterns = [
            /\b(?:import|export)\s+(?!type\b)[^;\n]*?\s+from\s*['"]([^'"]+)['"]/g,
            /\bimport\s*['"]([^'"]+)['"]/g,
            /\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
        ];
        for (const pattern of patterns)
            for (const match of code.matchAll(pattern))
                if (match[1])
                    found.push(match[1]);
        return found;
    };
    const reached = new Set();
    const queue = modules.filter(file => /^\s*(?:['"]use strict['"]\s*;\s*)*['"]use client['"]\s*(?:;|$|\r?\n)/.test(file.code)).map(file => file.path);
    while (queue.length) {
        const file = queue.shift();
        if (reached.has(file))
            continue;
        reached.add(file);
        for (const spec of imports(files.get(file) ?? ''))
            for (const target of resolve(file, spec))
                if (!reached.has(target))
                    queue.push(target);
    }
    return [...reached].sort();
}
