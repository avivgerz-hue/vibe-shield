"use strict";
/**
 * vibe-shield :: shared rule vocabulary
 * ------------------------------------
 * Thin, reusable predicates used by more than one rule family. Nothing in this
 * module is heuristic-by-accident: every helper answers a single question about
 * a `FileContext` and is unit-tested through the rules that consume it.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SELF_INSTALL_SPECS = exports.SELF_GITHUB_SPEC = exports.confident = exports.handlerBody = exports.checksRole = exports.isBrowserFile = exports.verifiesAuth = exports.LOGIC_SKIP_FLAGS = exports.isSchemaFile = exports.isDataFile = exports.SERVER_CODE_LANGUAGES = exports.JS_LANGUAGES = exports.CWES = exports.cwe = void 0;
exports.isApplicationCode = isApplicationCode;
exports.offsetOf = offsetOf;
exports.escalate = escalate;
exports.isGitInstallArg = isGitInstallArg;
const lexicon_1 = require("../lexicon");
const text_1 = require("../text");
/** Build a `Cwe` record from an id and its short MITRE name. */
const cwe = (id, name) => ({
    id,
    name,
    url: `https://cwe.mitre.org/data/definitions/${id.replace(/\D/g, '')}.html`,
});
exports.cwe = cwe;
exports.CWES = {
    xss: (0, exports.cwe)('CWE-79', 'Improper Neutralization of Input During Web Page Generation'),
    commandInjection: (0, exports.cwe)('CWE-78', 'Improper Neutralization of Special Elements used in an OS Command'),
    sqlInjection: (0, exports.cwe)('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command'),
    codeInjection: (0, exports.cwe)('CWE-94', 'Improper Control of Generation of Code'),
    pathTraversal: (0, exports.cwe)('CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory'),
    hardcodedCredentials: (0, exports.cwe)('CWE-798', 'Use of Hard-coded Credentials'),
    missingAuth: (0, exports.cwe)('CWE-306', 'Missing Authentication for Critical Function'),
    missingAuthz: (0, exports.cwe)('CWE-862', 'Missing Authorization'),
    incorrectAuthz: (0, exports.cwe)('CWE-863', 'Incorrect Authorization'),
    improperAuthn: (0, exports.cwe)('CWE-287', 'Improper Authentication'),
    idor: (0, exports.cwe)('CWE-639', 'Authorization Bypass Through User-Controlled Key'),
    improperCertValidation: (0, exports.cwe)('CWE-347', 'Improper Verification of Cryptographic Signature'),
    signatureVerification: (0, exports.cwe)('CWE-345', 'Insufficient Verification of Data Authenticity'),
    exposureOfSecrets: (0, exports.cwe)('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor'),
    cleartextStorage: (0, exports.cwe)('CWE-312', 'Cleartext Storage of Sensitive Information'),
    credentialLeak: (0, exports.cwe)('CWE-540', 'Inclusion of Sensitive Information in Source Code'),
    secretInConfig: (0, exports.cwe)('CWE-526', 'Exposure of Sensitive Information Through Environmental Variables'),
    rlsDisabled: (0, exports.cwe)('CWE-284', 'Improper Access Control'),
    permissiveAcl: (0, exports.cwe)('CWE-732', 'Incorrect Permission Assignment for Critical Resource'),
    privilegeEscalation: (0, exports.cwe)('CWE-250', 'Execution with Unnecessary Privileges'),
    csrf: (0, exports.cwe)('CWE-352', 'Cross-Site Request Forgery'),
    openRedirect: (0, exports.cwe)('CWE-601', 'URL Redirection to Untrusted Site'),
    ssrf: (0, exports.cwe)('CWE-918', 'Server-Side Request Forgery'),
    unrestrictedUpload: (0, exports.cwe)('CWE-434', 'Unrestricted Upload of File with Dangerous Type'),
    resourceExhaustion: (0, exports.cwe)('CWE-770', 'Allocation of Resources Without Limits or Throttling'),
    deserialization: (0, exports.cwe)('CWE-502', 'Deserialization of Untrusted Data'),
    prototypePollution: (0, exports.cwe)('CWE-1321', 'Improperly Controlled Modification of Object Prototype Attributes'),
    promptInjection: (0, exports.cwe)('CWE-74', 'Improper Neutralization of Special Elements in Output'),
    weakCrypto: (0, exports.cwe)('CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm'),
    privateKey: (0, exports.cwe)('CWE-321', 'Use of Hard-coded Cryptographic Key'),
    defaultCredentials: (0, exports.cwe)('CWE-1392', 'Use of Default Credentials'),
    injection: (0, exports.cwe)('CWE-77', 'Improper Neutralization of Special Elements used in a Command'),
    dangerousFunction: (0, exports.cwe)('CWE-749', 'Exposed Dangerous Method or Function'),
    dependencyConfusion: (0, exports.cwe)('CWE-829', 'Inclusion of Functionality from Untrusted Control Sphere'),
    untrustedSearchPath: (0, exports.cwe)('CWE-1104', 'Use of Unmaintained Third Party Components'),
    browserSecurity: (0, exports.cwe)('CWE-942', 'Permissive Cross-domain Policy with Untrusted Domains'),
};
/** Languages we treat as JavaScript-family for brace/await reasoning. */
exports.JS_LANGUAGES = new Set(['typescript', 'javascript', 'jsx', 'vue', 'svelte']);
/** Languages that can contain an HTTP handler implemented in JS/TS. */
exports.SERVER_CODE_LANGUAGES = new Set([
    'typescript',
    'javascript',
    'jsx',
    'vue',
    'svelte',
    'python',
    'ruby',
    'php',
    'go',
    'java',
]);
/** True when the file is plain JSON/YAML/TOML data (no executable logic). */
const isDataFile = (ctx) => ctx.language === 'json' || ctx.language === 'yaml' || ctx.language === 'toml' || ctx.language === 'xml';
exports.isDataFile = isDataFile;
/** True when the file is a SQL/Prisma schema - i.e. DDL, not application code. */
const isSchemaFile = (ctx) => ctx.language === 'sql' || ctx.language === 'prisma' || ctx.extension === 'sql';
exports.isSchemaFile = isSchemaFile;
/** Shared "not a real target" predicate for application-code rules. */
function isApplicationCode(ctx) {
    return (!ctx.flags.isTestFile &&
        !ctx.flags.isDocumentation &&
        !ctx.flags.isLockfile &&
        !ctx.flags.isGenerated &&
        !ctx.flags.isEnvFile &&
        !ctx.flags.isMcpConfig &&
        !ctx.flags.isAgentInstructionFile);
}
/** Skip list used by every logic rule: tests, docs, generators, data files. */
exports.LOGIC_SKIP_FLAGS = [
    'isTestFile',
    'isDocumentation',
    'isLockfile',
    'isGenerated',
    'isEnvFile',
];
/** True when `ctx` contains an auth verification anywhere (session, jwt...). */
const verifiesAuth = (ctx) => lexicon_1.AUTH_VERIFICATION_REGEX.test(ctx.code);
exports.verifiesAuth = verifiesAuth;
/** True when the file ships to the browser (client directive or client-ish path). */
const isBrowserFile = (ctx) => ctx.flags.isClientComponent || ctx.flags.isClientPath;
exports.isBrowserFile = isBrowserFile;
/** True when `ctx` checks a role/permission/ownership claim. */
const checksRole = (ctx) => lexicon_1.ROLE_CHECK_REGEX.test(ctx.code);
exports.checksRole = checksRole;
/**
 * The body of a handler starting at `offset`, capped so a pathological file
 * cannot blow up quadratic brace scanning.
 */
const handlerBody = (ctx, offset) => (0, text_1.balancedBlock)(ctx.code, ctx.code.indexOf('{', offset), '{', '}').slice(0, 8000);
exports.handlerBody = handlerBody;
/** Locate the first occurrence of `needle` at or after `from`, else `from`. */
function offsetOf(source, needle, from = 0) {
    if (typeof needle === 'string') {
        const index = source.indexOf(needle, from);
        return index === -1 ? from : index;
    }
    const scoped = source.slice(from);
    const match = needle.exec(scoped);
    return match ? from + match.index : from;
}
/** Downgrade helper: severity only escalates (never de-escalates) a base value. */
function escalate(base, candidate) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    return order.indexOf(candidate) < order.indexOf(base) ? candidate : base;
}
/** Confidence bump used when a project-level signal corroborates a hit. */
const confident = (value, boost = false) => boost ? 'high' : value;
exports.confident = confident;
/**
 * This repository's canonical `github:` install coordinate.
 *
 * Single source of truth: `init` writes it into `.mcp.json`, and the auditor
 * recognises it there. Keeping one constant means the two can never drift.
 */
exports.SELF_GITHUB_SPEC = 'github:avivgerz-hue/vibe-shield';
/** First-party install specs the auditor vouches for without a `@sha`. */
exports.SELF_INSTALL_SPECS = [exports.SELF_GITHUB_SPEC];
/**
 * Recognise an `npx` argument that installs from a git host rather than from a
 * mutable registry tag.
 *
 * `github:owner/repo`, `gitlab:…`, `bitbucket:…` and explicit git URLs resolve
 * to a commit SHA instead of a semver tag, so they are not the "whatever the
 * registry published five minutes ago" risk that VSB-AGENT-004 exists to catch.
 *
 * This does **not** mean the pin is immutable: without a lockfile entry npm
 * re-resolves a bare `github:owner/repo` to the default branch head on every
 * fresh install. Callers are told to pin `#<sha>` for that. The narrower claim
 * — that it is not a mutable registry tag — is what is checkable here.
 */
function isGitInstallArg(arg) {
    return (/^(?:github|gitlab|bitbucket):[^/@\s]+\/[^/\s@]+(?:#[^\s]+)?$/i.test(arg) ||
        /^(?:git\+)?(?:https?|ssh|git):\/\/[^\s]+\.git(?:#[^\s]+)?$/i.test(arg) ||
        /^git@[^\s:]+:[^\s]+\.git(?:#[^\s]+)?$/i.test(arg) ||
        /^(?:git\+)?(?:github|gitlab|bitbucket):[^\s]+$/i.test(arg));
}
