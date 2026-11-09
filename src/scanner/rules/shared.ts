/**
 * vibe-shield :: shared rule vocabulary
 * ------------------------------------
 * Thin, reusable predicates used by more than one rule family. Nothing in this
 * module is heuristic-by-accident: every helper answers a single question about
 * a `FileContext` and is unit-tested through the rules that consume it.
 */

import { AUTH_VERIFICATION_REGEX, ROLE_CHECK_REGEX } from '../lexicon';
import { balancedBlock } from '../text';
import type { Cwe, Confidence, FileContext, Severity } from '../types';

/** Build a `Cwe` record from an id and its short MITRE name. */
export const cwe = (id: string, name: string): Cwe => ({
  id,
  name,
  url: `https://cwe.mitre.org/data/definitions/${id.replace(/\D/g, '')}.html`,
});

export const CWES = {
  xss: cwe('CWE-79', 'Improper Neutralization of Input During Web Page Generation'),
  commandInjection: cwe('CWE-78', 'Improper Neutralization of Special Elements used in an OS Command'),
  sqlInjection: cwe('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command'),
  codeInjection: cwe('CWE-94', 'Improper Control of Generation of Code'),
  pathTraversal: cwe('CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory'),
  hardcodedCredentials: cwe('CWE-798', 'Use of Hard-coded Credentials'),
  missingAuth: cwe('CWE-306', 'Missing Authentication for Critical Function'),
  missingAuthz: cwe('CWE-862', 'Missing Authorization'),
  incorrectAuthz: cwe('CWE-863', 'Incorrect Authorization'),
  improperAuthn: cwe('CWE-287', 'Improper Authentication'),
  idor: cwe('CWE-639', 'Authorization Bypass Through User-Controlled Key'),
  improperCertValidation: cwe('CWE-347', 'Improper Verification of Cryptographic Signature'),
  signatureVerification: cwe('CWE-345', 'Insufficient Verification of Data Authenticity'),
  exposureOfSecrets: cwe('CWE-200', 'Exposure of Sensitive Information to an Unauthorized Actor'),
  cleartextStorage: cwe('CWE-312', 'Cleartext Storage of Sensitive Information'),
  credentialLeak: cwe('CWE-540', 'Inclusion of Sensitive Information in Source Code'),
  secretInConfig: cwe('CWE-526', 'Exposure of Sensitive Information Through Environmental Variables'),
  rlsDisabled: cwe('CWE-284', 'Improper Access Control'),
  permissiveAcl: cwe('CWE-732', 'Incorrect Permission Assignment for Critical Resource'),
  privilegeEscalation: cwe('CWE-250', 'Execution with Unnecessary Privileges'),
  csrf: cwe('CWE-352', 'Cross-Site Request Forgery'),
  openRedirect: cwe('CWE-601', 'URL Redirection to Untrusted Site'),
  ssrf: cwe('CWE-918', 'Server-Side Request Forgery'),
  unrestrictedUpload: cwe('CWE-434', 'Unrestricted Upload of File with Dangerous Type'),
  resourceExhaustion: cwe('CWE-770', 'Allocation of Resources Without Limits or Throttling'),
  deserialization: cwe('CWE-502', 'Deserialization of Untrusted Data'),
  prototypePollution: cwe('CWE-1321', 'Improperly Controlled Modification of Object Prototype Attributes'),
  promptInjection: cwe('CWE-74', 'Improper Neutralization of Special Elements in Output'),
  weakCrypto: cwe('CWE-327', 'Use of a Broken or Risky Cryptographic Algorithm'),
  privateKey: cwe('CWE-321', 'Use of Hard-coded Cryptographic Key'),
  defaultCredentials: cwe('CWE-1392', 'Use of Default Credentials'),
  injection: cwe('CWE-77', 'Improper Neutralization of Special Elements used in a Command'),
  dangerousFunction: cwe('CWE-749', 'Exposed Dangerous Method or Function'),
  dependencyConfusion: cwe('CWE-829', 'Inclusion of Functionality from Untrusted Control Sphere'),
  untrustedSearchPath: cwe('CWE-1104', 'Use of Unmaintained Third Party Components'),
  browserSecurity: cwe('CWE-942', 'Permissive Cross-domain Policy with Untrusted Domains'),
} as const;

/** Languages we treat as JavaScript-family for brace/await reasoning. */
export const JS_LANGUAGES: ReadonlySet<string> = new Set(['typescript', 'javascript', 'jsx', 'vue', 'svelte']);

/** Languages that can contain an HTTP handler implemented in JS/TS. */
export const SERVER_CODE_LANGUAGES: ReadonlySet<string> = new Set([
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
export const isDataFile = (ctx: FileContext): boolean =>
  ctx.language === 'json' || ctx.language === 'yaml' || ctx.language === 'toml' || ctx.language === 'xml';

/** True when the file is a SQL/Prisma schema - i.e. DDL, not application code. */
export const isSchemaFile = (ctx: FileContext): boolean =>
  ctx.language === 'sql' || ctx.language === 'prisma' || ctx.extension === 'sql';

/** Shared "not a real target" predicate for application-code rules. */
export function isApplicationCode(ctx: FileContext): boolean {
  return (
    !ctx.flags.isTestFile &&
    !ctx.flags.isDocumentation &&
    !ctx.flags.isLockfile &&
    !ctx.flags.isGenerated &&
    !ctx.flags.isEnvFile &&
    !ctx.flags.isMcpConfig &&
    !ctx.flags.isAgentInstructionFile
  );
}

/** Skip list used by every logic rule: tests, docs, generators, data files. */
export const LOGIC_SKIP_FLAGS = [
  'isTestFile',
  'isDocumentation',
  'isLockfile',
  'isGenerated',
  'isEnvFile',
] as const satisfies ReadonlyArray<keyof FileContext['flags']>;

/** True when `ctx` contains an auth verification anywhere (session, jwt...). */
export const verifiesAuth = (ctx: FileContext): boolean => AUTH_VERIFICATION_REGEX.test(ctx.code);

/** True when the file ships to the browser (client directive or client-ish path). */
export const isBrowserFile = (ctx: FileContext): boolean =>
  ctx.flags.isClientComponent || ctx.flags.isClientPath;


/** Observed client code or a module reachable through the static import graph. */
export const isClientReachable = (ctx: FileContext): boolean =>
  isBrowserFile(ctx) || (ctx.project.clientReachablePaths?.includes(ctx.relativePath) ?? false);

/** True when `ctx` checks a role/permission/ownership claim. */
export const checksRole = (ctx: FileContext): boolean => ROLE_CHECK_REGEX.test(ctx.code);

/**
 * The body of a handler starting at `offset`, capped so a pathological file
 * cannot blow up quadratic brace scanning.
 */
export const handlerBody = (ctx: FileContext, offset: number): string =>
  balancedBlock(ctx.code, ctx.code.indexOf('{', offset), '{', '}').slice(0, 8000);

/** Locate the first occurrence of `needle` at or after `from`, else `from`. */
export function offsetOf(source: string, needle: string | RegExp, from = 0): number {
  if (typeof needle === 'string') {
    const index = source.indexOf(needle, from);
    return index === -1 ? from : index;
  }
  const scoped = source.slice(from);
  const match = needle.exec(scoped);
  return match ? from + match.index : from;
}

/** Downgrade helper: severity only escalates (never de-escalates) a base value. */
export function escalate(base: Severity, candidate: Severity): Severity {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  return order.indexOf(candidate) < order.indexOf(base) ? candidate : base;
}

/** Confidence bump used when a project-level signal corroborates a hit. */
export const confident = (value: Confidence, boost = false): Confidence =>
  boost ? 'high' : value;

/**
 * This repository's canonical `github:` install coordinate.
 *
 * Single source of truth: `init` writes it into `.mcp.json`, and the auditor
 * recognises it there. Keeping one constant means the two can never drift.
 */
export const SELF_GITHUB_SPEC = '@vibefoundry/vibe-shield';

/** First-party install specs the auditor vouches for without a `@sha`. */
export const SELF_INSTALL_SPECS: readonly string[] = [SELF_GITHUB_SPEC];

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
export function isGitInstallArg(arg: string): boolean {
  return (
    /^(?:github|gitlab|bitbucket):[^/@\s]+\/[^/\s@]+(?:#[^\s]+)?$/i.test(arg) ||
    /^(?:git\+)?(?:https?|ssh|git):\/\/[^\s]+\.git(?:#[^\s]+)?$/i.test(arg) ||
    /^git@[^\s:]+:[^\s]+\.git(?:#[^\s]+)?$/i.test(arg) ||
    /^(?:git\+)?(?:github|gitlab|bitbucket):[^\s]+$/i.test(arg)
  );
}
