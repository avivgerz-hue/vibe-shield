/**
 * vibe-shield :: shared rule vocabulary
 * ------------------------------------
 * Thin, reusable predicates used by more than one rule family. Nothing in this
 * module is heuristic-by-accident: every helper answers a single question about
 * a `FileContext` and is unit-tested through the rules that consume it.
 */
import type { Cwe, Confidence, FileContext, Severity } from '../types';
/** Build a `Cwe` record from an id and its short MITRE name. */
export declare const cwe: (id: string, name: string) => Cwe;
export declare const CWES: {
    readonly xss: Cwe;
    readonly commandInjection: Cwe;
    readonly sqlInjection: Cwe;
    readonly codeInjection: Cwe;
    readonly pathTraversal: Cwe;
    readonly hardcodedCredentials: Cwe;
    readonly missingAuth: Cwe;
    readonly missingAuthz: Cwe;
    readonly incorrectAuthz: Cwe;
    readonly improperAuthn: Cwe;
    readonly idor: Cwe;
    readonly improperCertValidation: Cwe;
    readonly signatureVerification: Cwe;
    readonly exposureOfSecrets: Cwe;
    readonly cleartextStorage: Cwe;
    readonly credentialLeak: Cwe;
    readonly secretInConfig: Cwe;
    readonly rlsDisabled: Cwe;
    readonly permissiveAcl: Cwe;
    readonly privilegeEscalation: Cwe;
    readonly csrf: Cwe;
    readonly openRedirect: Cwe;
    readonly ssrf: Cwe;
    readonly unrestrictedUpload: Cwe;
    readonly resourceExhaustion: Cwe;
    readonly deserialization: Cwe;
    readonly prototypePollution: Cwe;
    readonly promptInjection: Cwe;
    readonly weakCrypto: Cwe;
    readonly privateKey: Cwe;
    readonly defaultCredentials: Cwe;
    readonly injection: Cwe;
    readonly dangerousFunction: Cwe;
    readonly dependencyConfusion: Cwe;
    readonly untrustedSearchPath: Cwe;
    readonly browserSecurity: Cwe;
};
/** Languages we treat as JavaScript-family for brace/await reasoning. */
export declare const JS_LANGUAGES: ReadonlySet<string>;
/** Languages that can contain an HTTP handler implemented in JS/TS. */
export declare const SERVER_CODE_LANGUAGES: ReadonlySet<string>;
/** True when the file is plain JSON/YAML/TOML data (no executable logic). */
export declare const isDataFile: (ctx: FileContext) => boolean;
/** True when the file is a SQL/Prisma schema - i.e. DDL, not application code. */
export declare const isSchemaFile: (ctx: FileContext) => boolean;
/** Shared "not a real target" predicate for application-code rules. */
export declare function isApplicationCode(ctx: FileContext): boolean;
/** Skip list used by every logic rule: tests, docs, generators, data files. */
export declare const LOGIC_SKIP_FLAGS: readonly ["isTestFile", "isDocumentation", "isLockfile", "isGenerated", "isEnvFile"];
/** True when `ctx` contains an auth verification anywhere (session, jwt...). */
export declare const verifiesAuth: (ctx: FileContext) => boolean;
/** True when the file ships to the browser (client directive or client-ish path). */
export declare const isBrowserFile: (ctx: FileContext) => boolean;
/** True when `ctx` checks a role/permission/ownership claim. */
export declare const checksRole: (ctx: FileContext) => boolean;
/**
 * The body of a handler starting at `offset`, capped so a pathological file
 * cannot blow up quadratic brace scanning.
 */
export declare const handlerBody: (ctx: FileContext, offset: number) => string;
/** Locate the first occurrence of `needle` at or after `from`, else `from`. */
export declare function offsetOf(source: string, needle: string | RegExp, from?: number): number;
/** Downgrade helper: severity only escalates (never de-escalates) a base value. */
export declare function escalate(base: Severity, candidate: Severity): Severity;
/** Confidence bump used when a project-level signal corroborates a hit. */
export declare const confident: (value: Confidence, boost?: boolean) => Confidence;
/**
 * This repository's canonical `github:` install coordinate.
 *
 * Single source of truth: `init` writes it into `.mcp.json`, and the auditor
 * recognises it there. Keeping one constant means the two can never drift.
 */
export declare const SELF_GITHUB_SPEC = "@vibefoundry/vibe-shield";
/** First-party install specs the auditor vouches for without a `@sha`. */
export declare const SELF_INSTALL_SPECS: readonly string[];
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
export declare function isGitInstallArg(arg: string): boolean;
