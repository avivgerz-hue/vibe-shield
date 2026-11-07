/**
 * vibe-shield :: credential signature library
 * -------------------------------------------
 * Vendor-specific secret signatures plus a Shannon-entropy fallback. The same
 * table powers `VSB-SECRET-*` (source scanner) and the agent-skill auditor, so
 * a leaked key is reported identically no matter where it is found.
 *
 * Every regex is *deliberately* written so it cannot match its own source text
 * (that is why character classes appear as `[0-9A-Z]{16}` and never as a
 * literal example key) — vibe-shield scans itself in CI.
 */
import type { Severity } from '../scanner/types';
export type SecretFamily = 'openai' | 'anthropic' | 'aws' | 'stripe' | 'github' | 'supabase' | 'private-key' | 'saas' | 'registry' | 'jwt' | 'database-url' | 'generic';
export interface SecretPattern {
    /** Stable id used by config overrides, e.g. `openai`. */
    id: string;
    /** Human readable vendor, e.g. `OpenAI`. */
    vendor: string;
    family: SecretFamily;
    severity: Severity;
    /** Global regex; group 1 (when present) holds the credential. */
    regex: RegExp;
    /** Minimum Shannon entropy for the captured value. */
    minEntropy?: number;
    /**
     * The match *is* the finding (PEM headers, connection strings): skip the
     * placeholder/entropy gates, which exist to filter out opaque token bodies.
     */
    raw?: boolean;
    /** Short note shown in the finding message. */
    note: string;
}
export declare const SECRET_PATTERNS: SecretPattern[];
/** Loose "assignment of a long opaque value" probe used by the generic rule. */
export declare const GENERIC_ASSIGNMENT_REGEX: RegExp;
export interface SecretMatch {
    patternId: string;
    vendor: string;
    family: SecretFamily;
    severity: Severity;
    /** The raw credential. Never print this — use `display`. */
    value: string;
    /** Masked value safe for terminals, logs and reports. */
    display: string;
    offset: number;
    length: number;
    entropy: number;
    note: string;
}
/** Find every credential in `text`, deduplicating overlapping matches. */
export declare function findSecrets(text: string, options?: {
    skipGeneric?: boolean;
}): SecretMatch[];
/**
 * Decode a JWT payload without verifying it — used to spot `service_role`,
 * `admin` or `exp: never` claims sitting in source code.
 */
export declare function decodeJwtPayload(token: string): Record<string, unknown> | null;
/** True when a JWT carries a privileged role claim. */
export declare function jwtHasPrivilegedRole(token: string): {
    privileged: boolean;
    role: string | null;
};
