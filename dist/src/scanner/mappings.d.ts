/**
 * OWASP Top 10:2025 associations. CWE-based entries follow the "List of
 * Mapped CWEs" in the official 2025 category pages; contextual associations
 * are explicitly labelled and require review. LLM associations are rule-level
 * judgements, not a claim that every finding involves an LLM.
 */
export interface OwaspMapping {
    id: string;
    name: string;
    basis: 'owasp-cwe' | 'contextual';
}
export interface OwaspMappings {
    web: OwaspMapping | null;
    llm: OwaspMapping[];
}
/** A null web mapping or empty LLM list means no applicable association was assigned. */
export declare function owaspMappings(ruleId: string, cweId: string): OwaspMappings;
