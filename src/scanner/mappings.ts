/**
 * OWASP Top 10:2025 associations. CWE-based entries follow the "List of
 * Mapped CWEs" in the official 2025 category pages; contextual associations
 * are explicitly labelled and require review. LLM associations are rule-level
 * judgements, not a claim that every finding involves an LLM.
 */
export interface OwaspMapping { id: string; name: string; basis: 'owasp-cwe' | 'contextual' }
export interface OwaspMappings { web: OwaspMapping | null; llm: OwaspMapping[] }

const names: Record<string, string> = {
  A01:'Broken Access Control', A02:'Security Misconfiguration', A03:'Software Supply Chain Failures',
  A04:'Cryptographic Failures', A05:'Injection', A06:'Insecure Design',
  A07:'Authentication Failures', A08:'Software or Data Integrity Failures',
};
const webByCwe: Record<string, string> = {
  'CWE-22':'A01','CWE-200':'A01','CWE-284':'A01','CWE-352':'A01','CWE-540':'A01','CWE-601':'A01',
  'CWE-639':'A01','CWE-732':'A01','CWE-749':'A01','CWE-862':'A01','CWE-863':'A01','CWE-918':'A01','CWE-1275':'A01',
  'CWE-16':'A02','CWE-526':'A02','CWE-614':'A02','CWE-942':'A02','CWE-1004':'A02',
  'CWE-1104':'A03', 'CWE-321':'A04','CWE-327':'A04','CWE-347':'A04',
  'CWE-74':'A05','CWE-77':'A05','CWE-78':'A05','CWE-79':'A05','CWE-89':'A05','CWE-94':'A05',
  'CWE-434':'A06','CWE-693':'A06', 'CWE-287':'A07','CWE-306':'A07','CWE-798':'A07','CWE-1392':'A07',
  'CWE-345':'A08','CWE-502':'A08','CWE-829':'A08',
};
const contextualWeb: Record<string, string> = { 'CWE-250':'A01', 'CWE-770':'A06' };
const llmNames: Record<string, string> = {
  LLM01:'Prompt Injection', LLM02:'Sensitive Information Disclosure', LLM03:'Supply Chain',
  LLM05:'Improper Output Handling', LLM06:'Excessive Agency', LLM10:'Unbounded Consumption',
};
const llmByRule: Record<string, string[]> = {
  'VSB-AI-002':['LLM05','LLM06'], 'VSB-AI-003':['LLM05'], 'VSB-AI-004':['LLM01'],
  'VSB-AI-008':['LLM05'], 'VSB-AI-014':['LLM10'],
  'VSB-AGENT-001':['LLM01'], 'VSB-AGENT-002':['LLM01','LLM02'], 'VSB-AGENT-003':['LLM01','LLM02'],
  'VSB-AGENT-004':['LLM03'], 'VSB-AGENT-005':['LLM02'], 'VSB-AGENT-006':['LLM01'],
  'VSB-AGENT-007':['LLM06'], 'VSB-AGENT-008':['LLM05','LLM06'], 'VSB-AGENT-009':['LLM01','LLM03'],
  'VSB-AGENT-010':['LLM06'], 'VSB-AGENT-011':['LLM02'], 'VSB-AGENT-012':['LLM06'],
};

/** A null web mapping or empty LLM list means no applicable association was assigned. */
export function owaspMappings(ruleId: string, cweId: string): OwaspMappings {
  const official = webByCwe[cweId];
  const webId = official ?? contextualWeb[cweId];
  return {
    web: webId ? { id:`${webId}:2025`, name:names[webId]!, basis:official ? 'owasp-cwe' : 'contextual' } : null,
    llm: (llmByRule[ruleId] ?? []).map(id => ({ id:`${id}:2025`, name:llmNames[id]!, basis:'contextual' })),
  };
}
