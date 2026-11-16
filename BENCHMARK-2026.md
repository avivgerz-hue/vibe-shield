# 2026 Empirical Security Benchmark: AI-Generated Code, MCP Servers & Agent Skills

> **Dataset:** **160** published packages (**7,062** source, SQL, and agent configuration files) sampled across 4 AI-native cohorts from the public npm registry and audited statically with **[`@vibefoundry/vibe-shield`](https://github.com/avivgerz-hue/vibe-shield)** (92 rules mapped to CWE & OWASP Top 10:2025).
> **Methodological Control & Responsible Disclosure:** Because `npm pack` strips `package-lock.json` from published tarballs by specification, rule `VSB-DEPS-006` (missing lockfile) is excluded from tarball scoring to prevent packaging-artifact inflation. All package-level findings are aggregated and anonymized in [`benchmark/results-summary.json`](./benchmark/results-summary.json).

## Executive Findings

| Metric | Empirical Result |
| :--- | :--- |
| **Published Packages Audited** | **160** across 4 AI-native cohorts |
| **Source & Agent Files Inspected** | **7,062** files |
| **Total Actionable Security Findings** | **597** (**167** Critical, **82** High, **321** Medium, **27** Low) |
| **Packages with >= 1 Vulnerability / Hardening Flaw** | **33 / 160 (20.6%)** |
| **Packages with Critical or High Severity Flaws** | **16 / 160 (10%)** |

## Cohort Breakdown

| Cohort | Packages | Mean Score (0-100) | Affected Packages | Critical / High Rate | Total Findings |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **MCP Servers & Tool Providers** | 40 | **90.7** | 17.5% | **10.0%** | 49 |
| **Agent Skills, Cursor Rules & Coding Plugins** | 40 | **94.3** | 15.0% | **7.5%** | 16 |
| **Next.js / Supabase / Stripe AI Web Packages** | 40 | **87.8** | 25.0% | **5.0%** | 244 |
| **LLM Agent & Prompt Execution Tooling** | 40 | **85.8** | 25.0% | **17.5%** | 288 |

## Top Vulnerability Rules Triggered in the Wild

| Rank | Rule ID & Title | Occurrences |
| :---: | :--- | :---: |
| 1 | `VSB-SECRET-002: High-entropy value assigned to a credential-shaped name` | **306** |
| 2 | `VSB-DB-006: ORM raw-SQL API called with a dynamic string` | **130** |
| 3 | `VSB-DB-010: Request data used as a table, column or ORDER BY identifier` | **30** |
| 4 | `VSB-AUTH-004: Record ownership taken from the request instead of the session (IDOR)` | **26** |
| 5 | `VSB-AI-012: Filesystem path built from request data` | **17** |
| 6 | `VSB-DEPS-001: Wildcard package dependency` | **12** |
| 7 | `VSB-INFRA-001: Wildcard cross-origin response` | **11** |
| 8 | `VSB-INFRA-010: Content-Security-Policy not observed in server configuration` | **9** |
| 9 | `VSB-INFRA-011: X-Frame-Options not observed in server configuration` | **9** |
| 10 | `VSB-INFRA-012: Strict-Transport-Security not observed in server configuration` | **9** |
| 11 | `VSB-AI-011: Outbound request to a caller-supplied URL (SSRF)` | **6** |
| 12 | `VSB-DEPS-002: Latest tag used for package dependency` | **5** |

## Top CWE Classifications Observed

| CWE Identifier | Occurrences |
| :--- | :---: |
| **CWE-798: Use of Hard-coded Credentials** | 310 |
| **CWE-89: Improper Neutralization of Special Elements used in an SQL Command** | 162 |
| **CWE-693: Protection Mechanism Failure** | 27 |
| **CWE-639: Authorization Bypass Through User-Controlled Key** | 26 |
| **CWE-1104: Use of Unmaintained Third Party Components** | 17 |
| **CWE-22: Improper Limitation of a Pathname to a Restricted Directory** | 17 |
| **CWE-942: Permissive Cross-domain Policy with Untrusted Domains** | 11 |
| **CWE-918: Server-Side Request Forgery** | 6 |
| **CWE-863: Incorrect Authorization** | 4 |
| **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor** | 4 |

## Attack Vector Distribution

| Vector Category | Findings |
| :--- | :---: |
| `secret-entropy` | **310** |
| `database-exposure` | **162** |
| `infrastructure` | **39** |
| `unguarded-routes` | **33** |
| `ai-vulnerabilities` | **29** |
| `dependencies` | **17** |
| `client-exposure` | **7** |

## Reproducing Locally

```bash
npx -y @vibefoundry/vibe-shield@latest scan .
npx -y @vibefoundry/vibe-shield@latest audit-skills .
node scripts/run-benchmark-2026.mjs
```
