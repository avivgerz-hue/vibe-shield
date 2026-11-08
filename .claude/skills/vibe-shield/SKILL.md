---
name: vibe-shield
description: Apply a six-phase defensive security review to changes affecting applications, APIs, data, AI agents, and MCP configuration. Use static evidence, preserve behavior, and report limitations.
allowed-tools: Bash(npx -y @vibefoundry/vibe-shield scan*), Bash(npx -y @vibefoundry/vibe-shield audit-skills*), Bash(npx -y @vibefoundry/vibe-shield explain*), Read(./**), Grep, Glob
license: MIT
metadata:
  author: VibeFoundry
  homepage: https://github.com/avivgerz-hue/vibe-shield
  version: 2.0.0
---

# Defensive AppSec architect protocol

Work only within the authorized project. Static findings are evidence for review, not proof of exploitability or a guarantee of safety. Do not transmit source code or secrets. Ask before changing production services, rotating credentials, or making destructive changes.

## Phase 1: Attack-surface reconnaissance

Map entrypoints and trust boundaries: API methods, authentication and authorization, middleware matchers, database tables and policies, storage, LLM inputs and tools, webhooks, and agent/MCP configuration. Check deployment configuration and exclusions. Identify what the scanner cannot see.

## Phase 2: Automated static scan and skill audit

```bash
npx -y @vibefoundry/vibe-shield scan . --format json
npx -y @vibefoundry/vibe-shield audit-skills . --format json
```

Inspect findings, inventory, ignored paths, and the files scanned. The explicit `.` includes test and documentation files: review fixtures as examples rather than blindly changing them. Use `explain <RULE_ID>` to investigate a rule. These commands run locally; first-time installation with npx requires registry access.

## Phase 3: Deep contextual threat modeling

Trace untrusted input through authentication, ownership checks and tenant boundaries to database, filesystem, network, HTML, and LLM sinks. Inspect IDOR, business-logic bypasses, webhook signature verification and asynchronous jobs. Check cross-file guards and deployed database policies; absence of a static finding is not evidence of protection.

## Phase 4: Surgical zero-regression remediation

- On Next.js mutation routes, authenticate the session on the server and authorize the target resource against the session principal before writes. Do not trust identity from request bodies.
- Enable Supabase RLS and write action-specific policies using the authenticated principal; test both permitted and denied tenants before deploying migrations.
- Validate inputs at the boundary with a schema such as Zod, then use parameterized database queries. Treat LLM output as untrusted.
- Use explicit CORS allowlists, secure cookie flags and a CSP appropriate for the application. Test login, redirects, and browser behavior.
- Report exposed credentials to the owner for provider-side rotation; avoid reproducing their values in reports. Do not suppress findings or weaken controls to obtain a higher score. Ask for missing business or deployment decisions.

## Phase 5: Verification gate

Run project tests and both audits again. Aim for 100/100 Grade A+ with no high or critical findings, but report any unresolved finding, exclusion, false positive, or verification limitation honestly rather than claiming success. Never equate a clean score with a complete security assessment.

```bash
npx -y @vibefoundry/vibe-shield scan --fail-on high
npx -y @vibefoundry/vibe-shield audit-skills --fail-on high
```

## Phase 6: Executive security sign-off

Produce a Markdown or HTML report with scope, inventory, risks prioritized by severity, evidence, actions, test results and remaining uncertainty. Illustrative code examples are not project-specific patches; review and adapt them. Obtain human approval before deployment or provider-side action.

```bash
npx -y @vibefoundry/vibe-shield scan --report SECURITY-REPORT.md --patch-prompt PATCH-PROMPT.md
npx -y @vibefoundry/vibe-shield audit-skills --report AGENT-REPORT.html
```
