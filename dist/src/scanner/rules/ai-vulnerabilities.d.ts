/**
 * vibe-shield :: ai-vulnerabilities rules
 * ---------------------------------------
 * Two families live here because they share a root cause: an agent that
 * "makes it work" on the happy path and never models an attacker.
 *
 *  - LLM-specific: tool calls that reach a shell, model output piped into
 *    `eval`, untrusted context promoted to the system prompt, expensive routes
 *    with no quota.
 *  - Classic web: command injection, webhook signature bypass, XSS, open
 *    redirect, SSRF, path traversal, unrestricted uploads, insecure
 *    deserialization.
 */
import type { Rule } from '../types';
export declare const AI_VULNERABILITY_RULES: readonly Rule[];
