/**
 * vibe-shield :: secret-entropy rules
 * -----------------------------------
 * `src/secrets/patterns.ts` knows ~40 vendor signature formats (Stripe, OpenAI,
 * Anthropic, AWS, GitHub, Supabase, Slack...) plus a generic high-entropy
 * assignment heuristic. This module turns those matches into findings with the
 * right severity for *where* the secret sits:
 *
 *   - a live key in a server file is a critical hardcoded credential,
 *   - the same key in a browser-reachable file is an immediate data breach,
 *   - the same key inside a committed `.env` is a repository leak.
 *
 * Splitting rules by destination (instead of reporting one match three ways) is
 * what keeps the scorecard honest and the patch prompt actionable.
 */
import type { Rule } from '../types';
export declare const SECRET_ENTROPY_RULES: readonly Rule[];
