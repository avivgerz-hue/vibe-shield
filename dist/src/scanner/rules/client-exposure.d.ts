/**
 * vibe-shield :: client-exposure rules
 * ------------------------------------
 * The single most common way an AI coding agent leaks a production credential
 * is *not* a typo in a test fixture - it is a perfectly reasonable-looking
 * `process.env.NEXT_PUBLIC_OPENAI_API_KEY`. Next.js, Vite, Nuxt, Expo, Gatsby
 * and every other bundler inline those values into the JavaScript the browser
 * downloads, so the "environment variable" is really a hardcoded secret that
 * happens to live in `.env`.
 *
 * These seven rules cover that failure mode end to end: the variable name, the
 * server-only read that a client component still performs, the Supabase
 * service-role client, the admin SDK imported into the browser graph, the
 * "make the SDK work in the browser" escape hatch, the env file that carries a
 * real key, and the `next.config.js` `env` block that re-inlines one.
 */
import type { Rule } from '../types';
export declare const CLIENT_EXPOSURE_RULES: readonly Rule[];
