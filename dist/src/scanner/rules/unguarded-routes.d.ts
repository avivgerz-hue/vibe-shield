/**
 * vibe-shield :: unguarded-routes rules
 * -------------------------------------
 * The second great AI failure mode: an endpoint that does exactly what it was
 * asked to do, with no check on *who* is asking. An agent asked to "add a
 * delete endpoint" happily writes `export async function DELETE(req)` with no
 * session lookup at all, and a route that deletes by `req.body.id` is a
 * one-request account takeover.
 *
 * Nine rules cover the space: App Router handlers, Pages Router handlers,
 * Express/Fastify/Koa/Hono routes, object-level authorisation (IDOR), Server
 * Actions, identity taken from an unverified source, admin surfaces without a
 * role check, auth that is fetched but never enforced, and cookie-session CSRF.
 */
import type { Rule } from '../types';
export declare const UNGUARDED_ROUTE_RULES: readonly Rule[];
