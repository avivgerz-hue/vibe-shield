import type { Rule } from '../types';
export declare const HARDENING_RULES: readonly Rule[];
export declare const MISSING_LOCKFILE_RULE: Rule;
/** Docker defaults to root when the final stage never selects a runtime user. */
export declare const DOCKER_DEFAULT_ROOT_RULE: Rule;
