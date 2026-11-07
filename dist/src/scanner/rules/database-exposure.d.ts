/**
 * vibe-shield :: database-exposure rules
 * --------------------------------------
 * Supabase + Postgres is where AI-generated code gets *quietly* dangerous. The
 * `CREATE TABLE` an agent writes is perfect; the `ALTER TABLE ... ENABLE ROW
 * LEVEL SECURITY` that should follow it simply never gets written, and with the
 * anon key in every browser the table is world-readable through PostgREST.
 *
 * The RLS rules live here rather than in a linter because the mistake spans
 * files: a table created in migration #1 and secured in migration #7 is fine,
 * and only a project-wide index can tell the difference. `detectProject()`
 * builds that index (`ProjectContext.sqlTables`).
 */
import type { Rule } from '../types';
export declare const DATABASE_EXPOSURE_RULES: readonly Rule[];
