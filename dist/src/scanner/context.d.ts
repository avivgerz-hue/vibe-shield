/**
 * vibe-shield :: file & project context
 * -------------------------------------
 * Everything a rule needs is computed once per file here: language, structural
 * flags ("is this a client component?", "is this an App Router handler?", "is
 * this a SQL migration?") and the comment-masked code view.
 */
import { type FileContext, type FileFlags, type Language, type ProjectContext, type SqlTableInfo } from './types';
export declare const toPosix: (value: string) => string;
/** Resolve the `Language` bucket for a path. */
export declare function detectLanguage(relativePath: string, fileName: string, extension: string): Language;
/** Extension without the dot, lower-cased (`.env.local` -> `local`). */
export declare const extensionOf: (fileName: string) => string;
/** Compute the structural flags for one file. */
export declare function computeFlags(relativePath: string, fileName: string, extension: string, language: Language, content: string): FileFlags;
/** Build the immutable per-file context handed to every rule. */
export declare function createFileContext(absolutePath: string, rootDir: string, content: string, project: ProjectContext): FileContext;
/** Strip JSON comments/trailing commas so `jsonc` manifests still parse. */
export declare function tolerantJsonParse(text: string): unknown;
export interface DetectProjectOptions {
    /** Directories (relative) that should not be inspected for manifests. */
    skip?: (relativePath: string, isDirectory: boolean) => boolean;
    /** How deep to look for workspace manifests. Default 8. */
    maxDepth?: number;
    /** Read the git index to learn which paths are actually tracked. Default true. */
    readGitIndex?: boolean;
    /** Maximum number of SQL files parsed for the RLS index. Default 400. */
    maxSqlFiles?: number;
    /** Maximum bytes read per SQL file. Default 512 KiB. */
    maxSqlBytes?: number;
}
/** Extract the `matcher` entries declared by a Next.js middleware module. */
export declare function parseMiddlewareMatchers(source: string): string[];
/**
 * Parse every `CREATE TABLE` / `ALTER TABLE ... ROW LEVEL SECURITY` /
 * `CREATE POLICY` / `GRANT` statement in a SQL file into table records.
 * Deliberately tolerant: SQL dialects differ, and a partial read is still
 * better than a missed "RLS is enabled three migrations later".
 */
export declare function parseSqlTables(relativePath: string, source: string): SqlTableInfo[];
/** Merge per-file table records into the project-wide index. */
export declare function mergeSqlTables(target: SqlTableInfo[], incoming: SqlTableInfo[]): void;
/** Paths tracked by git, read from the index in a single subprocess call. */
export declare function readGitTrackedPaths(rootDir: string): string[];
/**
 * Cheap project fingerprint: manifests + marker files + SQL RLS posture.
 * Runs before the scan so rules can ask "does this project even have a CSRF
 * library installed?" or "is RLS enabled for this table in a later migration?"
 * without a second pass over the source.
 */
export declare function detectProject(rootDir: string, options?: DetectProjectOptions): Promise<ProjectContext>;
