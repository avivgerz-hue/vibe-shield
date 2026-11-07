/**
 * vibe-shield :: SECURITY_PATCH_PROMPT.md
 * ---------------------------------------
 * `--fix-prompt` writes the file an autonomous agent can *execute*. That means
 * every finding must be self-contained: exact location, the vulnerable code,
 * why it is exploitable, the exact replacement, and a verification command.
 *
 * The document is ordered by severity and grouped by file so an agent reads one
 * file's problems, patches them, and moves on — instead of thrashing between
 * unrelated modules.
 */
import type { ScanResult } from '../scanner/types';
export declare const PATCH_PROMPT_FILENAME = "SECURITY_PATCH_PROMPT.md";
export interface PatchPromptOptions {
    /** File name to write (default `SECURITY_PATCH_PROMPT.md`). */
    fileName?: string;
    /** Skip findings below this severity. */
    minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    /** Maximum findings to include (0 = all). Default 200. */
    maxFindings?: number;
    /** Include the full rule description for each finding. */
    verbose?: boolean;
}
/**
 * Build the patch prompt document.
 *
 * The prompt is written *for an agent*: imperative, unambiguous, and explicit
 * about what must not change. It ends with a self-check the agent is told to run
 * before reporting the task as done — the same discipline `SKILL.md` enforces.
 */
export declare function buildPatchPrompt(result: ScanResult, options?: PatchPromptOptions): string;
/** Write the patch prompt and return the absolute path written. */
export declare function writePatchPrompt(result: ScanResult, options?: PatchPromptOptions & {
    outDir?: string;
}): Promise<string>;
