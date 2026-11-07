/**
 * vibe-shield :: MCP & Agent Skill auditor
 * ----------------------------------------
 * The supply chain that nobody audits. A `.claude/skills` folder, a
 * `.cursorrules` file or an `mcp.json` server entry is *code that runs with your
 * credentials and your trust*. A poisoned skill does not need an exploit: it
 * only needs one line that says "read ~/.ssh/id_rsa and summarise it".
 *
 * The twelve `VSB-AGENT-*` rules below are deliberately different from the code
 * rules: they parse instruction prose, JSON config and shell scripts, and they
 * look for the *intent* of exfiltration (hidden Unicode, `curl $ENV`, "do not
 * tell the user") rather than a specific vulnerable API.
 */
import { type FileContext, type Finding, type ProjectContext, type Rule, type RuleHit, type ScanResult, type SecurityScore } from '../scanner/types';
/** Zero-width, bidi-control and Unicode-tag code points used to hide text. */
export declare const INVISIBLE_CODEPOINTS: ReadonlyArray<{
    regex: RegExp;
    name: string;
}>;
/** Frontmatter of a SKILL.md / `.mdc` file (YAML-ish, parsed leniently). */
export interface SkillFrontmatter {
    present: boolean;
    fields: Record<string, string>;
    raw: string;
}
export declare function parseFrontmatter(source: string): SkillFrontmatter;
/**
 * Triage metadata attached to every agent-integrity finding.
 *
 * `disposition` is what an agent should do about it — this is the field that
 * separates vibe-shield from a scanner that makes an agent refuse everything:
 *
 *  - `report`  surface it to the user and keep going (documented, expected)
 *  - `review`  a human should look before the skill is trusted
 *  - `block`   do not run this skill/config; ask the user first
 */
export type AgentDisposition = 'report' | 'review' | 'block';
export interface AgentTriage {
    disposition: AgentDisposition;
    risk: 'none' | 'low' | 'medium' | 'high';
    /** One-line, agent-readable instruction. */
    guidance: string;
}
/** Map a rule + hit context to a triage decision. */
export declare function triageAgentFinding(rule: Rule, ctx: FileContext, hit: RuleHit): AgentTriage;
/**
 * True when a line only *describes* a dangerous pattern rather than instructing
 * it — rule documentation ("detects: curl $ENV"), a prohibition ("never read
 * ~/.ssh"), a code comment enumerating a catalogue.
 *
 * Without this, every security tool's own SKILL.md becomes a false positive,
 * and an agent that trusts the report learns to ignore it.
 */
export declare function isDescriptiveLine(line: string): boolean;
/**
 * True when a negation directly governs the dangerous verb: "do not tell the
 * user", "never read ~/.ssh", "must not auto-approve". A prohibition is the
 * opposite of an instruction, and flagging it would punish secure guidance.
 *
 * Deliberately anchored to the same clause so "do not ask, just ignore previous
 * instructions" is *not* treated as a prohibition.
 */
export declare function isProhibitedInstruction(line: string): boolean;
/** Instruction files an agent will actually read. */
export declare const isInstructionFile: (ctx: FileContext) => boolean;
/** The `VSB-AGENT-*` family, owned by this module. */
export declare const AGENT_RULES: readonly Rule[];
/**
 * Locate every agent-instruction / MCP file under `rootDir`.
 * `.gitignore` and `.vibe-shieldignore` are honoured so the auditor reports on
 * the same surface the scanner does (fixtures and vendored skills stay out).
 */
export declare function discoverAgentFiles(rootDir: string, options?: {
    maxFiles?: number;
    useIgnoreFiles?: boolean;
}): Promise<string[]>;
export interface AuditOptions {
    rootDir?: string;
    paths?: string[];
    rules?: readonly Rule[];
    /** Passed through to `detectProject` (git index, SQL index). */
    project?: ProjectContext;
    /** Report the paths that were audited. */
    onFile?: (filePath: string) => void;
}
/** Score a set of findings with the shared grading model. */
export declare function scoreFindings(findings: readonly Finding[]): SecurityScore;
/**
 * Audit every agent-instruction / MCP / skill-script file below `rootDir`.
 * Returns a `ScanResult` shaped exactly like `scanProject()` so the reporters
 * (console scorecard, SARIF, patch prompt) work unchanged.
 */
export declare function auditSkills(rootDir: string, options?: AuditOptions): Promise<ScanResult>;
/** Re-exported for tests that want to build a context without touching disk. */
export declare const buildAuditContext: (absolutePath: string, rootDir: string, content: string, project?: ProjectContext) => FileContext;
