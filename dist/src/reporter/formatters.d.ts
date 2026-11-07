/**
 * vibe-shield :: machine-readable output
 * --------------------------------------
 * Five formats, one contract: every field the console shows is available
 * structured, so nothing is lost when the report goes to a machine.
 *
 *  - `json`     the full `ScanResult` (stable, versioned by `schemaVersion`)
 *  - `compact`  one line per finding — what CI actually needs
 *  - `summary`  counts + grade only — for dashboards and PR comments
 *  - `sarif`    SARIF 2.1.0 for GitHub code scanning (`--format sarif`)
 *  - `github`   GitHub Actions workflow commands (annotations in the diff)
 */
import type { Finding, ScanResult } from '../scanner/types';
export declare const OUTPUT_FORMATS: readonly ["console", "compact", "summary", "json", "sarif", "github"];
export type OutputFormat = (typeof OUTPUT_FORMATS)[number];
export declare const isOutputFormat: (value: unknown) => value is OutputFormat;
/** Bump when the JSON shape changes in a breaking way. */
export declare const SCHEMA_VERSION = 1;
/** Full machine-readable report. */
export declare function formatJson(result: ScanResult): string;
/** Counts and grade only. */
export declare function formatSummary(result: ScanResult): string;
/** One line per finding: `path:line:col severity ruleId message`. */
export declare function formatCompact(result: ScanResult): string;
/**
 * GitHub Actions annotations. Each finding becomes an inline comment on the
 * diff when the workflow runs on a pull request.
 */
export declare function formatGithub(result: ScanResult): string;
/**
 * SARIF 2.1.0 document accepted by GitHub code scanning, VS Code SARIF viewer,
 * and every other consumer of the format.
 */
export declare function formatSarif(result: ScanResult): string;
/** Render `result` in the requested format. */
export declare function formatResult(result: ScanResult, format: OutputFormat): string;
/** Group findings by file for reporters that render trees. */
export declare function groupByFile(findings: readonly Finding[]): Map<string, Finding[]>;
