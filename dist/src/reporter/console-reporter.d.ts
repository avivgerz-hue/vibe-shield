/**
 * vibe-shield :: terminal reporter
 * --------------------------------
 * The scorecard is the product. It has one job: make a developer *feel* the
 * number of critical findings in under a second, then hand them exact
 * `file:line` citations they can click in a terminal.
 *
 * No colour is required for meaning — every status is also spelled out — so the
 * output survives CI logs, `--no-color`, and screen readers.
 */
import type { ScanResult, Severity } from '../scanner/types';
export interface Colorizer {
    enabled: boolean;
    red(text: string): string;
    green(text: string): string;
    yellow(text: string): string;
    blue(text: string): string;
    magenta(text: string): string;
    cyan(text: string): string;
    gray(text: string): string;
    bold(text: string): string;
    dim(text: string): string;
    underline(text: string): string;
}
/** Build a colouriser honouring `NO_COLOR`, `FORCE_COLOR` and TTY detection. */
export declare function createColorizer(stream?: {
    isTTY?: boolean;
}): Colorizer;
declare const severityPaint: (color: Colorizer, severity: Severity) => ((text: string) => string);
/** Strip ANSI codes to measure true display width. */
declare const visibleLength: (text: string) => number;
/** Pad `text` to `width` visible characters. */
export declare const pad: (text: string, width: number) => string;
declare const GRADE_ICON: Record<string, string>;
export interface ReportOptions {
    color?: Colorizer;
    /** Terminal width. Defaults to `process.stdout.columns` or 100. */
    width?: number;
    /** Cap the per-finding list (0 = all). Default 50. */
    maxFindings?: number;
    /** Show timing / throughput statistics. */
    showStats?: boolean;
    /** Absolute root used to shorten paths (defaults to `result.rootDir`). */
    cwd?: string;
}
/** Shown instead of a grade when discovery matched nothing: silence is not a pass. */
export declare const NOTHING_SCANNED = "\u26A0  NO FILES SCANNED \u2014 this is not a pass";
/** The one-line verdict, e.g. `💀 GRADE F — 0/100 · 6 critical`. */
export declare function verdictLine(result: ScanResult, color: Colorizer): string;
/** Full scorecard as an array of lines (no trailing newline). */
export declare function renderConsoleReport(result: ScanResult, options?: ReportOptions): string[];
/** Print the scorecard to a stream. */
export declare function reportConsole(result: ScanResult, stream?: {
    write(chunk: string): unknown;
    isTTY?: boolean;
    columns?: number;
}, options?: ReportOptions): void;
export { GRADE_ICON, severityPaint, visibleLength };
