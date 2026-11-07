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

import type { Finding, ScanResult, Severity } from '../scanner/types';
import { CATEGORY_TITLES, SEVERITY_WEIGHT } from '../scanner/types';

/* -------------------------------------------------------------------------- */
/* Colour                                                                     */
/* -------------------------------------------------------------------------- */

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

const ANSI: Record<string, [number, number]> = {
  red: [31, 39],
  green: [32, 39],
  yellow: [33, 39],
  blue: [34, 39],
  magenta: [35, 39],
  cyan: [36, 39],
  gray: [90, 39],
  bold: [1, 22],
  dim: [2, 22],
  underline: [4, 24],
};

/** Build a colouriser honouring `NO_COLOR`, `FORCE_COLOR` and TTY detection. */
export function createColorizer(stream: { isTTY?: boolean } = process.stdout): Colorizer {
  const env = process.env;
  const forced = env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '0';
  const disabled = env.NO_COLOR !== undefined || env.TERM === 'dumb';
  const enabled = forced || (!disabled && stream.isTTY === true);
  const wrap = (code: number, close: number) => (text: string) => (enabled ? `\u001B[${code}m${text}\u001B[${close}m` : text);
  return {
    enabled,
    red: wrap(...(ANSI.red as [number, number])),
    green: wrap(...(ANSI.green as [number, number])),
    yellow: wrap(...(ANSI.yellow as [number, number])),
    blue: wrap(...(ANSI.blue as [number, number])),
    magenta: wrap(...(ANSI.magenta as [number, number])),
    cyan: wrap(...(ANSI.cyan as [number, number])),
    gray: wrap(...(ANSI.gray as [number, number])),
    bold: wrap(...(ANSI.bold as [number, number])),
    dim: wrap(...(ANSI.dim as [number, number])),
    underline: wrap(...(ANSI.underline as [number, number])),
  };
}

const SEVERITY_COLORS: Record<Severity, keyof Colorizer> = {
  critical: 'red',
  high: 'magenta',
  medium: 'yellow',
  low: 'blue',
  info: 'gray',
};

const severityPaint = (color: Colorizer, severity: Severity): ((text: string) => string) =>
  color[SEVERITY_COLORS[severity]] as (text: string) => string;

/* -------------------------------------------------------------------------- */
/* Layout helpers                                                             */
/* -------------------------------------------------------------------------- */

/** Strip ANSI codes to measure true display width. */
const visibleLength = (text: string): number => text.replace(/\u001B\[[0-9;]*m/g, '').length;

/** Pad `text` to `width` visible characters. */
export const pad = (text: string, width: number): string =>
  text + ' '.repeat(Math.max(0, width - visibleLength(text)));

const truncate = (text: string, width: number): string =>
  text.length <= width ? text : `${text.slice(0, Math.max(0, width - 1))}…`;

const GRADE_ICON: Record<string, string> = {
  'A+': '🏆',
  A: '✅',
  'A-': '✅',
  'B+': '🟢',
  B: '🟢',
  'B-': '🟡',
  'C+': '🟡',
  C: '🟠',
  'C-': '🟠',
  'D+': '🔴',
  D: '🔴',
  'D-': '🔴',
  F: '💀',
};

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

const DEFAULT_WIDTH = 100;

/** The one-line verdict, e.g. `💀 GRADE F — 0/100 · 6 critical`. */
export function verdictLine(result: ScanResult, color: Colorizer): string {
  const icon = GRADE_ICON[result.score.grade] ?? '•';
  const grade = color.bold(severityPaint(color, result.score.counts.critical > 0 ? 'critical' : result.score.counts.high > 0 ? 'high' : result.score.counts.medium > 0 ? 'medium' : 'low')(result.score.grade));
  const counts = (['critical', 'high', 'medium', 'low'] as const)
    .filter((severity) => result.score.counts[severity] > 0)
    .map((severity) => `${result.score.counts[severity]} ${severity}`)
    .join(' · ');
  return `${icon} GRADE ${grade} — ${result.score.score}/100${counts ? ` · ${counts}` : ''}`;
}

/** Render the header block: brand, version, target and verdict. */
function renderHeader(result: ScanResult, color: Colorizer, width: number): string[] {
  const lines: string[] = [];
  const title = color.bold(color.cyan('🛡️  vibe-shield'));
  const version = color.dim(`v${result.version}`);
  const mode = result.command === 'audit-skills' ? 'agent surface audit' : 'security scan';
  lines.push(`${title} ${version} ${color.dim(`· ${mode}`)}`);
  lines.push(color.dim(`target  ${truncate(result.rootDir, width - 10)}`));
  lines.push('');
  lines.push(verdictLine(result, color));
  lines.push('');
  return lines;
}

/** A horizontal bar for the severity histogram. */
function histogram(result: ScanResult, color: Colorizer): string[] {
  const counts = result.score.counts;
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const lines: string[] = [];
  for (const severity of order) {
    const count = counts[severity];
    if (!count) continue;
    const paint = severityPaint(color, severity);
    const bar = paint('█'.repeat(Math.min(40, count)));
    lines.push(`  ${pad(paint(severity.toUpperCase()), 8)} ${pad(String(count), 4)} ${bar}`);
  }
  return lines;
}

/** All findings grouped by file, with exact citations. */
function renderFindings(findings: readonly Finding[], color: Colorizer, options: ReportOptions): string[] {
  const lines: string[] = [];
  const maxFindings = options.maxFindings ?? 50;
  // Severity is the outer sort key (what to fix first); file is the inner one so
  // each file's findings stay together and the list reads like a patch.
  const ordered = [...findings].sort(
    (a, b) =>
      SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] ||
      a.filePath.localeCompare(b.filePath) ||
      a.line - b.line,
  );
  const shown = maxFindings > 0 ? ordered.slice(0, maxFindings) : ordered;

  let currentFile = '';
  for (const finding of shown) {
    if (finding.filePath !== currentFile) {
      currentFile = finding.filePath;
      lines.push('');
      lines.push(color.bold(color.underline(currentFile)));
    }
    const paint = severityPaint(color, finding.severity);
    const location = color.cyan(`${finding.line}:${finding.column}`);
    lines.push(`  ${paint(finding.severity.toUpperCase().padEnd(8))} ${location.padEnd(color.enabled ? 22 : 8)} ${color.dim(finding.ruleId)}  ${finding.title}`);
    if (finding.snippet) lines.push(`           ${color.gray(truncate(finding.snippet, 110))}`);
  }
  if (maxFindings > 0 && findings.length > maxFindings) {
    lines.push('');
    lines.push(color.dim(`  … and ${findings.length - maxFindings} more. Run with --format json or --max-findings 0 to see every finding.`));
  }
  return lines;
}

/** Category breakdown, useful when the list is long. */
function renderCategories(result: ScanResult, color: Colorizer): string[] {
  const byCategory = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const bucket = byCategory.get(finding.category) ?? [];
    bucket.push(finding);
    byCategory.set(finding.category, bucket);
  }
  if (byCategory.size <= 1) return [];
  const lines: string[] = ['', color.bold('By category')];
  const sorted = [...byCategory.entries()].sort((a, b) => b[1].length - a[1].length);
  for (const [category, findings] of sorted) {
    const worst = findings.reduce<Severity>(
      (acc, finding) => (SEVERITY_WEIGHT[finding.severity] > SEVERITY_WEIGHT[acc] ? finding.severity : acc),
      'info',
    );
    const paint = severityPaint(color, worst);
    lines.push(`  ${paint('●')} ${pad(CATEGORY_TITLES[category as keyof typeof CATEGORY_TITLES] ?? category, 44)} ${findings.length}`);
  }
  return lines;
}

/** Timing / throughput footer. */
function renderStats(result: ScanResult, color: Colorizer): string[] {
  const { stats } = result;
  const parts = [
    `${stats.filesScanned} files`,
    `${(stats.bytesScanned / 1024).toFixed(0)} KiB`,
    `${stats.filesPerSecond} files/s`,
    `${stats.durationMs} ms`,
    `${result.ruleCount} rules`,
  ];
  if (stats.cacheHits > 0) parts.push(`${stats.cacheHits} cached`);
  if (result.suppressedCount > 0) parts.push(`${result.suppressedCount} suppressed`);
  const line = color.dim(`  ${parts.join('  ·  ')}`);
  return ['', line];
}

/** Next steps, tailored to what was found. */
function renderFooter(result: ScanResult, color: Colorizer): string[] {
  const lines: string[] = [''];
  if (result.findings.length === 0) {
    lines.push(color.green('  Nothing to fix. Keep the shield up. 🛡️'));
    for (const notice of result.notices) lines.push(color.dim(`  ${notice}`));
    return lines;
  }
  const worst = result.findings[0]?.severity ?? 'info';
  const critical = result.score.counts.critical;
  if (critical > 0) {
    lines.push(color.red(`  ⚠  ${critical} critical finding${critical === 1 ? '' : 's'} — rotate any exposed credential before anything else.`));
  }
  lines.push(`  ${color.bold('Fix it')}      npx vibe-shield scan --fix-prompt    ${color.dim('# writes SECURITY_PATCH_PROMPT.md for your agent')}`);
  lines.push(`  ${color.bold('Explain')}     npx vibe-shield explain ${result.findings[0]?.ruleId ?? 'VSB-AI-001'}`);
  lines.push(`  ${color.bold('Gate CI')}     npx vibe-shield scan --fail-on ${worst} --format github`);
  for (const notice of result.notices) lines.push(color.dim(`  ${notice}`));
  return lines;
}

/** Full scorecard as an array of lines (no trailing newline). */
export function renderConsoleReport(result: ScanResult, options: ReportOptions = {}): string[] {
  const color = options.color ?? createColorizer();
  const width = options.width ?? process.stdout.columns ?? DEFAULT_WIDTH;
  const lines: string[] = [];
  lines.push(...renderHeader(result, color, width));
  lines.push(...histogram(result, color));
  lines.push(...renderCategories(result, color));
  if (result.findings.length) {
    lines.push('');
    lines.push(color.bold('Findings'));
    lines.push(...renderFindings(result.findings, color, options));
  }
  if (options.showStats !== false) lines.push(...renderStats(result, color));
  lines.push(...renderFooter(result, color));
  return lines;
}

/** Print the scorecard to a stream. */
export function reportConsole(
  result: ScanResult,
  stream: { write(chunk: string): unknown; isTTY?: boolean; columns?: number } = process.stdout,
  options: ReportOptions = {},
): void {
  const color = options.color ?? createColorizer(stream);
  const width = options.width ?? stream.columns ?? DEFAULT_WIDTH;
  const lines = renderConsoleReport(result, { ...options, color, width });
  stream.write(`${lines.join('\n')}\n`);
}

export { GRADE_ICON, severityPaint, visibleLength };
