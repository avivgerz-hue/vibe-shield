"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.visibleLength = exports.severityPaint = exports.GRADE_ICON = exports.NOTHING_SCANNED = exports.pad = void 0;
exports.createColorizer = createColorizer;
exports.verdictLine = verdictLine;
exports.renderConsoleReport = renderConsoleReport;
exports.reportConsole = reportConsole;
const types_1 = require("../scanner/types");
const ANSI = {
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
function createColorizer(stream = process.stdout) {
    const env = process.env;
    const forced = env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '0';
    const disabled = env.NO_COLOR !== undefined || env.TERM === 'dumb';
    const enabled = forced || (!disabled && stream.isTTY === true);
    const wrap = (code, close) => (text) => (enabled ? `\u001B[${code}m${text}\u001B[${close}m` : text);
    return {
        enabled,
        red: wrap(...ANSI.red),
        green: wrap(...ANSI.green),
        yellow: wrap(...ANSI.yellow),
        blue: wrap(...ANSI.blue),
        magenta: wrap(...ANSI.magenta),
        cyan: wrap(...ANSI.cyan),
        gray: wrap(...ANSI.gray),
        bold: wrap(...ANSI.bold),
        dim: wrap(...ANSI.dim),
        underline: wrap(...ANSI.underline),
    };
}
const SEVERITY_COLORS = {
    critical: 'red',
    high: 'magenta',
    medium: 'yellow',
    low: 'blue',
    info: 'gray',
};
const severityPaint = (color, severity) => color[SEVERITY_COLORS[severity]];
exports.severityPaint = severityPaint;
/* -------------------------------------------------------------------------- */
/* Layout helpers                                                             */
/* -------------------------------------------------------------------------- */
/** Strip ANSI codes to measure true display width. */
const visibleLength = (text) => text.replace(/\u001B\[[0-9;]*m/g, '').length;
exports.visibleLength = visibleLength;
/** Pad `text` to `width` visible characters. */
const pad = (text, width) => text + ' '.repeat(Math.max(0, width - visibleLength(text)));
exports.pad = pad;
const truncate = (text, width) => text.length <= width ? text : `${text.slice(0, Math.max(0, width - 1))}…`;
const GRADE_ICON = {
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
exports.GRADE_ICON = GRADE_ICON;
const DEFAULT_WIDTH = 100;
/** Shown instead of a grade when discovery matched nothing: silence is not a pass. */
exports.NOTHING_SCANNED = '⚠  NO FILES SCANNED — this is not a pass';
/** The one-line verdict, e.g. `💀 GRADE F — 0/100 · 6 critical`. */
function verdictLine(result, color) {
    if (result.stats.filesScanned === 0)
        return color.yellow(exports.NOTHING_SCANNED);
    const icon = GRADE_ICON[result.score.grade] ?? '•';
    const grade = color.bold(severityPaint(color, result.score.counts.critical > 0 ? 'critical' : result.score.counts.high > 0 ? 'high' : result.score.counts.medium > 0 ? 'medium' : 'low')(result.score.grade));
    const counts = ['critical', 'high', 'medium', 'low']
        .filter((severity) => result.score.counts[severity] > 0)
        .map((severity) => `${result.score.counts[severity]} ${severity}`)
        .join(' · ');
    return `${icon} GRADE ${grade} — ${result.score.score}/100${counts ? ` · ${counts}` : ''}`;
}
/** Render the header block: brand, version, target and verdict. */
function renderHeader(result, color, width) {
    const lines = [];
    const title = color.bold(color.cyan('🛡️  vibe-shield'));
    const version = color.dim(`v${result.version}`);
    const mode = result.command === 'audit-skills' ? 'agent surface audit' : 'security scan';
    lines.push(`${title} ${version} ${color.dim(`· ${mode}`)}`);
    lines.push(color.dim(`target  ${truncate(result.rootDir, width - 10)}`));
    lines.push('');
    lines.push(verdictLine(result, color));
    return lines;
}
/** A horizontal bar for the severity histogram. */
function histogram(result, color) {
    const counts = result.score.counts;
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const lines = [];
    for (const severity of order) {
        const count = counts[severity];
        if (!count)
            continue;
        const paint = severityPaint(color, severity);
        const bar = paint('█'.repeat(Math.min(40, count)));
        lines.push(`  ${(0, exports.pad)(paint(severity.toUpperCase()), 8)} ${(0, exports.pad)(String(count), 4)} ${bar}`);
    }
    return lines;
}
/** All findings grouped by file, with exact citations. */
function renderFindings(findings, color, options) {
    const lines = [];
    const maxFindings = options.maxFindings ?? 50;
    // Severity is the outer sort key (what to fix first); file is the inner one so
    // each file's findings stay together and the list reads like a patch.
    const ordered = [...findings].sort((a, b) => types_1.SEVERITY_WEIGHT[b.severity] - types_1.SEVERITY_WEIGHT[a.severity] ||
        a.filePath.localeCompare(b.filePath) ||
        a.line - b.line);
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
        if (finding.snippet)
            lines.push(`           ${color.gray(truncate(finding.snippet, 110))}`);
    }
    if (maxFindings > 0 && findings.length > maxFindings) {
        lines.push('');
        lines.push(color.dim(`  … and ${findings.length - maxFindings} more. Run with --format json or --max-findings 0 to see every finding.`));
    }
    return lines;
}
/** Category breakdown, useful when the list is long. */
function renderCategories(result, color) {
    const byCategory = new Map();
    for (const finding of result.findings) {
        const bucket = byCategory.get(finding.category) ?? [];
        bucket.push(finding);
        byCategory.set(finding.category, bucket);
    }
    if (byCategory.size <= 1)
        return [];
    const lines = ['', color.bold('By category')];
    const sorted = [...byCategory.entries()].sort((a, b) => b[1].length - a[1].length);
    for (const [category, findings] of sorted) {
        const worst = findings.reduce((acc, finding) => (types_1.SEVERITY_WEIGHT[finding.severity] > types_1.SEVERITY_WEIGHT[acc] ? finding.severity : acc), 'info');
        const paint = severityPaint(color, worst);
        lines.push(`  ${paint('●')} ${(0, exports.pad)(types_1.CATEGORY_TITLES[category] ?? category, 44)} ${findings.length}`);
    }
    return lines;
}
/** Timing / throughput footer. */
function renderStats(result, color) {
    const { stats } = result;
    const parts = [
        `${stats.filesScanned} ${stats.filesScanned === 1 ? 'file' : 'files'}`,
    ];
    parts.push(stats.bytesScanned >= 1024
        ? `${(stats.bytesScanned / 1024).toFixed(0)} KiB`
        : `${stats.bytesScanned} B`);
    parts.push(`${stats.filesPerSecond} files/s`, `${stats.durationMs} ms`, `${result.ruleCount} rules`);
    if (stats.cacheHits > 0)
        parts.push(`${stats.cacheHits} cached`);
    if (result.suppressedCount > 0)
        parts.push(`${result.suppressedCount} suppressed`);
    const line = color.dim(`  ${parts.join('  ·  ')}`);
    return ['', line];
}
/** Next steps, tailored to what was found. */
function renderFooter(result, color) {
    const lines = [''];
    if (result.stats.filesScanned === 0) {
        for (const notice of result.notices)
            lines.push(color.dim(`  ${notice}`));
        lines.push(color.dim('  No grade is given for an empty scan — check the path, --include-docs/--include-tests, and .vibe-shieldignore.'));
        return lines;
    }
    if (result.findings.length === 0) {
        lines.push(color.green('  Nothing to fix. Keep the shield up. 🛡️'));
        // The engine's "no vulnerabilities found" notice says the same thing in
        // different words; drop it so a clean run stays one line.
        for (const notice of result.notices) {
            if (/^no vulnerabilities found/i.test(notice))
                continue;
            lines.push(color.dim(`  ${notice}`));
        }
        return lines;
    }
    const worst = result.findings[0]?.severity ?? 'info';
    const critical = result.score.counts.critical;
    if (critical > 0) {
        lines.push(color.red(`  ⚠  ${critical} critical finding${critical === 1 ? '' : 's'} — rotate any exposed credential before anything else.`));
    }
    lines.push(`  ${color.bold('Fix it')}      npx -y @vibefoundry/vibe-shield scan --fix-prompt    ${color.dim('# writes SECURITY_PATCH_PROMPT.md for your agent')}`);
    lines.push(`  ${color.bold('Explain')}     npx -y @vibefoundry/vibe-shield explain ${result.findings[0]?.ruleId ?? 'VSB-AI-001'}`);
    lines.push(`  ${color.bold('Gate CI')}     npx -y @vibefoundry/vibe-shield scan --fail-on ${worst} --format github`);
    for (const notice of result.notices)
        lines.push(color.dim(`  ${notice}`));
    return lines;
}
/** Full scorecard as an array of lines (no trailing newline). */
function renderConsoleReport(result, options = {}) {
    const color = options.color ?? createColorizer();
    const width = options.width ?? process.stdout.columns ?? DEFAULT_WIDTH;
    const lines = [];
    lines.push(...renderHeader(result, color, width));
    const bars = histogram(result, color);
    if (bars.length) {
        lines.push('');
        lines.push(...bars);
    }
    lines.push(...renderCategories(result, color));
    if (result.findings.length) {
        lines.push('');
        lines.push(color.bold('Findings'));
        lines.push(...renderFindings(result.findings, color, options));
    }
    if (options.showStats !== false)
        lines.push(...renderStats(result, color));
    lines.push(...renderFooter(result, color));
    return lines;
}
/** Print the scorecard to a stream. */
function reportConsole(result, stream = process.stdout, options = {}) {
    const color = options.color ?? createColorizer(stream);
    const width = options.width ?? stream.columns ?? DEFAULT_WIDTH;
    const lines = renderConsoleReport(result, { ...options, color, width });
    stream.write(`${lines.join('\n')}\n`);
}
