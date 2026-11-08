"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SCHEMA_VERSION = exports.isOutputFormat = exports.OUTPUT_FORMATS = void 0;
exports.formatJson = formatJson;
exports.formatSummary = formatSummary;
exports.formatCompact = formatCompact;
exports.formatGithub = formatGithub;
exports.formatSarif = formatSarif;
exports.formatResult = formatResult;
exports.groupByFile = groupByFile;
const node_url_1 = require("node:url");
const executive_1 = require("./executive");
exports.OUTPUT_FORMATS = ['console', 'compact', 'summary', 'json', 'sarif', 'github', 'markdown', 'html'];
const isOutputFormat = (value) => typeof value === 'string' && exports.OUTPUT_FORMATS.includes(value);
exports.isOutputFormat = isOutputFormat;
/** Bump when the JSON shape changes in a breaking way. */
exports.SCHEMA_VERSION = 1;
const SEVERITY_TO_SARIF = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
};
const SEVERITY_TO_GITHUB = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'notice',
    info: 'notice',
};
/* -------------------------------------------------------------------------- */
/* json / summary                                                            */
/* -------------------------------------------------------------------------- */
/** Full machine-readable report. */
function formatJson(result) {
    return `${JSON.stringify({ schemaVersion: exports.SCHEMA_VERSION, ...result }, null, 2)}\n`;
}
/** Counts and grade only. */
function formatSummary(result) {
    const payload = {
        schemaVersion: exports.SCHEMA_VERSION,
        command: result.command,
        version: result.version,
        rootDir: result.rootDir,
        score: result.score.score,
        grade: result.score.grade,
        total: result.score.total,
        counts: result.score.counts,
        filesScanned: result.stats.filesScanned,
        durationMs: result.stats.durationMs,
        ruleCount: result.ruleCount,
        suppressed: result.suppressedCount,
        notices: result.notices,
    };
    return `${JSON.stringify(payload, null, 2)}\n`;
}
/* -------------------------------------------------------------------------- */
/* compact                                                                   */
/* -------------------------------------------------------------------------- */
/** One line per finding: `path:line:col severity ruleId message`. */
function formatCompact(result) {
    const lines = result.findings.map((finding) => `${finding.filePath}:${finding.line}:${finding.column} ${finding.severity} ${finding.ruleId} ${finding.message.replace(/\s+/g, ' ')}`);
    const counts = result.score.counts;
    lines.push(`${result.score.score}/100 (${result.score.grade}) — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info across ${result.stats.filesScanned} ${result.stats.filesScanned === 1 ? 'file' : 'files'}`);
    return `${lines.join('\n')}\n`;
}
/* -------------------------------------------------------------------------- */
/* github actions annotations                                                */
/* -------------------------------------------------------------------------- */
/** Escape a value for a `::error ...::` workflow command. */
const escapeGithubData = (value) => value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
const escapeGithubProperty = (value) => escapeGithubData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
/**
 * GitHub Actions annotations. Each finding becomes an inline comment on the
 * diff when the workflow runs on a pull request.
 */
function formatGithub(result) {
    const lines = [];
    for (const finding of result.findings) {
        const level = SEVERITY_TO_GITHUB[finding.severity];
        const props = [
            `file=${escapeGithubProperty(finding.filePath)}`,
            `line=${finding.line}`,
            `col=${finding.column}`,
            `title=${escapeGithubProperty(`vibe-shield ${finding.ruleId}: ${finding.title}`)}`,
        ].join(',');
        lines.push(`::${level} ${props}::${escapeGithubData(`${finding.message} (${finding.cwe.id})`)}`);
    }
    lines.push(`::notice title=vibe-shield::Scanned ${result.stats.filesScanned} files in ${result.stats.durationMs}ms — score ${result.score.score}/100 (${result.score.grade}), ${result.score.total} finding(s).`);
    return `${lines.join('\n')}\n`;
}
/** CVSS-ish score so GitHub can rank the alert. */
const securitySeverity = (severity) => {
    switch (severity) {
        case 'critical':
            return '9.5';
        case 'high':
            return '8.1';
        case 'medium':
            return '5.5';
        case 'low':
            return '3.1';
        default:
            return '0.0';
    }
};
/**
 * SARIF 2.1.0 document accepted by GitHub code scanning, VS Code SARIF viewer,
 * and every other consumer of the format.
 */
function formatSarif(result) {
    const ruleMap = new Map();
    for (const finding of result.findings) {
        if (ruleMap.has(finding.ruleId))
            continue;
        ruleMap.set(finding.ruleId, {
            id: finding.ruleId,
            name: finding.slug.replace(/[^A-Za-z0-9]/g, '_'),
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.message },
            help: {
                text: [
                    finding.title,
                    '',
                    'Vulnerable:',
                    finding.insecureExample,
                    '',
                    'Fixed:',
                    finding.secureExample,
                    '',
                    ...finding.remediation.map((step, index) => `${index + 1}. ${step}`),
                ].join('\n'),
                markdown: [
                    `**${finding.title}**`,
                    '',
                    '```ts',
                    finding.insecureExample,
                    '```',
                    '',
                    '**Fix**',
                    '',
                    ...finding.remediation.map((step) => `- ${step}`),
                ].join('\n'),
            },
            defaultConfiguration: { level: SEVERITY_TO_SARIF[finding.severity] },
            properties: {
                tags: ['security', finding.category, finding.cwe.id, 'vibe-shield'],
                'security-severity': securitySeverity(finding.severity),
                precision: finding.confidence,
                category: finding.category,
                cwe: finding.cwe.id,
            },
            relationships: [{ target: { id: finding.cwe.id, toolComponent: { name: 'CWE' } } }],
            helpUri: finding.references[0],
        });
    }
    const sarif = {
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'vibe-shield',
                        version: result.version,
                        informationUri: 'https://github.com/avivgerz-hue/vibe-shield',
                        semanticVersion: result.version,
                        rules: [...ruleMap.values()],
                    },
                },
                invocations: [
                    {
                        executionSuccessful: true,
                        commandLine: `vibe-shield ${result.command}`,
                        startTimeUtc: result.startedAt,
                        endTimeUtc: result.finishedAt,
                        properties: {
                            score: result.score.score,
                            grade: result.score.grade,
                            filesScanned: result.stats.filesScanned,
                        },
                    },
                ],
                originalUriBaseIds: {
                    '%SRCROOT%': { uri: (0, node_url_1.pathToFileURL)(result.rootDir.endsWith('/') ? result.rootDir : result.rootDir + '/').href },
                },
                results: result.findings.map((finding) => ({
                    ruleId: finding.ruleId,
                    ruleIndex: [...ruleMap.keys()].indexOf(finding.ruleId),
                    level: SEVERITY_TO_SARIF[finding.severity],
                    message: { text: `${finding.message} [${finding.cwe.id}: ${finding.cwe.name}]` },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: { uri: finding.filePath.split('/').map(encodeURIComponent).join('/'), uriBaseId: '%SRCROOT%' },
                                region: {
                                    startLine: finding.line,
                                    startColumn: finding.column,
                                    endLine: finding.line,
                                    endColumn: finding.column + Math.max(1, finding.matched.length),
                                    snippet: { text: finding.snippet },
                                },
                            },
                        },
                    ],
                    partialFingerprints: {
                        'vibe-shield/v1': `${finding.ruleId}:${finding.filePath}:${finding.line}`,
                    },
                    properties: {
                        severity: finding.severity,
                        confidence: finding.confidence,
                        cwe: finding.cwe.id,
                        remediation: finding.remediation,
                        secureExample: finding.secureExample,
                    },
                })),
            },
        ],
    };
    return `${JSON.stringify(sarif, null, 2)}\n`;
}
/* -------------------------------------------------------------------------- */
/* dispatcher                                                                */
/* -------------------------------------------------------------------------- */
/** Render `result` in the requested format. */
function formatResult(result, format) {
    switch (format) {
        case 'markdown':
            return (0, executive_1.formatMarkdown)(result);
        case 'html':
            return (0, executive_1.formatHtml)(result);
        case 'json':
            return formatJson(result);
        case 'summary':
            return formatSummary(result);
        case 'compact':
            return formatCompact(result);
        case 'sarif':
            return formatSarif(result);
        case 'github':
            return formatGithub(result);
        default:
            throw new Error(`format "${String(format)}" is not a machine format`);
    }
}
/** Group findings by file for reporters that render trees. */
function groupByFile(findings) {
    const map = new Map();
    for (const finding of findings) {
        const bucket = map.get(finding.filePath) ?? [];
        bucket.push(finding);
        map.set(finding.filePath, bucket);
    }
    return map;
}
