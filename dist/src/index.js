"use strict";
/**
 * vibe-shield :: public API
 * -------------------------
 * Everything an embedder needs: run a scan, audit agent surface, render a
 * report, or write a patch prompt — without spawning the CLI.
 *
 * ```ts
 * import { scanProject, formatSarif } from 'vibe-shield';
 *
 * const result = await scanProject({ rootDir: process.cwd() });
 * process.stdout.write(formatSarif(result));
 * ```
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatCompact = exports.formatSummary = exports.formatJson = exports.formatResult = exports.verdictLine = exports.createColorizer = exports.renderConsoleReport = exports.reportConsole = exports.jwtHasPrivilegedRole = exports.decodeJwtPayload = exports.SECRET_PATTERNS = exports.findSecrets = exports.tolerantJsonParse = exports.detectLanguage = exports.computeFlags = exports.createFileContext = exports.detectProject = exports.readGitTrackedPaths = exports.mergeSqlTables = exports.parseSqlTables = exports.parseMiddlewareMatchers = exports.parseFrontmatter = exports.discoverAgentFiles = exports.auditSkills = exports.AGENT_RULES = exports.selectRules = exports.rulesByCategory = exports.getRule = exports.RULES_FINGERPRINT = exports.SCAN_RULES = exports.ALL_RULES = exports.CACHE_FILE_NAME = exports.DEFAULT_CONCURRENCY = exports.MAX_FILE_SIZE_BYTES = exports.BINARY_EXTENSIONS = exports.DEFAULT_IGNORED_DIRS = exports.isDocPath = exports.isTestPath = exports.contentHash = exports.packageVersion = exports.gitTrackedPaths = exports.dedupe = exports.hasFindingsAtOrAbove = exports.suppressionFor = exports.parseSuppressions = exports.applySuppressions = exports.scoreFindings = exports.runRulesOnFile = exports.discoverFiles = exports.scanProject = void 0;
exports.VERSION = exports.isRuleCategory = exports.isSeverity = exports.meetsSeverity = exports.severityRank = exports.emptySeverityCounts = exports.emptyProjectContext = exports.CATEGORY_TITLES = exports.RULE_CATEGORIES = exports.GRADE_THRESHOLDS = exports.GRADES = exports.SEVERITY_SCORE_CEILING = exports.SEVERITY_SCORE_PENALTY = exports.SEVERITY_WEIGHT = exports.SEVERITIES = exports.IGNORE_TEMPLATE = exports.WORKFLOW_TEMPLATE = exports.AGENTS_SECTION = exports.SKILL_TEMPLATE = exports.installScaffold = exports.buildScaffold = exports.PATCH_PROMPT_FILENAME = exports.writePatchPrompt = exports.buildPatchPrompt = exports.SCHEMA_VERSION = exports.OUTPUT_FORMATS = exports.isOutputFormat = exports.groupByFile = exports.formatGithub = exports.formatSarif = void 0;
var engine_1 = require("./scanner/engine");
Object.defineProperty(exports, "scanProject", { enumerable: true, get: function () { return engine_1.scanProject; } });
Object.defineProperty(exports, "discoverFiles", { enumerable: true, get: function () { return engine_1.discoverFiles; } });
Object.defineProperty(exports, "runRulesOnFile", { enumerable: true, get: function () { return engine_1.runRulesOnFile; } });
Object.defineProperty(exports, "scoreFindings", { enumerable: true, get: function () { return engine_1.scoreFindings; } });
Object.defineProperty(exports, "applySuppressions", { enumerable: true, get: function () { return engine_1.applySuppressions; } });
Object.defineProperty(exports, "parseSuppressions", { enumerable: true, get: function () { return engine_1.parseSuppressions; } });
Object.defineProperty(exports, "suppressionFor", { enumerable: true, get: function () { return engine_1.suppressionFor; } });
Object.defineProperty(exports, "hasFindingsAtOrAbove", { enumerable: true, get: function () { return engine_1.hasFindingsAtOrAbove; } });
Object.defineProperty(exports, "dedupe", { enumerable: true, get: function () { return engine_1.dedupe; } });
Object.defineProperty(exports, "gitTrackedPaths", { enumerable: true, get: function () { return engine_1.gitTrackedPaths; } });
Object.defineProperty(exports, "packageVersion", { enumerable: true, get: function () { return engine_1.packageVersion; } });
Object.defineProperty(exports, "contentHash", { enumerable: true, get: function () { return engine_1.contentHash; } });
Object.defineProperty(exports, "isTestPath", { enumerable: true, get: function () { return engine_1.isTestPath; } });
Object.defineProperty(exports, "isDocPath", { enumerable: true, get: function () { return engine_1.isDocPath; } });
Object.defineProperty(exports, "DEFAULT_IGNORED_DIRS", { enumerable: true, get: function () { return engine_1.DEFAULT_IGNORED_DIRS; } });
Object.defineProperty(exports, "BINARY_EXTENSIONS", { enumerable: true, get: function () { return engine_1.BINARY_EXTENSIONS; } });
Object.defineProperty(exports, "MAX_FILE_SIZE_BYTES", { enumerable: true, get: function () { return engine_1.MAX_FILE_SIZE_BYTES; } });
Object.defineProperty(exports, "DEFAULT_CONCURRENCY", { enumerable: true, get: function () { return engine_1.DEFAULT_CONCURRENCY; } });
Object.defineProperty(exports, "CACHE_FILE_NAME", { enumerable: true, get: function () { return engine_1.CACHE_FILE_NAME; } });
var rules_1 = require("./scanner/rules");
Object.defineProperty(exports, "ALL_RULES", { enumerable: true, get: function () { return rules_1.ALL_RULES; } });
Object.defineProperty(exports, "SCAN_RULES", { enumerable: true, get: function () { return rules_1.SCAN_RULES; } });
Object.defineProperty(exports, "RULES_FINGERPRINT", { enumerable: true, get: function () { return rules_1.RULES_FINGERPRINT; } });
Object.defineProperty(exports, "getRule", { enumerable: true, get: function () { return rules_1.getRule; } });
Object.defineProperty(exports, "rulesByCategory", { enumerable: true, get: function () { return rules_1.rulesByCategory; } });
Object.defineProperty(exports, "selectRules", { enumerable: true, get: function () { return rules_1.selectRules; } });
var skill_auditor_1 = require("./mcp-guard/skill-auditor");
Object.defineProperty(exports, "AGENT_RULES", { enumerable: true, get: function () { return skill_auditor_1.AGENT_RULES; } });
Object.defineProperty(exports, "auditSkills", { enumerable: true, get: function () { return skill_auditor_1.auditSkills; } });
Object.defineProperty(exports, "discoverAgentFiles", { enumerable: true, get: function () { return skill_auditor_1.discoverAgentFiles; } });
Object.defineProperty(exports, "parseFrontmatter", { enumerable: true, get: function () { return skill_auditor_1.parseFrontmatter; } });
var context_1 = require("./scanner/context");
Object.defineProperty(exports, "parseMiddlewareMatchers", { enumerable: true, get: function () { return context_1.parseMiddlewareMatchers; } });
Object.defineProperty(exports, "parseSqlTables", { enumerable: true, get: function () { return context_1.parseSqlTables; } });
Object.defineProperty(exports, "mergeSqlTables", { enumerable: true, get: function () { return context_1.mergeSqlTables; } });
Object.defineProperty(exports, "readGitTrackedPaths", { enumerable: true, get: function () { return context_1.readGitTrackedPaths; } });
Object.defineProperty(exports, "detectProject", { enumerable: true, get: function () { return context_1.detectProject; } });
Object.defineProperty(exports, "createFileContext", { enumerable: true, get: function () { return context_1.createFileContext; } });
Object.defineProperty(exports, "computeFlags", { enumerable: true, get: function () { return context_1.computeFlags; } });
Object.defineProperty(exports, "detectLanguage", { enumerable: true, get: function () { return context_1.detectLanguage; } });
Object.defineProperty(exports, "tolerantJsonParse", { enumerable: true, get: function () { return context_1.tolerantJsonParse; } });
var patterns_1 = require("./secrets/patterns");
Object.defineProperty(exports, "findSecrets", { enumerable: true, get: function () { return patterns_1.findSecrets; } });
Object.defineProperty(exports, "SECRET_PATTERNS", { enumerable: true, get: function () { return patterns_1.SECRET_PATTERNS; } });
Object.defineProperty(exports, "decodeJwtPayload", { enumerable: true, get: function () { return patterns_1.decodeJwtPayload; } });
Object.defineProperty(exports, "jwtHasPrivilegedRole", { enumerable: true, get: function () { return patterns_1.jwtHasPrivilegedRole; } });
var console_reporter_1 = require("./reporter/console-reporter");
Object.defineProperty(exports, "reportConsole", { enumerable: true, get: function () { return console_reporter_1.reportConsole; } });
Object.defineProperty(exports, "renderConsoleReport", { enumerable: true, get: function () { return console_reporter_1.renderConsoleReport; } });
Object.defineProperty(exports, "createColorizer", { enumerable: true, get: function () { return console_reporter_1.createColorizer; } });
Object.defineProperty(exports, "verdictLine", { enumerable: true, get: function () { return console_reporter_1.verdictLine; } });
var formatters_1 = require("./reporter/formatters");
Object.defineProperty(exports, "formatResult", { enumerable: true, get: function () { return formatters_1.formatResult; } });
Object.defineProperty(exports, "formatJson", { enumerable: true, get: function () { return formatters_1.formatJson; } });
Object.defineProperty(exports, "formatSummary", { enumerable: true, get: function () { return formatters_1.formatSummary; } });
Object.defineProperty(exports, "formatCompact", { enumerable: true, get: function () { return formatters_1.formatCompact; } });
Object.defineProperty(exports, "formatSarif", { enumerable: true, get: function () { return formatters_1.formatSarif; } });
Object.defineProperty(exports, "formatGithub", { enumerable: true, get: function () { return formatters_1.formatGithub; } });
Object.defineProperty(exports, "groupByFile", { enumerable: true, get: function () { return formatters_1.groupByFile; } });
Object.defineProperty(exports, "isOutputFormat", { enumerable: true, get: function () { return formatters_1.isOutputFormat; } });
Object.defineProperty(exports, "OUTPUT_FORMATS", { enumerable: true, get: function () { return formatters_1.OUTPUT_FORMATS; } });
Object.defineProperty(exports, "SCHEMA_VERSION", { enumerable: true, get: function () { return formatters_1.SCHEMA_VERSION; } });
var patch_prompt_writer_1 = require("./reporter/patch-prompt-writer");
Object.defineProperty(exports, "buildPatchPrompt", { enumerable: true, get: function () { return patch_prompt_writer_1.buildPatchPrompt; } });
Object.defineProperty(exports, "writePatchPrompt", { enumerable: true, get: function () { return patch_prompt_writer_1.writePatchPrompt; } });
Object.defineProperty(exports, "PATCH_PROMPT_FILENAME", { enumerable: true, get: function () { return patch_prompt_writer_1.PATCH_PROMPT_FILENAME; } });
var scaffold_1 = require("./init/scaffold");
Object.defineProperty(exports, "buildScaffold", { enumerable: true, get: function () { return scaffold_1.buildScaffold; } });
Object.defineProperty(exports, "installScaffold", { enumerable: true, get: function () { return scaffold_1.installScaffold; } });
Object.defineProperty(exports, "SKILL_TEMPLATE", { enumerable: true, get: function () { return scaffold_1.SKILL_TEMPLATE; } });
Object.defineProperty(exports, "AGENTS_SECTION", { enumerable: true, get: function () { return scaffold_1.AGENTS_SECTION; } });
Object.defineProperty(exports, "WORKFLOW_TEMPLATE", { enumerable: true, get: function () { return scaffold_1.WORKFLOW_TEMPLATE; } });
Object.defineProperty(exports, "IGNORE_TEMPLATE", { enumerable: true, get: function () { return scaffold_1.IGNORE_TEMPLATE; } });
var types_1 = require("./scanner/types");
Object.defineProperty(exports, "SEVERITIES", { enumerable: true, get: function () { return types_1.SEVERITIES; } });
Object.defineProperty(exports, "SEVERITY_WEIGHT", { enumerable: true, get: function () { return types_1.SEVERITY_WEIGHT; } });
Object.defineProperty(exports, "SEVERITY_SCORE_PENALTY", { enumerable: true, get: function () { return types_1.SEVERITY_SCORE_PENALTY; } });
Object.defineProperty(exports, "SEVERITY_SCORE_CEILING", { enumerable: true, get: function () { return types_1.SEVERITY_SCORE_CEILING; } });
Object.defineProperty(exports, "GRADES", { enumerable: true, get: function () { return types_1.GRADES; } });
Object.defineProperty(exports, "GRADE_THRESHOLDS", { enumerable: true, get: function () { return types_1.GRADE_THRESHOLDS; } });
Object.defineProperty(exports, "RULE_CATEGORIES", { enumerable: true, get: function () { return types_1.RULE_CATEGORIES; } });
Object.defineProperty(exports, "CATEGORY_TITLES", { enumerable: true, get: function () { return types_1.CATEGORY_TITLES; } });
Object.defineProperty(exports, "emptyProjectContext", { enumerable: true, get: function () { return types_1.emptyProjectContext; } });
Object.defineProperty(exports, "emptySeverityCounts", { enumerable: true, get: function () { return types_1.emptySeverityCounts; } });
Object.defineProperty(exports, "severityRank", { enumerable: true, get: function () { return types_1.severityRank; } });
Object.defineProperty(exports, "meetsSeverity", { enumerable: true, get: function () { return types_1.meetsSeverity; } });
Object.defineProperty(exports, "isSeverity", { enumerable: true, get: function () { return types_1.isSeverity; } });
Object.defineProperty(exports, "isRuleCategory", { enumerable: true, get: function () { return types_1.isRuleCategory; } });
/** Package version, injected at build time from `package.json`. */
exports.VERSION = '1.1.0';
