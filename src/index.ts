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

export {
  scanProject,
  discoverFiles,
  runRulesOnFile,
  scoreFindings,
  applySuppressions,
  parseSuppressions,
  suppressionFor,
  hasFindingsAtOrAbove,
  dedupe,
  gitTrackedPaths,
  packageVersion,
  contentHash,
  isTestPath,
  isDocPath,
  DEFAULT_IGNORED_DIRS,
  BINARY_EXTENSIONS,
  MAX_FILE_SIZE_BYTES,
  DEFAULT_CONCURRENCY,
  CACHE_FILE_NAME,
  type ScanOptions,
  type DiscoveredFile,
  type DiscoverResult,
} from './scanner/engine';

export {
  ALL_RULES,
  SCAN_RULES,
  RULES_FINGERPRINT,
  getRule,
  rulesByCategory,
  selectRules,
} from './scanner/rules';

export { AGENT_RULES, auditSkills, discoverAgentFiles, parseFrontmatter, type AuditOptions, type SkillFrontmatter } from './mcp-guard/skill-auditor';

export { parseMiddlewareMatchers, parseSqlTables, mergeSqlTables, readGitTrackedPaths, detectProject, createFileContext, computeFlags, detectLanguage, tolerantJsonParse } from './scanner/context';

export { findSecrets, SECRET_PATTERNS, decodeJwtPayload, jwtHasPrivilegedRole, type SecretMatch, type SecretPattern } from './secrets/patterns';

export { reportConsole, renderConsoleReport, createColorizer, verdictLine, type Colorizer, type ReportOptions } from './reporter/console-reporter';

export {
  formatResult,
  formatJson,
  formatSummary,
  formatCompact,
  formatSarif,
  formatGithub,
  groupByFile,
  isOutputFormat,
  OUTPUT_FORMATS,
  SCHEMA_VERSION,
  type OutputFormat,
} from './reporter/formatters';

export {
  buildPatchPrompt,
  writePatchPrompt,
  PATCH_PROMPT_FILENAME,
  type PatchPromptOptions,
} from './reporter/patch-prompt-writer';

export {
  buildScaffold,
  installScaffold,
  SKILL_TEMPLATE,
  AGENTS_SECTION,
  WORKFLOW_TEMPLATE,
  IGNORE_TEMPLATE,
  type ScaffoldFile,
  type InitOptions,
  type InitResult,
} from './init/scaffold';

export {
  SEVERITIES,
  SEVERITY_WEIGHT,
  SEVERITY_SCORE_PENALTY,
  SEVERITY_SCORE_CEILING,
  GRADES,
  GRADE_THRESHOLDS,
  RULE_CATEGORIES,
  CATEGORY_TITLES,
  emptyProjectContext,
  emptySeverityCounts,
  severityRank,
  meetsSeverity,
  isSeverity,
  isRuleCategory,
  type Cwe,
  type Confidence,
  type FileContext,
  type FileFlags,
  type Finding,
  type Grade,
  type Language,
  type ProjectContext,
  type Rule,
  type RuleCategory,
  type RuleHit,
  type ScanResult,
  type ScanStats,
  type SecurityScore,
  type Severity,
  type SeverityCounts,
  type SqlTableInfo,
  type Suppression,
} from './scanner/types';

/** Package version, injected at build time from `package.json`. */
export const VERSION = '1.1.0';
