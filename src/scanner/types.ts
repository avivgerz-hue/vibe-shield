import type { OwaspMappings } from './mappings';

/**
 * vibe-shield :: scanner type system
 * ----------------------------------
 * Every rule, finding and scan result in vibe-shield is described by the
 * interfaces below. They are intentionally serialisable (plain JSON) so that a
 * `ScanResult` can be cached to disk, emitted as SARIF, or handed to an agent
 * as a patch prompt without any transformation.
 */

/** Ordered list of severities, most severe first. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export type Severity = (typeof SEVERITIES)[number];

/** Detection confidence reported alongside every finding. */
export const CONFIDENCES = ['high', 'medium', 'low'] as const;

export type Confidence = (typeof CONFIDENCES)[number];

/**
 * Rule families. Each family maps 1:1 to a module in `src/scanner/rules`
 * (plus `agent-integrity`, which is produced by the MCP / skill auditor).
 */
export const RULE_CATEGORIES = [
  'client-exposure',
  'unguarded-routes',
  'database-exposure',
  'ai-vulnerabilities',
  'secret-entropy',
  'infrastructure',
  'dependencies',
  'agent-integrity',
] as const;

export type RuleCategory = (typeof RULE_CATEGORIES)[number];

export const CATEGORY_TITLES: Record<RuleCategory, string> = {
  'client-exposure': 'Client-side secret & data exposure',
  'unguarded-routes': 'Unguarded mutation routes (authZ / authN)',
  'database-exposure': 'Database exposure (RLS, SQLi, service role)',
  'ai-vulnerabilities': 'AI / LLM & classic web vulnerabilities',
  'secret-entropy': 'Hardcoded credentials & high-entropy secrets',
  infrastructure: 'Infrastructure, headers & containers',
  dependencies: 'Supply-chain & dependency hygiene',
  'agent-integrity': 'Agent skill & MCP poisoning',
};

/** Relative severity weight used by the scoring model. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Points deducted from the 100-point security score per finding. The curve is
 * deliberately steep: one leaked live key must be able to fail a build on its
 * own, while a handful of informational notes must not.
 */
export const SEVERITY_SCORE_PENALTY: Record<Severity, number> = {
  critical: 30,
  high: 12,
  medium: 5,
  low: 2,
  info: 0.5,
};

/**
 * Score ceilings: the worst severity present caps the achievable score, so a
 * single severe finding can never yield a good grade no matter how clean the
 * rest of the repository is.
 *
 * - any critical -> at most 29 (grade F)
 * - any high     -> at most 58 (grade C)
 * - any medium   -> at most 76 (grade B)
 * - any low      -> at most 88 (grade A-)
 */
export const SEVERITY_SCORE_CEILING: Partial<Record<Severity, number>> = {
  critical: 29,
  high: 58,
  medium: 76,
  low: 88,
};

export const GRADES = [
  'A+',
  'A',
  'A-',
  'B+',
  'B',
  'B-',
  'C+',
  'C',
  'C-',
  'D+',
  'D',
  'D-',
  'F',
] as const;

export type Grade = (typeof GRADES)[number];

/** Minimum score required for each grade. */
export const GRADE_THRESHOLDS: ReadonlyArray<{ grade: Grade; min: number }> = [
  { grade: 'A+', min: 98 },
  { grade: 'A', min: 93 },
  { grade: 'A-', min: 88 },
  { grade: 'B+', min: 82 },
  { grade: 'B', min: 76 },
  { grade: 'B-', min: 70 },
  { grade: 'C+', min: 64 },
  { grade: 'C', min: 58 },
  { grade: 'C-', min: 52 },
  { grade: 'D+', min: 45 },
  { grade: 'D', min: 38 },
  { grade: 'D-', min: 30 },
  { grade: 'F', min: -Infinity },
];

/** A CWE reference (https://cwe.mitre.org). */
export interface Cwe {
  /** e.g. `CWE-79` */
  id: string;
  /** Short human readable name, e.g. `Cross-site Scripting`. */
  name: string;
  /** Direct link to the CWE entry. */
  url: string;
}

/** Source language buckets used for cheap rule pre-filtering. */
export type Language =
  | 'typescript'
  | 'javascript'
  | 'jsx'
  | 'vue'
  | 'svelte'
  | 'html'
  | 'css'
  | 'sql'
  | 'prisma'
  | 'python'
  | 'ruby'
  | 'php'
  | 'go'
  | 'rust'
  | 'java'
  | 'shell'
  | 'yaml'
  | 'toml'
  | 'json'
  | 'markdown'
  | 'dotenv'
  | 'dockerfile'
  | 'terraform'
  | 'graphql'
  | 'xml'
  | 'other';

export const LANGUAGE_EXTENSIONS: Readonly<Record<string, Language>> = {
  ts: 'typescript',
  mts: 'typescript',
  cts: 'typescript',
  tsx: 'jsx',
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  jsx: 'jsx',
  vue: 'vue',
  svelte: 'svelte',
  html: 'html',
  htm: 'html',
  ejs: 'html',
  handlebars: 'html',
  hbs: 'html',
  css: 'css',
  scss: 'css',
  less: 'css',
  sql: 'sql',
  prisma: 'prisma',
  py: 'python',
  rb: 'ruby',
  php: 'php',
  go: 'go',
  rs: 'rust',
  java: 'java',
  kt: 'java',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  yml: 'yaml',
  yaml: 'yaml',
  toml: 'toml',
  json: 'json',
  jsonc: 'json',
  json5: 'json',
  map: 'json',
  md: 'markdown',
  mdx: 'markdown',
  markdown: 'markdown',
  env: 'dotenv',
  tf: 'terraform',
  tfvars: 'terraform',
  graphql: 'graphql',
  gql: 'graphql',
  xml: 'xml',
  plist: 'xml',
  csproj: 'xml',
  dockerfile: 'dockerfile',
};

/** Structural hints computed once per file and shared by every rule. */
export interface FileFlags {
  /** File starts with (or contains at top level) a `"use client"` directive. */
  isClientComponent: boolean;
  /** File contains a `"use server"` directive (Next.js server action module). */
  isServerActionModule: boolean;
  /** Next.js App Router handler: `app/**\/route.(ts|js)`. */
  isAppRouterRoute: boolean;
  /** Next.js Pages Router handler: `pages/api/**`. */
  isPagesApiRoute: boolean;
  /** Express / Fastify / Koa / Hono style server file. */
  isServerFrameworkFile: boolean;
  /** Path lives in a directory that is shipped to the browser verbatim. */
  isStaticAssetDir: boolean;
  /** Path matches a client-side source location (components/, pages/, app/, src/client...). */
  isClientPath: boolean;
  /** SQL migration file (Supabase / Prisma / Drizzle / raw migrations dir). */
  isMigration: boolean;
  /** `.env*` file. */
  isEnvFile: boolean;
  /** Test / spec / fixture / storybook file. */
  isTestFile: boolean;
  /** Documentation file (`*.md`, `docs/**`). */
  isDocumentation: boolean;
  /** Lockfile (never scanned for logic rules). */
  isLockfile: boolean;
  /** Generated / vendored file. */
  isGenerated: boolean;
  /** Agent instruction file (CLAUDE.md, AGENTS.md, .cursorrules, SKILL.md...). */
  isAgentInstructionFile: boolean;
  /** MCP configuration file (`mcp.json`, `.mcp.json`, `.cursor/mcp.json`...). */
  isMcpConfig: boolean;
  /** CI workflow file (`.github/workflows/*`). */
  isCiWorkflow: boolean;
  /** File mentions authentication/session symbols anywhere. */
  mentionsAuth: boolean;
  /** File performs a state mutation (DB write, HTTP mutation, fs write). */
  mentionsMutation: boolean;
  /** File talks to an LLM provider or the Vercel AI SDK. */
  mentionsLlm: boolean;
}

/** A table parsed out of the project's SQL files, with its RLS posture. */
export interface SqlTableInfo {
  /** Schema-qualified name as written, e.g. `public.accounts`. */
  table: string;
  /** Bare table name without the schema, e.g. `accounts`. */
  name: string;
  /** SQL file (relative to the scan root) that created the table. */
  file: string;
  /** 1-based line of the `CREATE TABLE` statement. */
  line: number;
  rlsEnabled: boolean;
  rlsForced: boolean;
  /** Names of every policy created for this table, across all SQL files. */
  policies: string[];
  /** True when `GRANT ... TO anon|authenticated|public` touches this table. */
  grantedToPublic: boolean;
  /** True for `CREATE TEMP/TEMPORARY/UNLOGGED TABLE` and catalog schemas. */
  internal: boolean;
}

/** Whole-project context: framework detection plus resolved config. */
export interface ProjectContext {
  /** Absolute path of the scan root. */
  rootDir: string;
  /** Frameworks/SDKs detected from package manifests and file layout. */
  frameworks: string[];
  /** `dependencies` + `devDependencies` names across discovered manifests. */
  dependencies: string[];
  /** True when any manifest declares an Express-family server. */
  hasExpressServer: boolean;
  hasFastifyServer: boolean;
  hasCookieSession: boolean;
  hasRateLimiting: boolean;
  hasCsrfProtection: boolean;
  hasSanitizer: boolean;
  hasAuthLibrary: boolean;
  hasAiSdk: boolean;
  hasSupabase: boolean;
  hasStripe: boolean;
  hasPrisma: boolean;
  /** File-relative list of SQL migration files discovered in the project. */
  migrationFiles: string[];
  /**
   * Cross-file RLS index. Row Level Security is frequently enabled in a
   * *later* migration than the `CREATE TABLE`, so the posture of a table can
   * only be judged project-wide.
   */
  sqlTables: SqlTableInfo[];
  /** True when a root-level `middleware.ts` verifies auth for every request. */
  hasGlobalAuthMiddleware: boolean;
  /** `matcher` patterns declared by that middleware (empty = matches all). */
  authMiddlewareMatchers: string[];
  /** Paths tracked by git, relative to the scan root (empty without git). */
  trackedPaths: string[];
  /** True when the scan root sits inside a readable git work tree. */
  gitAvailable: boolean;
}

/** An empty project context, used by tests and single-file scans. */
export const emptyProjectContext = (rootDir: string): ProjectContext => ({
  rootDir,
  frameworks: [],
  dependencies: [],
  hasExpressServer: false,
  hasFastifyServer: false,
  hasCookieSession: false,
  hasRateLimiting: false,
  hasCsrfProtection: false,
  hasSanitizer: false,
  hasAuthLibrary: false,
  hasAiSdk: false,
  hasSupabase: false,
  hasStripe: false,
  hasPrisma: false,
  migrationFiles: [],
  sqlTables: [],
  hasGlobalAuthMiddleware: false,
  authMiddlewareMatchers: [],
  trackedPaths: [],
  gitAvailable: false,
});

/** Everything a rule is allowed to look at for a single file. */
export interface FileContext {
  /** Absolute path. */
  absolutePath: string;
  /** POSIX-style path relative to the scan root (what gets printed). */
  relativePath: string;
  fileName: string;
  /** Lower-cased extension without the dot (`.env.local` -> `local`). */
  extension: string;
  language: Language;
  /** Raw file content. */
  content: string;
  /** Content lower-cased once, for cheap case-insensitive hint tests. */
  lowerContent: string;
  /** Content with comments blanked out (same length, offsets preserved). */
  code: string;
  /** Content with comments blanked out, lower-cased. */
  lowerCode: string;
  /** Split lines of `content` (no trailing newlines). */
  lines: string[];
  /** Byte length of the file. */
  bytes: number;
  flags: FileFlags;
  project: ProjectContext;
  /** Convert a character offset into 1-based `{ line, column }`. */
  locate(offset: number): { line: number; column: number };
  /** 1-based line text accessor (returns '' for out-of-range lines). */
  lineText(line: number): string;
}

/** A single detection produced by a rule. */
export interface RuleHit {
  /** Character offset of the match inside `FileContext.content`. */
  offset?: number;
  /** 1-based line (used when `offset` is absent). */
  line?: number;
  /** 1-based column (used when `offset` is absent). */
  column?: number;
  /** Override for the printed match text (secrets must be redacted). */
  matched?: string;
  /** Override for the human readable message. */
  message?: string;
  /** Override severity for this specific hit. */
  severity?: Severity;
  /** Override confidence for this specific hit. */
  confidence?: Confidence;
  /** Extra structured data carried into the finding / patch prompt. */
  data?: Record<string, unknown>;
}

/** A fully implemented vibe-shield detection rule. */
export interface Rule {
  /** Stable identifier, e.g. `VSB-DB-001`. */
  id: string;
  /** Kebab-case slug used in config files and SARIF, e.g. `migration-table-without-rls`. */
  slug: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  confidence: Confidence;
  cwe: Cwe;
  /** OWASP associations; LLM mappings apply only where context warrants. */
  owasp?: OwaspMappings;
  /** Why this matters — one or two sentences, written for the coding agent. */
  description: string;
  /** Code shape that triggers the rule. */
  insecureExample: string;
  /** Code shape that resolves the finding. */
  secureExample: string;
  /** Ordered remediation steps injected into `SECURITY_PATCH_PROMPT.md`. */
  remediation: string[];
  references: string[];
  /** File extensions the rule applies to (empty = any). */
  extensions?: string[];
  /** Languages the rule applies to (empty = any). */
  languages?: Language[];
  /** Path regexes; when present at least one must match `relativePath`. */
  pathPatterns?: RegExp[];
  /** Path regexes that disqualify a file even when `pathPatterns` matched. */
  excludePathPatterns?: RegExp[];
  /**
   * Cheap content probes. The engine only calls `detect` when at least one
   * hint matches, which keeps a full-repo scan in the millisecond range.
   */
  contentHints?: RegExp[];
  /** Files for which the rule should never run (tests, docs, lockfiles...). */
  skipFlags?: Array<keyof FileFlags>;
  detect(ctx: FileContext): RuleHit[];
  /**
   * Scope predicate. `defineRule` derives it from the declarative fields above
   * (plus an optional custom predicate); the engine calls it before `detect`.
   */
  appliesTo?: (ctx: FileContext) => boolean;
  /** Free-form tags used for filtering and documentation (`owasp-llm01`...). */
  tags?: readonly string[];
  /** Optional per-hit message refinement. */
  message?(ctx: FileContext, hit: RuleHit): string;
  /** Optional per-hit remediation refinement (replaces `remediation`). */
  remediate?(ctx: FileContext, hit: RuleHit): string[];
}

/** A reported vulnerability with exact `file:line` citation. */
export interface Finding {
  ruleId: string;
  slug: string;
  title: string;
  category: RuleCategory;
  severity: Severity;
  confidence: Confidence;
  cwe: Cwe;
  owasp?: OwaspMappings;
  /** POSIX path relative to the scan root. */
  filePath: string;
  /** Alias for filePath, relative to the scan root. */
  file: string;
  absolutePath: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** The offending source line, trimmed and truncated for display. */
  snippet: string;
  /** Exact matched text (secrets are redacted). */
  matched: string;
  message: string;
  remediation: string[];
  insecureExample: string;
  secureExample: string;
  references: string[];
  data?: Record<string, unknown>;
}

/** Scan timing / throughput statistics shown in the scorecard. */
export interface ScanStats {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  rulesExecuted: number;
  ruleInvocations: number;
  cacheHits: number;
  durationMs: number;
  filesPerSecond: number;
  megabytesPerSecond: number;
}

/** Severity histogram. */
export type SeverityCounts = Record<Severity, number>;

/** Static inventory; guard and RLS signals are not proof of effective protection. */
export interface AttackSurface {
  routes: Array<{ file: string; line: number; method: string; path: string; auth: 'guard-signal' | 'unknown' }>;
  tables: Array<{ file: string; line: number; table: string; rls: 'enabled-signal' | 'not-observed' }>;
  aiEntrypoints: Array<{ file: string; line: number }>;
  agentFiles: Array<{ file: string; kind: 'mcp' | 'skill'; name?: string }>;
}

/** Final scorecard. */
export interface SecurityScore {
  /** 0-100, rounded to one decimal. */
  score: number;
  grade: Grade;
  counts: SeverityCounts;
  /** Rule ids responsible for the grade ceiling, if any. */
  ceiling: { severity: Severity; limit: number } | null;
  total: number;
}

export interface ScanResult {
  rootDir: string;
  command: 'scan' | 'audit-skills';
  attackSurface?: AttackSurface;
  findings: Finding[];
  score: SecurityScore;
  stats: ScanStats;
  scannedPaths: string[];
  startedAt: string;
  finishedAt: string;
  version: string;
  ruleCount: number;
  suppressedCount: number;
  /** Human readable notes about the run (empty results, skipped config...). */
  notices: string[];
}

/** Suppression directive parsed from source comments. */
export interface Suppression {
  line: number;
  ruleIds: string[];
  reason: string;
}

export const emptySeverityCounts = (): SeverityCounts => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

/** Numeric rank so severities can be compared (`critical` = 5). */
export const severityRank = (severity: Severity): number => SEVERITY_WEIGHT[severity];

/** True when `severity` is at least as severe as `threshold`. */
export const meetsSeverity = (severity: Severity, threshold: Severity): boolean =>
  severityRank(severity) >= severityRank(threshold);

export const isSeverity = (value: unknown): value is Severity =>
  typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);

export const isRuleCategory = (value: unknown): value is RuleCategory =>
  typeof value === 'string' && (RULE_CATEGORIES as readonly string[]).includes(value);
