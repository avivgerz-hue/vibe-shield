/**
 * vibe-shield :: file & project context
 * -------------------------------------
 * Everything a rule needs is computed once per file here: language, structural
 * flags ("is this a client component?", "is this an App Router handler?", "is
 * this a SQL migration?") and the comment-masked code view.
 */

import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';

import {
  AUTH_VERIFICATION_REGEX,
  LLM_REGEX,
  MUTATION_REGEX,
  SQL_MUTATION_REGEX,
} from './lexicon';
import { LineIndex, maskComments, maskSqlComments, splitLines } from './text';
import {
  LANGUAGE_EXTENSIONS,
  type FileContext,
  type FileFlags,
  type Language,
  type ProjectContext,
  type SqlTableInfo,
} from './types';

const posix = (value: string): string => value.split(path.sep).join('/');

export const toPosix = posix;

const DOTENV_NAMES = /^\.env(?:\..+)?$/i;

const INSTRUCTION_FILE_NAMES = new Set([
  'claude.md',
  'agents.md',
  'agent.md',
  'gemini.md',
  'cursorrules',
  'windsurfrules',
  'clinerules',
  'roorules',
  'skill.md',
  'copilot-instructions.md',
  'cline_docs',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  '.roorules',
]);

const MCP_CONFIG_NAMES = /^(?:\.mcp|mcp|mcp-config|mcp_settings|mcp\.settings|claude_desktop_config|settings)\.json$/i;

const CI_WORKFLOW_REGEX =
  /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(?:^|\/)\.gitlab-ci\.yml$|(?:^|\/)\.circleci\/config\.yml$|(?:^|\/)azure-pipelines\.yml$|(?:^|\/)\.travis\.yml$|(?:^|\/)Jenkinsfile$/i;

const TEST_PATH_REGEX =
  /(?:^|\/)(?:__tests__|__mocks__|tests?|specs?|e2e|cypress|playwright|fixtures?|stories|test-utils|testing)(?:\/|$)|\.(?:test|spec|stories|it)\.[cm]?[jt]sx?$|_test\.go$|_spec\.rb$|(?:^|\/)conftest\.py$|(?:^|\/)test_[^/]+\.py$/i;

const MIGRATION_PATH_REGEX =
  /(?:^|\/)(?:supabase\/migrations|migrations?|db\/migrations|prisma\/migrations|drizzle\/?|alembic\/versions|sequelize|mikro-orm-migrations)(?:\/|$)/i;

const CLIENT_PATH_REGEX =
  /(?:^|\/)(?:public|static|assets|wwwroot|client|frontend|ui|components?|hooks?|stores?|renderer|browser|web|app\/(?:[^/]+\/)?components)(?:\/|$)/i;

const STATIC_ASSET_REGEX = /(?:^|\/)(?:public|static|assets|wwwroot|media|dist|build|out)(?:\/|$)/i;

const LOCKFILE_REGEX =
  /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|bun\.lock|composer\.lock|Gemfile\.lock|poetry\.lock|uv\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|\.gitkeep)$/i;

const GENERATED_REGEX =
  /(?:^|\/)(?:generated|codegen|\.gen|__generated__|auto-generated)(?:[/.]|$)|\.min\.[cm]?js$|\.min\.css$|\.d\.ts$|\.snap$|(?:^|\/)dist\/|(?:^|\/)build\/|\.pb\.go$|_pb2\.py$/i;

const DOC_REGEX =
  /\.(?:md|mdx|markdown|rst|txt|adoc)$|(?:^|\/)(?:docs?|documentation|website\/docs)(?:\/|$)|(?:^|\/)(?:README|CHANGELOG|CONTRIBUTING|SECURITY|CODE_OF_CONDUCT|LICENSE)(?:\.[A-Za-z]+)?$/i;

const SERVER_FRAMEWORK_REGEX =
  /(?:from\s+['"](?:express|fastify|koa|hono|@hono\/node-server|@nestjs\/[a-z-]+|restana|elysia|polka|connect)['"]|require\(\s*['"](?:express|fastify|koa|hono|restana)['"]\s*\)|import\s+(?:Express|Fastify|Koa|Hono)\b)/;

const APP_ROUTER_ROUTE_REGEX = /(?:^|\/)app\/(?:[^/]+\/)*route\.[cm]?[jt]sx?$/i;
const PAGES_API_REGEX = /(?:^|\/)pages\/api\/(?:[^/]+\/)*[^/]+\.[cm]?[jt]sx?$/i;

/** Resolve the `Language` bucket for a path. */
export function detectLanguage(relativePath: string, fileName: string, extension: string): Language {
  const posixPath = relativePath.split(path.sep).join('/');
  if (DOTENV_NAMES.test(fileName)) return 'dotenv';
  if (/^dockerfile/i.test(fileName) || /\.dockerfile$/i.test(fileName)) return 'dockerfile';
  if (/^(?:makefile|procfile|rakefile|justfile|jenkinsfile|brewfile)$/i.test(fileName)) return 'shell';
  // Cursor / Windsurf rule files use the `.mdc` dialect of markdown.
  if (/\.mdc$/i.test(fileName)) return 'markdown';
  if (
    INSTRUCTION_FILE_NAMES.has(fileName.toLowerCase()) ||
    /^\.?(?:cursor|windsurf|cline|roo)rules$/i.test(fileName)
  ) {
    return 'markdown';
  }
  if (extension && LANGUAGE_EXTENSIONS[extension]) return LANGUAGE_EXTENSIONS[extension];
  // Extension-less files are classified by where they live: CI workflows are
  // YAML, `.env`-style dotfiles in nested config directories are dotenv.
  if (!extension) {
    if (/(?:^|\/)\.github\/workflows\/[^/]+$/.test(posixPath)) return 'yaml';
    if (/(?:^|\/)\.env\.[^/]+$/.test(posixPath)) return 'dotenv';
    if (/(?:^|\/)(?:LICENSE|NOTICE|AUTHORS)(?:\.[A-Za-z]+)?$/.test(posixPath)) return 'markdown';
  }
  const lowerName = fileName.toLowerCase();
  if (lowerName === 'license' || lowerName === 'notice') return 'markdown';
  return 'other';
}

/** Extension without the dot, lower-cased (`.env.local` -> `local`). */
export const extensionOf = (fileName: string): string => {
  const dot = fileName.lastIndexOf('.');
  if (dot <= 0) return '';
  return fileName.slice(dot + 1).toLowerCase();
};

const CLIENT_DIRECTIVE_REGEX = /^\s*['"]use client['"]\s*;?\s*$/m;
const SERVER_DIRECTIVE_REGEX = /^\s*['"]use server['"]\s*;?\s*$/m;

/** Compute the structural flags for one file. */
export function computeFlags(
  relativePath: string,
  fileName: string,
  extension: string,
  language: Language,
  content: string,
): FileFlags {
  // A `"use client"` / `"use server"` directive only counts in the leading
  // prologue of the module (before any statement), exactly like the bundlers.
  const head = content.slice(0, 4000);
  const isClientComponent = CLIENT_DIRECTIVE_REGEX.test(head);
  const lowerName = fileName.toLowerCase();
  const isMarkdownInstruction =
    language === 'markdown' &&
    (INSTRUCTION_FILE_NAMES.has(lowerName) || /\.(?:md|mdx)$/i.test(fileName));

  return {
    isClientComponent,
    isServerActionModule: SERVER_DIRECTIVE_REGEX.test(head),
    isAppRouterRoute: APP_ROUTER_ROUTE_REGEX.test(relativePath),
    isPagesApiRoute: PAGES_API_REGEX.test(relativePath),
    isServerFrameworkFile: SERVER_FRAMEWORK_REGEX.test(content),
    isStaticAssetDir: STATIC_ASSET_REGEX.test(relativePath),
    isClientPath: CLIENT_PATH_REGEX.test(relativePath) || CLIENT_DIRECTIVE_REGEX.test(head),
    isMigration:
      (language === 'sql' || language === 'prisma' || extension === 'sql') &&
      (MIGRATION_PATH_REGEX.test(relativePath) || /^\d{8,17}[_-].*\.sql$/i.test(fileName) || /\bmigration\b/i.test(relativePath) || /CREATE\s+TABLE/i.test(content)),
    isEnvFile: DOTENV_NAMES.test(fileName),
    isTestFile: TEST_PATH_REGEX.test(relativePath),
    isDocumentation: !isMarkdownInstruction && DOC_REGEX.test(relativePath) && language === 'markdown',
    isLockfile: LOCKFILE_REGEX.test(relativePath),
    isGenerated: GENERATED_REGEX.test(relativePath),
    isAgentInstructionFile:
      INSTRUCTION_FILE_NAMES.has(lowerName) ||
      /(?:^|\/)\.(?:claude|cursor|windsurf|cline|roo|codex|aider|continue|github)\/[^/]*\.(?:md|mdc|json|ya?ml|txt)$/i.test(relativePath) ||
      /(?:^|\/)SKILL\.md$/i.test(relativePath),
    isMcpConfig: MCP_CONFIG_NAMES.test(fileName) || /"mcpServers"\s*:/.test(content),
    isCiWorkflow: CI_WORKFLOW_REGEX.test(relativePath),
    mentionsAuth: AUTH_VERIFICATION_REGEX.test(content),
    mentionsMutation: MUTATION_REGEX.test(content) || SQL_MUTATION_REGEX.test(content),
    mentionsLlm: LLM_REGEX.test(content),
  };
}

const MAX_FLAG_HEAD = 200_000;

/** Build the immutable per-file context handed to every rule. */
export function createFileContext(
  absolutePath: string,
  rootDir: string,
  content: string,
  project: ProjectContext,
): FileContext {
  const relativePath = posix(path.relative(rootDir, absolutePath)) || posix(path.basename(absolutePath));
  const fileName = path.basename(relativePath);
  const extension = extensionOf(fileName);
  const language = detectLanguage(relativePath, fileName, extension);
  const flags = computeFlags(relativePath, fileName, extension, language, content.slice(0, MAX_FLAG_HEAD));
  const code = maskComments(content, language);
  const lines = splitLines(content);
  const index = new LineIndex(content);

  return {
    absolutePath,
    relativePath,
    fileName,
    extension,
    language,
    content,
    lowerContent: content.toLowerCase(),
    code,
    lowerCode: code.toLowerCase(),
    lines,
    bytes: Buffer.byteLength(content, 'utf8'),
    flags,
    project,
    locate: (offset: number) => index.locate(offset),
    lineText: (line: number) => lines[line - 1] ?? '',
  };
}

/** Dependency names that imply a project-wide security capability. */
const AUTH_DEPENDENCY_REGEX =
  /^(?:next-auth|@auth\/.*|@clerk\/.*|lucia|@lucia-auth\/.*|passport|passport-.*|@supabase\/ssr|firebase-admin|express-jwt|jose|@oslo\/.*|iron-session|@kinde\/.*|@workos\/.*|auth0|@auth0\/.*|@casl\/ability|better-auth|@better-auth\/.*)$/;
const SESSION_DEPENDENCY_REGEX =
  /^(?:express-session|cookie-session|next-auth|@auth\/.*|iron-session|@clerk\/.*|lucia|cookie|cookies|@hono\/.*|session|connect-redis|@lucia-auth\/.*)$/;
const RATE_LIMIT_DEPENDENCY_REGEX =
  /^(?:express-rate-limit|@upstash\/ratelimit|rate-limiter-flexible|ratelimit|ioredis|redis|@hono\/rate-limiter|slowdown|fastify-rate-limit|@fastify\/rate-limit|bottleneck)$/;
const CSRF_DEPENDENCY_REGEX = /^(?:csurf|@dr\.pompo\/.*csrf.*|csrf|csrf-csrf|tiny-csrf|@dr.pompo.*)$/;
const SANITIZER_DEPENDENCY_REGEX =
  /^(?:dompurify|isomorphic-dompurify|sanitize-html|xss|he|marked|rehype-sanitize|@braintree\/sanitize-url|validator|zod|yup|ajv|joi|superstruct|valibot|arktype|effect|io-ts)$/;
const AI_DEPENDENCY_REGEX =
  /^(?:ai|openai|@openai\/.*|@anthropic-ai\/.*|@google\/generative-ai|@google-cloud\/vertexai|langchain|@langchain\/.*|llamaindex|@xenova\/.*|@mistralai\/.*|cohere-ai|groq|ollama|@aws-sdk\/client-bedrock-runtime|@aws-sdk\/client-bedrock|replicate|together-ai|@modelcontextprotocol\/sdk|@huggingface\/.*)$/;
const SUPABASE_DEPENDENCY_REGEX = /^(?:@supabase\/supabase-js|@supabase\/ssr|@supabase\/auth-helpers-nextjs|supabase)$/;
const STRIPE_DEPENDENCY_REGEX = /^(?:stripe|@stripe\/.*|next-stripe|micro)$/;
const PRISMA_DEPENDENCY_REGEX = /^(?:@prisma\/client|prisma|drizzle-orm|@drizzle-team\/.*|typeorm|sequelize|mongoose|knex|kysely|objection)$/;
const EXPRESS_DEPENDENCY_REGEX = /^(?:express|koa|connect|restana|polka|@nestjs\/platform-express)$/;
const FASTIFY_DEPENDENCY_REGEX = /^(?:fastify|@fastify\/.*|@nestjs\/platform-fastify|elysia)$/;

const MANIFEST_FILES = [
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'Pipfile',
  'Cargo.toml',
  'go.mod',
  'Gemfile',
  'composer.json',
  'pom.xml',
  'build.gradle',
];

const FRAMEWORK_MARKERS: ReadonlyArray<{ file: RegExp; framework: string }> = [
  { file: /^next\.config\.[cm]?[jt]s$/, framework: 'next' },
  { file: /^nuxt\.config\.[cm]?[jt]s$/, framework: 'nuxt' },
  { file: /^vite\.config\.[cm]?[jt]s$/, framework: 'vite' },
  { file: /^svelte\.config\.[cm]?[jt]s$/, framework: 'sveltekit' },
  { file: /^angular\.json$/, framework: 'angular' },
  { file: /^astro\.config\.[cm]?[jt]s$/, framework: 'astro' },
  { file: /^remix\.config\.[cm]?[jt]s$/, framework: 'remix' },
  { file: /^gatsby-config\.[cm]?[jt]s$/, framework: 'gatsby' },
  { file: /^config\.toml$/, framework: 'supabase' },
  { file: /^schema\.prisma$/, framework: 'prisma' },
  { file: /^drizzle\.config\.[cm]?[jt]s$/, framework: 'drizzle' },
  { file: /^docker-compose\.ya?ml$/, framework: 'docker' },
  { file: /^Dockerfile$/, framework: 'docker' },
  { file: /^vercel\.json$/, framework: 'vercel' },
  { file: /^tailwind\.config\.[cm]?[jt]s$/, framework: 'tailwind' },
];

/** Strip JSON comments/trailing commas so `jsonc` manifests still parse. */
export function tolerantJsonParse(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    const stripped = text
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:"'\\])\/\/.*$/gm, '$1')
      .replace(/,(\s*[}\]])/g, '$1');
    try {
      return JSON.parse(stripped) as unknown;
    } catch {
      return null;
    }
  }
}

async function readTextIfExists(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return null;
  }
}

const addUnique = (target: string[], values: Iterable<string>): void => {
  for (const value of values) {
    const normalised = value.trim();
    if (normalised && !target.includes(normalised)) target.push(normalised);
  }
};

/** Extract dependency-ish names from non-npm manifests. */
function parseGenericManifest(fileName: string, text: string): string[] {
  const names: string[] = [];
  if (fileName === 'requirements.txt') {
    for (const line of text.split(/\r?\n/)) {
      const match = /^\s*([A-Za-z0-9_.\-]+)\s*(?:[=<>!~]|$)/.exec(line);
      if (match && match[1] && !line.trim().startsWith('#')) names.push(match[1]);
    }
    return names;
  }
  if (fileName === 'pyproject.toml' || fileName === 'Cargo.toml') {
    for (const match of text.matchAll(/["']?([A-Za-z0-9_.\-]+)["']?\s*(?:=|\^|~|>=|==)\s*["']?[\d^~.*]+/g)) {
      if (match[1]) names.push(match[1]);
    }
    return names;
  }
  if (fileName === 'go.mod') {
    for (const match of text.matchAll(/^\s*([\w./-]+)\s+v[\d.]/gm)) if (match[1]) names.push(match[1]);
    return names;
  }
  if (fileName === 'Gemfile') {
    for (const match of text.matchAll(/^\s*gem\s+['"]([^'"]+)['"]/gm)) if (match[1]) names.push(match[1]);
    return names;
  }
  if (fileName === 'composer.json' || fileName === 'package.json') {
    const parsed = tolerantJsonParse(text) as { dependencies?: Record<string, unknown>; require?: Record<string, unknown>; 'devDependencies'?: Record<string, unknown>; 'require-dev'?: Record<string, unknown> } | null;
    if (parsed) {
      addUnique(names, Object.keys(parsed.dependencies ?? {}));
      addUnique(names, Object.keys(parsed['devDependencies'] ?? {}));
      addUnique(names, Object.keys(parsed.require ?? {}));
      addUnique(names, Object.keys(parsed['require-dev'] ?? {}));
    }
    return names;
  }
  if (fileName === 'pom.xml' || fileName === 'build.gradle') {
    for (const match of text.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) if (match[1]) names.push(match[1]);
    for (const match of text.matchAll(/['"]([\w.-]+:[\w.-]+):[\d.]/g)) if (match[1]) names.push(match[1].split(':').pop() ?? match[1]);
    return names;
  }
  return names;
}

export interface DetectProjectOptions {
  /** Directories (relative) that should not be inspected for manifests. */
  skip?: (relativePath: string, isDirectory: boolean) => boolean;
  /** How deep to look for workspace manifests. Default 8. */
  maxDepth?: number;
  /** Read the git index to learn which paths are actually tracked. Default true. */
  readGitIndex?: boolean;
  /** Maximum number of SQL files parsed for the RLS index. Default 400. */
  maxSqlFiles?: number;
  /** Maximum bytes read per SQL file. Default 512 KiB. */
  maxSqlBytes?: number;
}

const ROOT_MIDDLEWARE_REGEX = /^(?:src\/)?middleware\.[cm]?[jt]sx?$/i;

/** Extract the `matcher` entries declared by a Next.js middleware module. */
export function parseMiddlewareMatchers(source: string): string[] {
  const matchers: string[] = [];
  const block = /matcher\s*:\s*(\[[^\]]*\]|['"`][^'"`]+['"`])/.exec(source);
  if (!block || !block[1]) return matchers;
  const raw = block[1];
  for (const match of raw.matchAll(/['"`]([^'"`]+)['"`]/g)) {
    if (match[1]) matchers.push(match[1]);
  }
  return matchers;
}

/**
 * Parse every `CREATE TABLE` / `ALTER TABLE ... ROW LEVEL SECURITY` /
 * `CREATE POLICY` / `GRANT` statement in a SQL file into table records.
 * Deliberately tolerant: SQL dialects differ, and a partial read is still
 * better than a missed "RLS is enabled three migrations later".
 */
export function parseSqlTables(relativePath: string, source: string): SqlTableInfo[] {
  const tables = new Map<string, SqlTableInfo>();
  const code = maskSqlComments(source);

  const ensure = (rawName: string, line: number): SqlTableInfo => {
    const table = rawName.replace(/^["'`\[]|["'`\]]$/g, '').trim();
    const name = table.includes('.') ? (table.split('.').pop() ?? table) : table;
    const existing = tables.get(table.toLowerCase());
    if (existing) return existing;
    const created: SqlTableInfo = {
      table,
      name,
      file: relativePath,
      line,
      rlsEnabled: false,
      rlsForced: false,
      policies: [],
      grantedToPublic: false,
      internal: /^(?:auth|extensions|pg_catalog|information_schema|storage|graphql|_timescaledb|cron|vault|supabase_functions)\./i.test(table) || table.startsWith('_'),
    };
    tables.set(table.toLowerCase(), created);
    return created;
  };

  const lineOf = (offset: number): number => {
    let line = 1;
    for (let i = 0; i < offset && i < code.length; i += 1) {
      if (code[i] === '\n') line += 1;
    }
    return line;
  };

  for (const match of code.matchAll(/\bCREATE\s+(?:GLOBAL\s+|LOCAL\s+)?(TEMPORARY\s+|TEMP\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"[\w.${}\-]+(?:\s*\.\s*[`"[\w.${}\-]+)?)/gi)) {
    const info = ensure(match[2] ?? '', lineOf(match.index));
    if (match[1]) info.internal = true;
  }
  for (const match of code.matchAll(/\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([`"[\w.${}\-]+(?:\s*\.\s*[`"[\w.${}\-]+)?)\s+(ENABLE|FORCE|DISABLE|NO\s+FORCE)\s+ROW\s+LEVEL\s+SECURITY/gi)) {
    const info = ensure(match[1] ?? '', lineOf(match.index));
    const verb = (match[2] ?? '').toUpperCase();
    if (verb === 'ENABLE' || verb === 'FORCE') info.rlsEnabled = true;
    if (verb === 'FORCE') info.rlsForced = true;
    if (verb === 'DISABLE') {
      info.rlsEnabled = false;
      info.rlsForced = false;
    }
  }
  for (const match of code.matchAll(/\bCREATE\s+POLICY\s+([`"[\w.$\-]+(?:\s[\w$\-]+)*?)\s+ON\s+([`"[\w.${}\-]+(?:\s*\.\s*[`"[\w.${}\-]+)?)/gi)) {
    const info = ensure(match[2] ?? '', lineOf(match.index));
    const policy = (match[1] ?? '').trim();
    if (policy && !info.policies.includes(policy)) info.policies.push(policy);
  }
  for (const match of code.matchAll(/\bGRANT\s+(?:[\w,\s]+?)\s+ON\s+(?:TABLE\s+|ALL\s+TABLES\s+IN\s+SCHEMA\s+)?([`"[\w.$*,\s\-]+?)\s+TO\s+([^;]+);/gi)) {
    const grantees = (match[2] ?? '').toLowerCase();
    if (!/\b(?:anon|authenticated|public|anonymous|web_anon|app_user)\b/.test(grantees)) continue;
    const targets = (match[1] ?? '').split(',');
    for (const target of targets) {
      const name = target.trim().replace(/^["'`\[]|["'`\]]$/g, '');
      if (!name) continue;
      if (name === '*') {
        for (const info of tables.values()) info.grantedToPublic = true;
        continue;
      }
      ensure(name, lineOf(match.index)).grantedToPublic = true;
    }
  }

  return [...tables.values()];
}

/** Merge per-file table records into the project-wide index. */
export function mergeSqlTables(target: SqlTableInfo[], incoming: SqlTableInfo[]): void {
  for (const info of incoming) {
    const key = info.table.toLowerCase();
    const existing = target.find((entry) => entry.table.toLowerCase() === key);
    if (!existing) {
      target.push({ ...info, policies: [...info.policies] });
      continue;
    }
    existing.rlsEnabled = existing.rlsEnabled || info.rlsEnabled;
    existing.rlsForced = existing.rlsForced || info.rlsForced;
    existing.grantedToPublic = existing.grantedToPublic || info.grantedToPublic;
    for (const policy of info.policies) {
      if (!existing.policies.includes(policy)) existing.policies.push(policy);
    }
    if (existing.internal && !info.internal) {
      existing.internal = false;
      existing.file = info.file;
      existing.line = info.line;
    }
  }
}

/** Paths tracked by git, read from the index in a single subprocess call. */
export function readGitTrackedPaths(rootDir: string): string[] {
  try {
    // `git ls-files` reports paths relative to the *repository* root, which is
    // not necessarily the scan root (a monorepo package, or a fixture directory
    // inside a larger repo). Resolve the prefix so callers can compare directly.
    const prefix = execFileSync('git', ['rev-parse', '--show-prefix'], {
      cwd: rootDir,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 15_000,
    })
      .trim()
      .split(path.sep)
      .join('/');
    const stdout = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: rootDir,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 15_000,
    });
    const entries = stdout.split('\0').filter(Boolean).map((entry) => entry.split(path.sep).join('/'));
    if (!prefix) return entries;
    return entries
      .filter((entry) => entry.startsWith(prefix))
      .map((entry) => entry.slice(prefix.length));
  } catch {
    return [];
  }
}

/**
 * Cheap project fingerprint: manifests + marker files + SQL RLS posture.
 * Runs before the scan so rules can ask "does this project even have a CSRF
 * library installed?" or "is RLS enabled for this table in a later migration?"
 * without a second pass over the source.
 */
export async function detectProject(rootDir: string, options: DetectProjectOptions = {}): Promise<ProjectContext> {
  const dependencies: string[] = [];
  const frameworks: string[] = [];
  const migrationFiles: string[] = [];
  const sqlTables: SqlTableInfo[] = [];
  const maxDepth = options.maxDepth ?? 8;
  const maxSqlFiles = options.maxSqlFiles ?? 400;
  const maxSqlBytes = options.maxSqlBytes ?? 512 * 1024;
  const skip = options.skip ?? (() => false);
  let sqlFilesRead = 0;
  let hasGlobalAuthMiddleware = false;
  const authMiddlewareMatchers: string[] = [];

  const walk = async (dir: string, depth: number): Promise<void> => {
    const rel = posix(path.relative(rootDir, dir));
    if (depth > maxDepth) return;
    if (rel && skip(rel, true)) return;
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const entryRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (skip(entryRel, true)) continue;
        await walk(path.join(dir, entry.name), depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      if (skip(entryRel, false)) continue;

      if (MANIFEST_FILES.includes(entry.name)) {
        const text = await readTextIfExists(path.join(dir, entry.name));
        if (text) addUnique(dependencies, parseGenericManifest(entry.name, text));
      }
      for (const marker of FRAMEWORK_MARKERS) {
        if (marker.file.test(entry.name) && !frameworks.includes(marker.framework)) frameworks.push(marker.framework);
      }
      if (entry.name.endsWith('.sql')) {
        if (MIGRATION_PATH_REGEX.test(entryRel)) migrationFiles.push(entryRel);
        if (sqlFilesRead < maxSqlFiles) {
          sqlFilesRead += 1;
          const text = await readTextIfExists(path.join(dir, entry.name));
          if (text) mergeSqlTables(sqlTables, parseSqlTables(entryRel, text.slice(0, maxSqlBytes)));
        }
      }
      if (ROOT_MIDDLEWARE_REGEX.test(entryRel)) {
        const text = await readTextIfExists(path.join(dir, entry.name));
        if (text && AUTH_VERIFICATION_REGEX.test(text)) {
          hasGlobalAuthMiddleware = true;
          addUnique(authMiddlewareMatchers, parseMiddlewareMatchers(text));
        }
      }
    }
  };

  await walk(rootDir, 0);

  const anyDependency = (regex: RegExp): boolean => dependencies.some((dep) => regex.test(dep));
  const trackedPaths = options.readGitIndex === false ? [] : readGitTrackedPaths(rootDir);

  return {
    rootDir,
    frameworks,
    dependencies,
    hasExpressServer: anyDependency(EXPRESS_DEPENDENCY_REGEX),
    hasFastifyServer: anyDependency(FASTIFY_DEPENDENCY_REGEX),
    hasCookieSession: anyDependency(SESSION_DEPENDENCY_REGEX),
    hasRateLimiting: anyDependency(RATE_LIMIT_DEPENDENCY_REGEX),
    hasCsrfProtection: anyDependency(CSRF_DEPENDENCY_REGEX),
    hasSanitizer: anyDependency(SANITIZER_DEPENDENCY_REGEX),
    hasAuthLibrary: anyDependency(AUTH_DEPENDENCY_REGEX),
    hasAiSdk: anyDependency(AI_DEPENDENCY_REGEX),
    hasSupabase: anyDependency(SUPABASE_DEPENDENCY_REGEX) || frameworks.includes('supabase'),
    hasStripe: anyDependency(STRIPE_DEPENDENCY_REGEX),
    hasPrisma: anyDependency(PRISMA_DEPENDENCY_REGEX),
    migrationFiles,
    sqlTables,
    hasGlobalAuthMiddleware,
    authMiddlewareMatchers,
    trackedPaths,
    gitAvailable: trackedPaths.length > 0,
  };
}
