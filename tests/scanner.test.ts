/**
 * End-to-end tests for the scanner engine, the rule catalogue, the suppressions
 * system, the scoring model and the real fixtures under `tests/fixtures/`.
 *
 * Every test writes its own project to a temp directory, so nothing here depends
 * on vibe-shield's own source tree staying clean.
 */

import { readFileSync, mkdirSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { detectProject, parseMiddlewareMatchers, parseSqlTables, tolerantJsonParse } from '../src/scanner/context';
import {
  applySuppressions,
  dedupe,
  discoverFiles,
  hasFindingsAtOrAbove,
  parseSuppressions,
  scoreFindings,
  scanProject,
} from '../src/scanner/engine';
import { ALL_RULES, getRule, SCAN_RULES, selectRules } from '../src/scanner/rules';
import { findSecrets } from '../src/secrets/patterns';
import { formatGithub, formatJson, formatSarif, formatSummary } from '../src/reporter/formatters';
import { buildPatchPrompt, writePatchPrompt } from '../src/reporter/patch-prompt-writer';
import { renderConsoleReport } from '../src/reporter/console-reporter';
import type { Finding, ScanResult } from '../src/scanner/types';
import { byRule, expectNoRule, expectRule, makeProject, scan } from './helpers';

const FIXTURES = path.join(__dirname, 'fixtures');
const VULNERABLE = path.join(FIXTURES, 'vulnerable');
const SECURE = path.join(FIXTURES, 'secure');

/* -------------------------------------------------------------------------- */
/* Catalogue                                                                  */
/* -------------------------------------------------------------------------- */

describe('rule catalogue', () => {
  it('ships at least 35 AI-specific signatures', () => {
    expect(SCAN_RULES.length).toBeGreaterThanOrEqual(35);
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(47);
  });

  it('ships every documented rule id', () => {
    const expected = [
      ...Array.from({ length: 7 }, (_, i) => `VSB-CLIENT-00${i + 1}`),
      ...Array.from({ length: 9 }, (_, i) => `VSB-AUTH-00${i + 1}`),
      ...Array.from({ length: 10 }, (_, i) => `VSB-DB-0${String(i + 1).padStart(2, '0')}`),
      ...Array.from({ length: 15 }, (_, i) => `VSB-AI-0${String(i + 1).padStart(2, '0')}`),
      ...Array.from({ length: 7 }, (_, i) => `VSB-SECRET-00${i + 1}`),
      ...Array.from({ length: 12 }, (_, i) => `VSB-AGENT-0${String(i + 1).padStart(2, '0')}`),
    ];
    const ids = new Set(ALL_RULES.map((rule) => rule.id));
    for (const id of expected) expect(ids.has(id), `missing rule ${id}`).toBe(true);
  });

  it('has unique ids and slugs', () => {
    const ids = ALL_RULES.map((rule) => rule.id);
    const slugs = ALL_RULES.map((rule) => rule.slug);
    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it('documents every rule fully: description, examples, remediation, CWE, references', () => {
    for (const rule of ALL_RULES) {
      expect(rule.description.length, `${rule.id} description`).toBeGreaterThan(40);
      expect(rule.insecureExample.length, `${rule.id} insecureExample`).toBeGreaterThan(0);
      expect(rule.secureExample.length, `${rule.id} secureExample`).toBeGreaterThan(0);
      expect(rule.remediation.length, `${rule.id} remediation`).toBeGreaterThanOrEqual(2);
      expect(rule.references.length, `${rule.id} references`).toBeGreaterThanOrEqual(1);
      expect(rule.cwe.id, `${rule.id} cwe`).toMatch(/^CWE-\d+$/);
      expect(rule.cwe.url, `${rule.id} cwe url`).toContain('cwe.mitre.org');
      expect(typeof rule.detect, `${rule.id} detect`).toBe('function');
    }
  });

  it('looks rules up by id, slug and prefix', () => {
    expect(getRule('VSB-DB-001')?.slug).toBe('table-without-rls');
    expect(getRule('vsb-db-001')?.id).toBe('VSB-DB-001');
    expect(getRule('table-without-rls')?.id).toBe('VSB-DB-001');
    expect(getRule('VSB-NOPE-999')).toBeUndefined();
    expect(selectRules(['VSB-AI']).every((rule) => rule.id.startsWith('VSB-AI-'))).toBe(true);
    expect(selectRules(['VSB-SECRET-*'])).toHaveLength(7);
    expect(selectRules([])).toHaveLength(ALL_RULES.length);
  });

  it('never contains placeholder text', () => {
    const files = [
      'src/scanner/rules/client-exposure.ts',
      'src/scanner/rules/unguarded-routes.ts',
      'src/scanner/rules/database-exposure.ts',
      'src/scanner/rules/ai-vulnerabilities.ts',
      'src/scanner/rules/secret-entropy.ts',
      'src/mcp-guard/skill-auditor.ts',
      'src/scanner/engine.ts',
      'bin/vibe-shield.ts',
    ];
    for (const file of files) {
      const source = readFileSync(path.join(__dirname, '..', file), 'utf8');
      expect(source, file).not.toMatch(/\bTODO\b/);
      expect(source, file).not.toMatch(/\bFIXME\b/);
      expect(source, file).not.toMatch(/\bXXX\b/);
      expect(source, file).not.toMatch(/not implemented/i);
      expect(source, file).not.toMatch(/coming soon/i);
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

describe('fixtures', () => {
  it('finds the full set of critical issues in the vulnerable app', async () => {
    const result = await scanProject({ rootDir: VULNERABLE, includeDocs: true, useGitIndex: false });
    expect(result.findings.length).toBeGreaterThan(20);
    expect(result.score.grade).toBe('F');
    expect(result.score.score).toBeLessThan(30);

    // Each family must be represented — this is the coverage regression test.
    for (const ruleId of [
      'VSB-CLIENT-001',
      'VSB-CLIENT-002',
      'VSB-CLIENT-003',
      'VSB-CLIENT-007',
      'VSB-AUTH-001',
      'VSB-AUTH-003',
      'VSB-AUTH-007',
      'VSB-DB-001',
      'VSB-DB-002',
      'VSB-DB-003',
      'VSB-DB-004',
      'VSB-DB-006',
      'VSB-DB-007',
      'VSB-AI-001',
      'VSB-AI-004',
      'VSB-AI-008',
      'VSB-AI-014',
      'VSB-SECRET-006',
      'VSB-SECRET-007',
    ]) {
      expectRule(result, ruleId);
    }
  });

  it('reports zero findings for the secure app', async () => {
    const result = await scanProject({ rootDir: SECURE, useGitIndex: false });
    if (result.findings.length) {
      const detail = result.findings.map((f) => `${f.ruleId} ${f.filePath}:${f.line} — ${f.message}`).join('\n');
      throw new Error(`secure fixture produced findings:\n${detail}`);
    }
    expect(result.findings).toHaveLength(0);
    expect(result.score.grade).toBe('A+');
    expect(result.score.score).toBe(100);
  });
});

/* -------------------------------------------------------------------------- */
/* Engine mechanics                                                           */
/* -------------------------------------------------------------------------- */

describe('engine', () => {
  it('prunes node_modules, build output and lockfiles', async () => {
    const project = makeProject({
      'src/app.ts': 'const x = 1;\n',
      'node_modules/pkg/index.js': 'const password = "supersecretvalue123";\n',
      'dist/bundle.js': 'const password = "supersecretvalue123";\n',
      'package-lock.json': '{"lockfileVersion":3}\n',
    });
    try {
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      expect(result.scannedPaths).toContain('src/app.ts');
      expect(result.scannedPaths.some((entry) => entry.includes('node_modules'))).toBe(false);
      expect(result.scannedPaths.some((entry) => entry.includes('dist/'))).toBe(false);
      expect(result.scannedPaths).not.toContain('package-lock.json');
    } finally {
      project.cleanup();
    }
  });

  it('honours .vibe-shieldignore and .gitignore', async () => {
    const project = makeProject({
      '.vibe-shieldignore': 'legacy/**\n',
      '.gitignore': 'generated/**\n',
      'legacy/bad.ts': 'export async function POST() {}\n',
      'generated/bad.ts': 'export async function POST() {}\n',
      'app/api/ok/route.ts': 'export async function GET() { return new Response("ok"); }\n',
    });
    try {
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      expect(result.scannedPaths.some((entry) => entry.startsWith('legacy/'))).toBe(false);
      expect(result.scannedPaths.some((entry) => entry.startsWith('generated/'))).toBe(false);
      expect(result.scannedPaths).toContain('app/api/ok/route.ts');
    } finally {
      project.cleanup();
    }
  });

  it('applies --ignore patterns', async () => {
    const project = makeProject({ 'skip/bad.ts': "const k = 'sk_live_7Qm3Xk9Rb2Vt6Yw4Zp8Nd5Hj1Lc0Sg';\n" });
    try {
      const result = await scanProject({ rootDir: project.root, ignorePatterns: ['skip/**'], useGitIndex: false });
      expect(result.scannedPaths).not.toContain('skip/bad.ts');
    } finally {
      project.cleanup();
    }
  });

  it('skips binary files and oversized files', async () => {
    const project = makeProject({ 'ok.ts': 'export const ok = true;\n' });
    try {
      writeFileSync(path.join(project.root, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
      writeFileSync(path.join(project.root, 'huge.ts'), 'x'.repeat(2_000_000));
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      expect(result.scannedPaths).toContain('ok.ts');
      expect(result.scannedPaths).not.toContain('image.png');
      expect(result.scannedPaths).not.toContain('huge.ts');
    } finally {
      project.cleanup();
    }
  });

  it('scans an explicitly named test path', async () => {
    const project = makeProject({
      'tests/bad.ts': 'const key = "sk_live_7Qm3Xk9Rb2Vt6Yw4Zp8Nd5Hj1Lc0Sg";\n',
    });
    try {
      const implicit = await scanProject({ rootDir: project.root, useGitIndex: false });
      expect(implicit.scannedPaths).toHaveLength(0);
      const explicit = await scanProject({ rootDir: project.root, paths: ['tests'], useGitIndex: false });
      expect(explicit.scannedPaths).toContain('tests/bad.ts');
    } finally {
      project.cleanup();
    }
  });

  it('reports a notice when nothing matched', async () => {
    const result = await scan({});
    expect(result.findings).toHaveLength(0);
    expect(result.notices.join(' ')).toMatch(/no scannable files/i);
  });

  it('deduplicates identical findings', async () => {
    const result = await scan({
      'components/x.tsx': `'use client';\nconst a = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\nconst b = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n`,
    });
    const hits = byRule(result, 'VSB-CLIENT-001');
    expect(hits).toHaveLength(2);
    expect(new Set(hits.map((hit) => hit.line)).size).toBe(2);
  });

  it('records exact line and column for every finding', async () => {
    const result = await scan({
      'app/api/users/route.ts': [
        'export async function DELETE(req: Request) {',
        '  const { id } = await req.json();',
        '  await db.delete(id);',
        '}',
      ].join('\n'),
    });
    const finding = expectRule(result, 'VSB-AUTH-001')[0];
    expect(finding?.line).toBe(1);
    expect(finding?.column).toBeGreaterThan(0);
    expect(finding?.filePath).toBe('app/api/users/route.ts');
    expect(finding?.snippet).toContain('DELETE');
  });

  it('sorts findings by severity then file then line', async () => {
    const result = await scanProject({ rootDir: VULNERABLE, useGitIndex: false });
    const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const;
    for (let i = 1; i < result.findings.length; i += 1) {
      const previous = result.findings[i - 1] as Finding;
      const current = result.findings[i] as Finding;
      expect(rank[previous.severity]).toBeGreaterThanOrEqual(rank[current.severity]);
    }
  });

  it('exposes discoverFiles with skip statistics', async () => {
    const project = makeProject({
      'a.ts': 'export {};\n',
      'node_modules/x/y.js': 'module.exports = 1;\n',
      'tests/a.test.ts': 'export {};\n',
    });
    try {
      const discovered = await discoverFiles(project.root, { rootDir: project.root });
      expect(discovered.files.map((file) => file.relativePath)).toEqual(['a.ts']);
      expect(discovered.pruned).toBeGreaterThan(0);
      expect(discovered.skipped).toBeGreaterThan(0);
    } finally {
      project.cleanup();
    }
  });

  it('never throws on malformed or hostile input', async () => {
    const project = makeProject({
      'weird.ts': 'const x = `${'.repeat(400) + '\n',
      'binaryish.ts': 'const a = 1;\u0000\n',
      'empty.ts': '',
    });
    try {
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      expect(result.findings).toBeInstanceOf(Array);
    } finally {
      project.cleanup();
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Suppressions                                                               */
/* -------------------------------------------------------------------------- */

describe('suppressions', () => {
  const vuln = 'app/api/users/route.ts';
  const body = ['export async function DELETE(req: Request) {', '  await db.delete(id);', '}', ''].join('\n');

  it('supports disable-next-line with a rule id and reason', async () => {
    const result = await scan({
      [vuln]: `// vibe-shield-disable-next-line VSB-AUTH-001 -- internal cron endpoint\n${body}`,
    });
    expectNoRule(result, 'VSB-AUTH-001');
    expect(result.suppressedCount).toBe(1);
    expect(result.notices.join(' ')).toMatch(/suppressed/i);
  });

  it('supports disable-line', async () => {
    const result = await scan({
      [vuln]: `export async function DELETE(req: Request) { // vibe-shield-disable-line VSB-AUTH-001\n  await db.delete(id);\n}`,
    });
    expectNoRule(result, 'VSB-AUTH-001');
  });

  it('supports disable-file', async () => {
    const result = await scan({
      [vuln]: `// vibe-shield-disable-file VSB-AUTH-001 -- generated edge endpoint\n${body}`,
    });
    expectNoRule(result, 'VSB-AUTH-001');
  });

  it('supports a disable/enable range', async () => {
    const result = await scan({
      [vuln]: [
        '// vibe-shield-disable VSB-AUTH-001',
        body,
        '// vibe-shield-enable',
        'export async function POST(req: Request) {',
        '  await db.create(id);',
        '}',
      ].join('\n'),
    });
    // The DELETE inside the disable..enable range is suppressed; the POST after
    // the `enable` directive is not.
    const hits = byRule(result, 'VSB-AUTH-001');
    expect(hits).toHaveLength(1);
    expect(hits[0]?.matched).toContain('POST');
  });

  it('does not suppress a different rule', async () => {
    const result = await scan({
      [vuln]: `// vibe-shield-disable-next-line VSB-DB-001\n${body}`,
    });
    expectRule(result, 'VSB-AUTH-001');
  });

  it('parses directives without reason text', () => {
    const parsed = parseSuppressions(['// vibe-shield-disable-next-line VSB-AI-001,VSB-DB-002', 'code']);
    expect(parsed.byLine.get(2)?.ruleIds).toEqual(['VSB-AI-001', 'VSB-DB-002']);
  });

  it('applySuppressions counts what it removed', () => {
    const finding = (ruleId: string, line: number): Finding => ({
      ruleId,
      slug: 'x',
      title: 'x',
      category: 'ai-vulnerabilities',
      severity: 'high',
      confidence: 'high',
      cwe: { id: 'CWE-1', name: 'x', url: '' },
      filePath: 'a.ts',
      absolutePath: '/a.ts',
      line,
      column: 1,
      snippet: '',
      matched: '',
      message: '',
      remediation: [],
      insecureExample: '',
      secureExample: '',
      references: [],
    });
    const parsed = parseSuppressions(['// vibe-shield-disable-line VSB-AI-001', '']);
    const outcome = applySuppressions([finding('VSB-AI-001', 1), finding('VSB-AI-002', 1)], parsed);
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.suppressed).toBe(1);
  });
});

/* -------------------------------------------------------------------------- */
/* Scoring                                                                    */
/* -------------------------------------------------------------------------- */

describe('scoring', () => {
  const finding = (severity: Finding['severity'], ruleId = 'VSB-AI-001'): Finding => ({
    ruleId,
    slug: 'x',
    title: 'x',
    category: 'ai-vulnerabilities',
    severity,
    confidence: 'high',
    cwe: { id: 'CWE-1', name: 'x', url: '' },
    filePath: 'a.ts',
    absolutePath: '/a.ts',
    line: 1,
    column: 1,
    snippet: '',
    matched: '',
    message: '',
    remediation: [],
    insecureExample: '',
    secureExample: '',
    references: [],
  });

  it('gives a clean project A+', () => {
    const score = scoreFindings([]);
    expect(score.score).toBe(100);
    expect(score.grade).toBe('A+');
  });

  it('fails the build on a single critical finding', () => {
    const score = scoreFindings([finding('critical')]);
    expect(score.grade).toBe('F');
    expect(score.ceiling).toEqual({ severity: 'critical', limit: 29 });
  });

  it('caps the grade on a single high finding', () => {
    expect(scoreFindings([finding('high')]).grade).toBe('C');
  });

  it('caps the grade on a single medium finding', () => {
    expect(scoreFindings([finding('medium')]).grade).toBe('B');
  });

  it('lets informational findings keep an A grade', () => {
    const score = scoreFindings([finding('info')]);
    expect(score.score).toBeGreaterThan(95);
    expect(['A+', 'A']).toContain(score.grade);
  });

  it('clamps at zero and never goes negative', () => {
    const findings = Array.from({ length: 40 }, () => finding('critical'));
    expect(scoreFindings(findings).score).toBe(0);
  });

  it('counts severities', () => {
    const counts = scoreFindings([finding('critical'), finding('high'), finding('high'), finding('info')]).counts;
    expect(counts).toMatchObject({ critical: 1, high: 2, medium: 0, low: 0, info: 1 });
  });

  it('hasFindingsAtOrAbove respects the threshold', async () => {
    const result = await scan({
      'app/api/x/route.ts': 'export async function POST() { await db.create({}); }\n',
    });
    expect(hasFindingsAtOrAbove(result, 'critical')).toBe(true);
    expect(hasFindingsAtOrAbove(result, 'info')).toBe(true);
  });
});

/* -------------------------------------------------------------------------- */
/* Secrets                                                                    */
/* -------------------------------------------------------------------------- */

describe('secret detection', () => {
  it('finds vendor-shaped keys and redacts them', () => {
    const matches = findSecrets('const k = "sk-proj-9xKq2Wm7Rt4Yb6Nc8Vd3Zf5Hg1Jl0Pz";');
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]?.patternId).toMatch(/^openai/);
    expect(matches[0]?.display).not.toContain('9xKq2Wm7Rt4Yb6Nc8Vd3Zf5Hg1Jl0Pz');
    expect(matches[0]?.display).toMatch(/•+/);
  });

  it('detects private key headers (raw pattern bypasses the placeholder gate)', () => {
    const matches = findSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n');
    expect(matches.some((match) => match.family === 'private-key')).toBe(true);
  });

  it('ignores placeholders', () => {
    for (const value of [
      'sk_live_xxxxxxxxxxxxxxxxxxxx',
      'sk-proj-your-key-here',
      'AKIAIOSFODNN7EXAMPLE',
      'ghp_placeholder_placeholder',
      'super-secret-value-that-is-fake',
    ]) {
      expect(findSecrets(`const key = "${value}";`), value).toHaveLength(0);
    }
  });

  it('redacts every value it reports', () => {
    const matches = findSecrets('STRIPE=sk_live_7Qm3Xk9Rb2Vt6Yw4Zp8Nd5Hj1Lc0Sg');
    for (const match of matches) {
      expect(match.display.length).toBeLessThan(match.value.length + 1);
    }
  });

  it('reports a committed .env file as critical when git tracks it', async () => {
    const project = makeProject({
      '.env': 'OPENAI_API_KEY=sk-proj-9xKq2Wm7Rt4Yb6Nc8Vd3Zf5Hg1Jl0Pz\n',
    });
    try {
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      const hits = byRule(result, 'VSB-SECRET-007');
      expect(hits.length).toBeGreaterThan(0);
      expect(hits[0]?.severity).toBe('critical');
    } finally {
      project.cleanup();
    }
  });

  it('flags a hardcoded privileged JWT', async () => {
    const payload = Buffer.from(JSON.stringify({ role: 'service_role', iss: 'supabase' })).toString('base64url');
    const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.7Qm3Xk9Rb2Vt6Yw4Zp8Nd5HjLc0Sg2Tf`;
    const result = await scan({ 'lib/supa.ts': `export const serviceKey = '${token}';\n` });
    const hits = byRule(result, 'VSB-SECRET-004');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.severity).toBe('critical');
  });
});

/* -------------------------------------------------------------------------- */
/* Project detection                                                          */
/* -------------------------------------------------------------------------- */

describe('project detection', () => {
  it('builds a cross-file RLS index', () => {
    const tables = parseSqlTables(
      'migrations/003_rls.sql',
      'alter table public.accounts enable row level security;\ncreate policy "own" on public.accounts using (auth.uid() = user_id);\n',
    );
    expect(tables[0]?.rlsEnabled).toBe(true);
    expect(tables[0]?.policies).toEqual(['"own"']);
  });

  it('ignores internal schemas and temp tables', () => {
    const tables = parseSqlTables('m.sql', 'create table auth.users (id uuid);\ncreate temp table scratch (id int);\n');
    expect(tables.every((table) => table.internal)).toBe(true);
  });

  it('parses Next.js middleware matchers', () => {
    const source = `export const config = { matcher: ['/dashboard/:path*', '/admin/:path*'] };`;
    expect(parseMiddlewareMatchers(source)).toEqual(['/dashboard/:path*', '/admin/:path*']);
  });

  it('detects the global auth middleware and suppresses route findings', async () => {
    const project = makeProject({
      'middleware.ts': [
        "import { auth } from './lib/auth';",
        'export async function middleware(req: Request) {',
        '  const session = await getServerSession(req);',
        '  if (!session) return new Response("Unauthorized", { status: 401 });',
        '}',
        'export const config = { matcher: [] };',
      ].join('\n'),
      'app/api/users/route.ts': 'export async function DELETE(req: Request) { await db.delete(1); }\n',
    });
    try {
      const context = await detectProject(project.root, { readGitIndex: false });
      expect(context.hasGlobalAuthMiddleware).toBe(true);
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      expectNoRule(result, 'VSB-AUTH-001');
    } finally {
      project.cleanup();
    }
  });

  it('parses jsonc manifests tolerantly', () => {
    const parsed = tolerantJsonParse('{ /* c */ "a": 1, "b": [1,2,], }') as { a: number; b: number[] };
    expect(parsed.a).toBe(1);
    expect(parsed.b).toEqual([1, 2]);
    expect(tolerantJsonParse('not json')).toBeNull();
  });

  it('reads project dependencies and framework flags', async () => {
    const project = makeProject({
      'package.json': JSON.stringify({
        dependencies: { next: '14.0.0', '@supabase/supabase-js': '2.0.0', stripe: '14.0.0', openai: '4.0.0' },
      }),
      'next.config.js': 'module.exports = {};\n',
      'supabase/config.toml': 'project_id = "x"\n',
    });
    try {
      const context = await detectProject(project.root, { readGitIndex: false });
      expect(context.hasSupabase).toBe(true);
      expect(context.hasStripe).toBe(true);
      expect(context.hasAiSdk).toBe(true);
      expect(context.frameworks).toContain('next');
      expect(context.frameworks).toContain('supabase');
    } finally {
      project.cleanup();
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Reporters                                                                  */
/* -------------------------------------------------------------------------- */

describe('reporters', () => {
  let cached: ScanResult | null = null;
  const vulnerable = async (): Promise<ScanResult> => {
    cached ??= await scanProject({ rootDir: VULNERABLE, includeDocs: true, useGitIndex: false });
    return cached;
  };

  it('renders a scorecard with grade, citations and next steps', async () => {
    const result = await vulnerable();
    const lines = renderConsoleReport(result, { width: 120 });
    const text = lines.join('\n');
    expect(text).toContain('GRADE F');
    expect(text).toMatch(/\d+ critical/);
    expect(text).toContain('app/api/users/route.ts');
    expect(text).toContain('VSB-AUTH-001');
    expect(text).toContain('--fix-prompt');
  });

  it('renders a clean A+ scorecard', async () => {
    const result = await scanProject({ rootDir: SECURE, useGitIndex: false });
    const text = renderConsoleReport(result).join('\n');
    expect(text).toContain('A+');
    expect(text).toContain('Nothing to fix');
  });

  it('emits valid JSON with schemaVersion', async () => {
    const result = await vulnerable();
    const parsed = JSON.parse(formatJson(result)) as { schemaVersion: number; findings: unknown[]; score: { grade: string } };
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.findings.length).toBeGreaterThan(10);
    expect(parsed.score.grade).toBe('F');
  });

  it('emits valid SARIF 2.1.0', async () => {
    const result = await vulnerable();
    const sarif = JSON.parse(formatSarif(result)) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string; rules: Array<{ id: string; properties: { 'security-severity': string } }> } };
        results: Array<{ ruleId: string; level: string; locations: Array<{ physicalLocation: { region: { startLine: number } } }> }>;
      }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('vibe-shield');
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(10);
    for (const rule of sarif.runs[0]?.tool.driver.rules ?? []) {
      expect(Number(rule.properties['security-severity'])).toBeGreaterThan(0);
    }
    for (const result_ of sarif.runs[0]?.results ?? []) {
      expect(['error', 'warning', 'note']).toContain(result_.level);
      expect(result_.locations[0]?.physicalLocation.region.startLine).toBeGreaterThan(0);
    }
  });

  it('emits GitHub annotations with escaped messages', async () => {
    const result = await vulnerable();
    const text = formatGithub(result);
    expect(text).toMatch(/^::error file=/m);
    expect(text).toContain('title=vibe-shield VSB-');
    expect(text).not.toMatch(/[\r\n]{2,}/);
  });

  it('emits a compact summary', async () => {
    const result = await vulnerable();
    const summary = formatSummary(result);
    expect(summary).toContain('"grade": "F"');
    const compact = (await import('../src/reporter/formatters')).formatCompact(result);
    expect(compact.split('\n').length).toBeGreaterThan(5);
  });

  it('writes a patch prompt with severity, CWE, citations and fixes', async () => {
    const result = await vulnerable();
    const prompt = buildPatchPrompt(result);
    expect(prompt).toContain('# Security patch prompt');
    expect(prompt).toContain('## Rules of engagement');
    expect(prompt).toContain('Critical — exploitable now, fix first');
    expect(prompt).toContain('CWE-');
    expect(prompt).toMatch(/app\/api\/users\/route\.ts:\d+:\d+/);
    expect(prompt).toContain('**Required change**');
    expect(prompt).toContain('**Target shape after the fix**');
    expect(prompt).toContain('npx vibe-shield scan --fail-on high');
    expect(prompt).toContain('- [ ] Every credential');
  });

  it('respects minSeverity in the patch prompt', async () => {
    const result = await vulnerable();
    const prompt = buildPatchPrompt(result, { minSeverity: 'critical' });
    expect(prompt).not.toContain('## Medium');
    expect(prompt).toContain('Critical');
  });

  it('writes the patch prompt to disk', async () => {
    const result = await vulnerable();
    const project = makeProject({});
    try {
      const file = await writePatchPrompt(result, { outDir: project.root });
      expect(readFileSync(file, 'utf8')).toContain('Security patch prompt');
      expect(path.basename(file)).toBe('SECURITY_PATCH_PROMPT.md');
    } finally {
      project.cleanup();
    }
  });

  it('handles a zero-finding patch prompt', async () => {
    const result = await scanProject({ rootDir: SECURE, useGitIndex: false });
    expect(buildPatchPrompt(result)).toContain('## Nothing to fix');
  });
});

/* -------------------------------------------------------------------------- */
/* Cache                                                                      */
/* -------------------------------------------------------------------------- */

describe('cache', () => {
  it('reuses results and reports cache hits', async () => {
    const project = makeProject({
      'app/api/users/route.ts': 'export async function DELETE(req: Request) { await db.delete(1); }\n',
    });
    try {
      const first = await scanProject({ rootDir: project.root, cache: true, useGitIndex: false });
      expect(first.stats.cacheHits).toBe(0);
      const second = await scanProject({ rootDir: project.root, cache: true, useGitIndex: false });
      expect(second.stats.cacheHits).toBeGreaterThan(0);
      expect(second.findings.map((f) => f.ruleId)).toEqual(first.findings.map((f) => f.ruleId));
    } finally {
      project.cleanup();
    }
  });

  it('invalidates when a file changes', async () => {
    const project = makeProject({ 'app/api/users/route.ts': 'export async function GET() { return new Response("ok"); }\n' });
    try {
      const first = await scanProject({ rootDir: project.root, cache: true, useGitIndex: false });
      expect(first.findings).toHaveLength(0);
      project.write('app/api/users/route.ts', 'export async function DELETE(req: Request) { await db.delete(1); }\n');
      const second = await scanProject({ rootDir: project.root, cache: true, useGitIndex: false });
      expect(byRule(second, 'VSB-AUTH-001').length).toBeGreaterThan(0);
    } finally {
      project.cleanup();
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Performance                                                                */
/* -------------------------------------------------------------------------- */

describe('performance', () => {
  it('scans a 400-file project in well under two seconds', async () => {
    const project = makeProject({});
    try {
      for (let i = 0; i < 400; i += 1) {
        project.write(
          `src/module-${i}/handler.ts`,
          `import { auth } from '../auth';\n\nexport async function handler${i}(input: string) {\n  const session = await auth();\n  if (!session?.user) return null;\n  return { value: input.repeat(${i + 1}) };\n}\n`,
        );
      }
      const started = Date.now();
      const result = await scanProject({ rootDir: project.root, useGitIndex: false });
      const elapsed = Date.now() - started;
      expect(result.stats.filesScanned).toBe(400);
      expect(elapsed).toBeLessThan(2000);
      expect(result.stats.filesPerSecond).toBeGreaterThan(50);
    } finally {
      project.cleanup();
    }
  }, 30_000);
});

/* -------------------------------------------------------------------------- */
/* Temp dir hygiene                                                           */
/* -------------------------------------------------------------------------- */

const stray: string[] = [];
afterAll(() => {
  for (const dir of stray) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

describe('helpers', () => {
  it('makeProject cleans up after itself', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'vibe-shield-check-'));
    mkdirSync(path.join(dir, 'nested'), { recursive: true });
    writeFileSync(path.join(dir, 'nested', 'file.txt'), 'x');
    stray.push(dir);
    expect(readFileSync(path.join(dir, 'nested', 'file.txt'), 'utf8')).toBe('x');
  });

  it('dedupe keeps the first of identical findings', () => {
    const base: Finding = {
      ruleId: 'VSB-AI-001',
      slug: 'x',
      title: 'x',
      category: 'ai-vulnerabilities',
      severity: 'high',
      confidence: 'high',
      cwe: { id: 'CWE-78', name: 'x', url: '' },
      filePath: 'a.ts',
      absolutePath: '/a.ts',
      line: 1,
      column: 1,
      snippet: 'one',
      matched: 'm',
      message: '',
      remediation: [],
      insecureExample: '',
      secureExample: '',
      references: [],
    };
    const deduped = dedupe([base, { ...base, snippet: 'two' }]);
    expect(deduped).toHaveLength(1);
    expect(deduped[0]?.snippet).toBe('one');
  });
});
