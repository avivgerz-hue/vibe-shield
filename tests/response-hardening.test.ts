import { describe, expect, it } from 'vitest';
import { ALL_RULES, getRule } from '../src/scanner/rules';
import { scanProject } from '../src/scanner/engine';
import { formatResult } from '../src/reporter/formatters';
import { makeContext, makeProject } from './helpers';

async function hits(id: string, file: string, text: string): Promise<number> {
  const rule = getRule(id)!;
  const ctx = await makeContext(file, text);
  return rule.appliesTo?.(ctx) ? rule.detect(ctx).length : 0;
}

describe('missing response security headers', () => {
  it.each([
    ['VSB-INFRA-010','Content-Security-Policy'],
    ['VSB-INFRA-011','X-Frame-Options'],
    ['VSB-INFRA-012','Strict-Transport-Security'],
  ])('%s reports absence in Next configuration, but recognizes a configured header', async (id, header) => {
    expect(await hits(id,'next.config.ts','export default { reactStrictMode: true };')).toBe(1);
    expect(await hits(id,'next.config.ts',`export default { headers: [{key: '${header}', value: 'configured'}] };`)).toBe(0);
    expect(await hits(id,'src/helpers.ts','export const enabled = true;')).toBe(0);
    expect(await hits(id,'next.config.ts',`// ${header}\nexport default {};`)).toBe(1);
  });
  it('recognizes an unconfigured Helmet default and frame-ancestors, but not an arbitrary route', async () => {
    const app = "import express from 'express'; app.use(helmet()); app.listen(3000);";
    for (const id of ['VSB-INFRA-010','VSB-INFRA-011','VSB-INFRA-012']) expect(await hits(id,'src/server.ts',app)).toBe(0);
    expect(await hits('VSB-INFRA-011','next.config.js',"const policy = 'frame-ancestors none';")).toBe(0);
    expect(await hits('VSB-INFRA-010','app/api/route.ts','export function GET() {}')).toBe(0);
  });
});

describe('missing cookie flags', () => {
  it.each([
    ['VSB-INFRA-013','httpOnly'],['VSB-INFRA-014','secure'],['VSB-INFRA-015','sameSite'],
  ])('%s detects absence but not a present option or dynamic options', async (id, key) => {
    expect(await hits(id,'src/auth.ts',"res.cookie('session', token, {});")).toBe(1);
    expect(await hits(id,'src/auth.ts',"res.cookie('session', token);")).toBe(1);
    expect(await hits(id,'src/auth.ts',`res.cookie('session', token, { ${key}: true });`)).toBe(0);
    expect(await hits(id,'src/auth.ts',"res.cookie('session', token, options);")).toBe(0);
    expect(await hits(id,'src/auth.ts',"res.cookie('session', token, { ...defaults });")).toBe(0);
    expect(await hits(id,'src/auth.ts',`res.cookie('session', token, { nested: { ${key}: true } });`)).toBe(1);
    expect(await hits(id,'src/auth.ts',`res.cookie('session', token, { ${key} });`)).toBe(0);
    expect(await hits(id,'src/auth.ts',"// res.cookie('session', token, {})\nconst x = 1;")).toBe(0);
  });
  it('treats each cookie setter separately, including Next and Hono shapes', async () => {
    const src = "cookies().set('a', token, { httpOnly: true, secure: true, sameSite: 'lax' });\n" +
      "cookies().set('b', token, { secure: true });\nsetCookie(c, 'sid', token, { secure: true, httpOnly: true });";
    expect(await hits('VSB-INFRA-013','app/api/auth/route.ts',src)).toBe(1);
    expect(await hits('VSB-INFRA-014','app/api/auth/route.ts',src)).toBe(0);
    expect(await hits('VSB-INFRA-015','app/api/auth/route.ts',src)).toBe(2);
    expect(await hits('VSB-INFRA-013','src/auth.ts',"cookies().set({ name: 'session', value: token, secure: true })")).toBe(1);
  });
});

describe('OWASP and CWE mapping', () => {
  it('assigns every rule a CWE and an OWASP web association with an explicit basis', () => {
    for (const rule of ALL_RULES) {
      expect(rule.cwe.id, rule.id).toMatch(/^CWE-\d+$/);
      expect(rule.owasp?.web, rule.id).toBeTruthy();
      expect(rule.owasp?.web?.id, rule.id).toMatch(/^A\d\d:2025$/);
      expect(['owasp-cwe','contextual']).toContain(rule.owasp?.web?.basis);
      expect(Array.isArray(rule.owasp?.llm)).toBe(true);
    }
    expect(getRule('VSB-AI-004')?.owasp?.llm[0]?.id).toBe('LLM01:2025');
    expect(getRule('VSB-AUTH-001')?.owasp?.llm).toEqual([]);
    expect(getRule('VSB-CRYPTO-004')?.owasp?.web?.id).toBe('A04:2025');
    expect(getRule('VSB-INFRA-009')?.owasp?.web?.basis).toBe('contextual');
  });
  it('includes mappings in JSON, Markdown, HTML, and SARIF findings', async () => {
    const p = makeProject({'src/auth.ts':"res.cookie('session', token, {});"});
    try {
      const result = await scanProject({rootDir:p.root, rules:[getRule('VSB-INFRA-013')!]});
      const json = JSON.parse(formatResult(result,'json'));
      expect(json.findings[0].owasp.web.id).toBe('A02:2025');
      expect(formatResult(result,'markdown')).toContain('A02:2025 Security Misconfiguration');
      expect(formatResult(result,'html')).toContain('A02:2025 Security Misconfiguration');
      const sarif = JSON.parse(formatResult(result,'sarif'));
      expect(sarif.runs[0].results[0].properties.owasp.web.id).toBe('A02:2025');
    } finally { p.cleanup(); }
  });
});
