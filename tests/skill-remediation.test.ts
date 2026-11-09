import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { describe, expect, it, vi } from 'vitest';

const skill = readFileSync('SKILL.md', 'utf8');
const blocks = [...skill.matchAll(/```typescript\n([\s\S]*?)```/g)].map(m => m[1]!);
const source = (marker: string) => {
  const block = blocks.find(entry => entry.includes(marker));
  if (!block) throw new Error(`Missing example: ${marker}`);
  return block;
};
function load(code: string, modules: Record<string, unknown>): Record<string, (...args: any[]) => Promise<Response>> {
  const built = ts.transpileModule(code, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 }, reportDiagnostics: true });
  expect(built.diagnostics).toEqual([]);
  const exports = {};
  new Function('require', 'exports', built.outputText)((name: string) => {
    if (!(name in modules)) throw new Error(`Unexpected import: ${name}`);
    return modules[name];
  }, exports);
  return exports;
}
// Minimal strict schema mock keeps the shipped examples dependency-free in the test harness.
const stringSchema = () => { const s = { uuid: () => s, trim: () => s, min: (_n: number) => s, max: (_n: number) => s }; return s; };
const zod = { z: { string: stringSchema, object: (shape: Record<string, unknown>) => ({ strict: () => ({ safeParse: (value: unknown) => {
  const obj = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const success = Object.keys(obj).length === Object.keys(shape).length && Object.keys(shape).every(key => typeof obj[key] === 'string');
  return success ? { success, data: obj } : { success: false };
} }) }) } };

describe('security skill remediation examples', () => {
  it('shows scoped SQL policies and warns about permissive policies and RLS bypass', () => {
    expect(skill).toContain('FOR SELECT TO authenticated USING (auth.uid() = user_id)');
    expect(skill).toContain('FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id)');
    expect(skill).toContain('USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)');
    expect(skill).toContain('permissive policies are OR-combined');
    expect(skill).toContain('BYPASSRLS');
  });
  it('binds updates to the verified principal, rejecting identity from the request', async () => {
    const predicates: unknown[][] = [];
    const chain = { update: () => chain, eq: (...args: unknown[]) => { predicates.push(args); return chain; }, select: () => chain, maybeSingle: async () => ({ data: { id: 'doc' }, error: null }) };
    const supabase = { auth: { getUser: async () => ({ data: { user: { id: 'verified-owner' } }, error: null }) }, from: () => chain };
    const route = load(source('app/api/documents/route.ts'), { zod, '@/lib/supabase/server': { createClient: async () => supabase } });
    const req = (body: object) => new Request('http://localhost', { method: 'PATCH', body: JSON.stringify(body) });
    expect((await route.PATCH!(req({ id: 'doc', title: 'safe' }))).status).toBe(200);
    expect(predicates).toContainEqual(['user_id', 'verified-owner']);
    expect((await route.PATCH!(req({ id: 'doc', title: 'safe', userId: 'attacker' }))).status).toBe(400);
  });
  it('guards both AI routes, fails closed, caps provider output, and rejects oversized bodies', async () => {
    const limit = vi.fn().mockResolvedValue({ success: true });
    const create = vi.fn().mockResolvedValue({ choices: [{ message: { content: 'ok' } }] });
    class Redis { static fromEnv() { return {}; } }
    class Ratelimit { static slidingWindow() { return {}; } limit = limit; }
    class OpenAI { chat = { completions: { create } }; }
    const supabase = { auth: { getUser: async () => ({ data: { user: { id: 'user-1' } }, error: null }) } };
    const route = load(source('lib/guarded-ai.ts'), { 'server-only': {}, openai: { default: OpenAI }, '@upstash/redis': { Redis }, '@upstash/ratelimit': { Ratelimit }, zod, '@/lib/supabase/server': { createClient: async () => supabase } });
    const req = (body: string) => new Request('http://localhost', { method: 'POST', body });
    expect((await route.POST!(req(JSON.stringify({prompt:'hello'})))).status).toBe(200);
    expect(limit).toHaveBeenCalledWith('ai:user-1');
    expect(create.mock.calls[0]![0].max_completion_tokens).toBe(512);
    limit.mockResolvedValueOnce({ success: false });
    expect((await route.POST!(req('{}'))).status).toBe(429);
    limit.mockRejectedValueOnce(new Error('offline'));
    expect((await route.POST!(req('{}'))).status).toBe(503);
    expect((await route.POST!(req('x'.repeat(8193)))).status).toBe(400);
    expect(create).toHaveBeenCalledTimes(1);
    expect(source('app/api/chat/route.ts')).toContain('app/api/completion/route.ts');
  });
});
