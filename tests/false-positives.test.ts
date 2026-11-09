import { describe, expect, it } from 'vitest';
import { scanProject } from '../src/scanner/engine';
import { selectRules } from '../src/scanner/rules';
import { makeProject, scan, byRule } from './helpers';

const rules = selectRules(['VSB-AUTH-001', 'VSB-AUTH-004', 'VSB-AUTH-007', 'VSB-CLIENT-003', 'VSB-DB-008']);
const only = async (files: Record<string, string>) => scan(files, { rules });
const ids = (result: Awaited<ReturnType<typeof only>>) => result.findings.map(f => f.ruleId);

describe('real-world authentication regressions', () => {
  it.each([
    'await supabase.auth.getUser()', 'await supabase.auth.getSession()', 'await auth()',
    'await getServerSession()', 'await currentUser()', 'await verifyToken(token)',
    "if (!user) return new Response('Unauthorized', { status: 401 })",
  ])('recognizes an auth signal in a handler with destructured params: %s', async guard => {
    const result = await only({ 'app/api/items/route.ts': `export async function DELETE(request: Request, { params }: { params: { id: string } }) { ${guard}; await db.update({}); }` });
    expect(byRule(result, 'VSB-AUTH-001')).toHaveLength(0);
  });
  it('recognizes wrapped exports, but still detects unwrapped and separately unguarded handlers', async () => {
    const result = await only({ 'app/api/items/route.ts': `
export const POST = withSomeHandler(async (req) => { await db.update({}); });
export async function DELETE(req, { params }) { await db.delete({}); }
export const PUT = async (req) => { await auth(); await db.update({}); };
export const PATCH = async (req) => { await db.update({}); };
` });
    const hits = byRule(result, 'VSB-AUTH-001');
    expect(hits.map(f => f.data?.verb)).toEqual(['DELETE', 'PATCH']);
  });
  it('does not borrow auth from a later unrelated arrow function', async () => {
    const result = await only({ 'app/api/items/route.ts': 'export const POST = handler; const unrelated = async () => { await auth(); };' });
    expect(byRule(result, 'VSB-AUTH-001')).toHaveLength(1);
  });
  it('does not treat an arbitrary non-wrapper as authenticated', async () => {
    const result = await only({ 'app/api/items/route.ts': 'export const POST = createHandler(async () => { await db.update({}); });' });
    expect(byRule(result, 'VSB-AUTH-001')).toHaveLength(1);
  });
});

describe('ownership-source regressions', () => {
  it('does not taint user.id simply because body supplies a different field', async () => {
    const result = await only({ 'app/api/memory/route.ts': `
export async function POST(request: Request) {
  const { data: { user } } = await supabase.auth.getUser();
  const body = await request.json();
  const payload = { user_id: user.id, full_name: body?.full_name };
  await supabase.from("ai_memory").upsert(payload);
}` });
    expect(ids(result)).toEqual([]);
  });
  it('does not confuse a request field used for a non-ownership property with session ownership', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) { const body = await req.json(); const payload = { user_id: user.id, full_name: body.userId }; await db.users.upsert(payload); }` });
    expect(byRule(result, 'VSB-AUTH-004')).toHaveLength(0);
  });
  it.each([
    'user_id: body.user_id', 'userId: req.body.userId', 'owner_id: params.userId',
    "org_id: searchParams.get('org_id')", 'account_id: body?.account_id', 'user_id: body.id',
    "user_id: body['user_id'], created_by: user.id",
  ])('continues to detect request-derived ownership: %s', async value => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) { const body = await req.json(); const payload = { ${value} }; await db.users.upsert(payload); }` });
    expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
  });
  it('detects ownership predicates and tainted aliases', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) { const owner = req.body.id; await db.users.update({user_id: owner}).eq('org_id', req.body.org); }` });
    expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
  });
  it('tracks a named owner variable assigned a different request field', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) { const userId = req.body.id; await db.users.update({ where: { userId } }); }` });
    expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
  });
  it('tracks an ownership field destructured with an alias', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) { const { userId: owner } = await req.json(); await db.users.update({ where: { userId: owner } }); }` });
    expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
  });
  it('accepts an ownership predicate after a matching session guard in the same handler', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req, {params}) { if (params.userId !== user.id) return new Response('Forbidden'); await db.users.update({ user_id: params.userId }); }` });
    expect(byRule(result, 'VSB-AUTH-004')).toHaveLength(0);
  });
  it('does not treat a conditional or nested guard as unconditional', async () => {
    for (const guard of ['if (flag) { if (params.userId !== user.id) return; }', 'if (flag) if (params.userId !== user.id) return;']) {
      const result = await only({ 'app/api/memory/route.ts': `export async function POST(req, {params}) { ${guard} await db.users.update({user_id: params.userId}); }` });
      expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
    }
  });
  it('does not reuse a guard from a different handler or after a reassignment', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req, {params}) { if (params.userId !== user.id) return; } export async function DELETE(req, {params}) { await db.users.update({user_id: params.userId}); }` });
    expect(byRule(result, 'VSB-AUTH-004').length).toBeGreaterThan(0);
  });
  it('accepts a direct comparison with the verified user, not a coincidental session on the same line', async () => {
    const result = await only({ 'app/api/memory/route.ts': `export async function POST(req) {\nif (params.userId !== user.id) return new Response('Forbidden', { status: 403 });\nawait db.users.update({where:{id: recordId}});\n}` });
    expect(byRule(result, 'VSB-AUTH-004')).toHaveLength(0);
  });
});

describe('admin rule scope', () => {
  it.each(['src/features/dashboard/layouts/footer.tsx','src/app/(extra)/privacy/page.tsx','src/components/header.tsx','src/features/table-cells.tsx'])('does not treat UI components as admin endpoints: %s', async name => {
    const result = await only({ [name]: `import express from 'express'; const app = express(); await auth(); app.delete('/admin/user', () => db.users.deleteMany({}));` });
    expect(byRule(result, 'VSB-AUTH-007')).toHaveLength(0);
  });
  it.each(['src/app/api/admin/route.ts', 'src/pages/api/admin.ts', 'src/server/admin.ts', 'src/actions/admin.ts'])('still catches real server admin surfaces: %s', async name => {
    const content = name.includes('/actions/') ? `'use server';\nexport async function act() { await auth(); await db.users.deleteMany({}); }` : name.includes('/server/') ? `import express from 'express';\nconst app=express();\napp.post('/admin', async () => { await auth(); await db.users.deleteMany({}); });` : `export async function POST() { await auth(); await db.users.deleteMany({}); }`;
    const result = await only({ [name]: content });
    expect(byRule(result, 'VSB-AUTH-007')).toHaveLength(1);
  });
});

describe('service-role boundary regressions', () => {
  const admin = `import { createClient } from '@supabase/supabase-js';\nexport const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);`;
  it('does not call a dedicated server helper a critical client exposure', async () => {
    const result = await only({ 'src/lib/supabase/admin.ts': admin });
    expect(ids(result)).toEqual([]);
  });
  it('still flags the key in an explicit client module', async () => {
    const result = await only({ 'src/lib/supabase/admin.ts': `'use client';\n${admin}` });
    expect(ids(result)).toEqual(expect.arrayContaining(['VSB-CLIENT-003','VSB-DB-008']));
  });
  it('still flags public service-role environment variables in server files', async () => {
    const result = await only({ 'src/lib/supabase/admin.ts': admin.replace('process.env.SUPABASE_SERVICE_ROLE_KEY','process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY') });
    expect(ids(result)).toEqual(expect.arrayContaining(['VSB-CLIENT-003','VSB-DB-008']));
  });
  it('traces transitive client imports and tsconfig aliases', async () => {
    const result = await only({
      'tsconfig.json': '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}',
      'src/app/page.tsx': `'use client';\nimport { wrapper } from '@/lib/wrapper'; wrapper();`,
      'src/lib/wrapper.ts': `export { admin as wrapper } from './supabase/admin';`,
      'src/lib/supabase/admin.ts': admin,
    });
    expect(ids(result)).toEqual(expect.arrayContaining(['VSB-CLIENT-003','VSB-DB-008']));
  });
  it('follows a dynamic literal import to a multiline admin client', async () => {
    const result = await only({ 'src/app/page.tsx': `'use client'; export const load = () => import('../lib/supabase/admin');`, 'src/lib/supabase/admin.ts': `export const admin = createClient(\n url,\n process.env.SUPABASE_SERVICE_ROLE_KEY!\n);` });
    expect(ids(result)).toEqual(expect.arrayContaining(['VSB-CLIENT-003','VSB-DB-008']));
  });
  it('does not treat a type-only import as runtime reachability', async () => {
    const result = await only({ 'src/app/page.tsx': `'use client';\nimport type { Admin } from '../lib/supabase/admin';`, 'src/lib/supabase/admin.ts': admin });
    expect(ids(result)).toEqual([]);
  });
  it('invalidates cached server results when a client starts importing the helper', async () => {
    const p = makeProject({ 'src/lib/supabase/admin.ts': admin, 'src/app/page.tsx': `'use client';\nexport default function Page() {}` });
    try {
      const opts = { rootDir:p.root, rules, useGitIndex:false, cache:true };
      expect(ids(await scanProject(opts))).toEqual([]);
      p.write('src/app/page.tsx', `'use client';\nimport { admin } from '../lib/supabase/admin';`);
      expect(ids(await scanProject(opts))).toEqual(expect.arrayContaining(['VSB-CLIENT-003','VSB-DB-008']));
    } finally { p.cleanup(); }
  });
});
