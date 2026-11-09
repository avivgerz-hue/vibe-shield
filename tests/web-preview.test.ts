import { readFileSync } from 'node:fs';
import { TextDecoder, TextEncoder } from 'node:util';
import { JSDOM } from 'jsdom';
import { describe, expect, it, vi } from 'vitest';

const html = readFileSync('docs/index.html', 'utf8');
const response = (payload: unknown, status = 200) => ({ ok: status === 200, status, json: async () => payload });
function page(fetcher = vi.fn()) {
  const copy = vi.fn().mockResolvedValue(undefined);
  const dom = new JSDOM(html, {
    url: 'https://example.github.io/vibe-shield/', runScripts: 'dangerously',
    beforeParse(window) {
      Object.assign(window, { TextEncoder, TextDecoder, fetch: fetcher });
      Object.defineProperty(window.navigator, 'clipboard', { value: { writeText: copy } });
      window.open = vi.fn();
    },
  });
  const doc = dom.window.document;
  const click = (id: string) => (doc.getElementById(id) as HTMLButtonElement).click();
  const text = (id: string) => doc.getElementById(id)!.textContent!;
  const value = (id: string, v: string) => { (doc.getElementById(id) as HTMLInputElement).value = v; };
  return { dom, doc, click, text, value, copy, fetcher };
}
async function until(fn: () => boolean) {
  for (let i = 0; i < 100; i++) { if (fn()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
  throw new Error('Timed out waiting for browser preview');
}
describe('standalone browser preview', () => {
  it('analyzes sample snippets and shares only score, not source', async () => {
    const p = page(); p.click('snippet-tab');
    (p.doc.querySelector('[data-sample="app"]') as HTMLButtonElement).click(); p.click('scan-snippet');
    expect(p.text('grade')).toContain('Grade F'); expect(p.text('finding-list')).toContain('CWE-200');
    expect(p.text('finding-list')).toContain('OWASP'); expect(p.text('tables')).toBe('1');
    p.click('copy'); await until(() => p.text('status').includes('badge copied'));
    expect(p.copy.mock.calls[0]![0]).toContain('Grade_F-ef4444');
    p.click('share'); const url = String(vi.mocked(p.dom.window.open).mock.calls[0]![0]);
    expect(url).toContain('twitter.com/intent/tweet'); expect(decodeURIComponent(url)).not.toContain('SERVICE_ROLE_KEY');
    p.dom.window.close();
  });
  it('reports MCP pin problems and handles empty inputs without a badge', () => {
    const p = page(); p.click('snippet-tab'); p.click('scan-snippet');
    expect(p.text('status')).toContain('Paste a snippet');
    expect((p.doc.getElementById('copy') as HTMLButtonElement).disabled).toBe(true);
    (p.doc.querySelector('[data-sample="mcp"]') as HTMLButtonElement).click(); p.click('scan-snippet');
    expect(p.text('finding-list')).toContain('Unpinned MCP'); expect(p.text('agents')).toBe('1');
    p.dom.window.close();
  });
  it('fetches the default branch and safely renders untrusted filenames', async () => {
    const contents = 'const value = process.env.NEXT_PUBLIC_SECRET_KEY;';
    const fetcher = vi.fn().mockResolvedValueOnce(response({private:false, default_branch:'main'}))
      .mockResolvedValueOnce(response({commit:{tree:{sha:'tree'}}}))
      .mockResolvedValueOnce(response({truncated:false,tree:[{type:'blob',mode:'100644',path:'<img src=x>.js',size:contents.length,sha:'blob'}]}))
      .mockResolvedValueOnce(response({encoding:'base64',content:Buffer.from(contents).toString('base64')}));
    const p=page(fetcher); p.value('repo','owner/repo'); p.click('scan-repo');
    await until(() => p.text('report-state') === 'Preview complete');
    expect(p.text('finding-list')).toContain('<img src=x>.js'); expect(p.doc.querySelector('#finding-list img')).toBeNull();
    expect(fetcher.mock.calls.every(call => String(call[0]).startsWith('https://api.github.com/repos/owner/repo'))).toBe(true);
    p.dom.window.close();
  });
  it('marks failed blobs and truncated trees partial and never calls them a full scan', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(response({private:false,default_branch:'main'})).mockResolvedValueOnce(response({commit:{tree:{sha:'t'}}}))
      .mockResolvedValueOnce(response({truncated:true,tree:[{type:'blob',mode:'100644',path:'ok.js',size:9,sha:'a'},{type:'blob',mode:'100644',path:'bad.js',size:9,sha:'b'}]}))
      .mockResolvedValueOnce(response({encoding:'base64',content:Buffer.from('let a=1;').toString('base64')})).mockResolvedValueOnce(response({},403));
    const p=page(fetcher); p.value('repo','owner/repo'); p.click('scan-repo');
    await until(() => p.text('report-state') === 'Partial preview');
    expect(p.text('status')).toContain('incomplete'); expect(p.text('coverage')).toContain('not equivalent'); p.dom.window.close();
  });
  it('rejects invalid repository input and reports rate limits without a stale score', async () => {
    const fetcher=vi.fn().mockResolvedValue(response({},403)), p=page(fetcher);
    p.value('repo','https://github.com/owner/repo'); p.click('scan-repo'); expect(fetcher).not.toHaveBeenCalled();
    p.value('repo','owner/repo'); p.click('scan-repo'); await until(() => p.text('status').includes('rate limit'));
    expect(p.text('score')).toBe('—'); expect((p.doc.getElementById('copy') as HTMLButtonElement).disabled).toBe(true); p.dom.window.close();
  });
});
