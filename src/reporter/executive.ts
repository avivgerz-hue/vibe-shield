import { owaspMappings } from '../scanner/mappings';
import { scoreFindings } from '../scanner/engine';
import { CATEGORY_TITLES, RULE_CATEGORIES, type ScanResult } from '../scanner/types';

const clean = (s: string): string => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');
const fence = (s: string): string => {
  const marker = '`'.repeat(Math.max(3, ...Array.from(s.matchAll(/`+/g), m => m[0].length + 1)));
  return `${marker}\n${s}\n${marker}`;
};


// The CWE mapping is based on OWASP's published 2025 category lists.
function mappings(ruleId: string, cwe: string): string {
  const mapping = owaspMappings(ruleId, cwe);
  const web = mapping.web ? `${mapping.web.id} ${mapping.web.name} (${mapping.web.basis})` : 'not mapped';
  const llm = mapping.llm.length ? mapping.llm.map(m => `${m.id} ${m.name} (contextual)`).join(', ') : 'not applicable or not assigned';
  return `OWASP Top 10 2025: ${web}; OWASP LLM Top 10 2025: ${llm}. Validate applicability in context.`;
}

export function formatMarkdown(result: ScanResult): string {
  const lines = ['# Executive Security Report', '', `**Score: ${result.score.score}/100 (${result.score.grade})** · ${result.stats.filesScanned} files scanned · ${result.command}`, '',
    'Static signals require manual validation. A clean score is not proof of security. Ignored, unavailable, and unscanned files are outside this report.', '',
    '## Category scorecard', '', '| Vector | Score | Findings |', '| --- | --- | ---: |'];
  for (const category of RULE_CATEGORIES) {
    const subset = result.findings.filter(f => f.category === category);
    const applicable = result.command === 'audit-skills' ? category === 'agent-integrity' : category !== 'agent-integrity';
    lines.push(`| ${CATEGORY_TITLES[category]} | ${applicable ? `${scoreFindings(subset).score}/100` : 'Not assessed'} | ${subset.length} |`);
  }
  lines.push('', '## Attack-surface inventory', '', 'Observed signals only; guard and RLS signals do not prove enforcement. Absence of a guard signal is not proof a route is unguarded.', '', '| Type | Location | Detail | Signal |', '| --- | --- | --- | --- |');
  const surface = result.attackSurface;
  if (surface) {
    for (const r of surface.routes) lines.push(`| Route | ${clean(r.file)}:${r.line} | ${clean(r.method)} ${clean(r.path)} | ${r.auth} |`);
    for (const t of surface.tables) lines.push(`| Table | ${clean(t.file)}:${t.line} | ${clean(t.table)} | ${t.rls} |`);
    for (const a of surface.aiEntrypoints) lines.push(`| AI entrypoint | ${clean(a.file)}:${a.line} | LLM reference | review |`);
    for (const a of surface.agentFiles) lines.push(`| Agent | ${clean(a.file)} | ${a.kind}${a.name ? ': ' + clean(a.name) : ''} | review |`);
  } else lines.push('| — | — | Inventory not available for this command | — |');
  lines.push('', '## Prioritized findings', '');
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  for (const f of [...result.findings].sort((a,b) => (rank[a.severity] ?? 5) - (rank[b.severity] ?? 5))) {
    lines.push(`### ${clean(f.severity.toUpperCase())}: ${clean(f.title)}`, '', `**${f.ruleId} · ${clean(f.filePath)}:${f.line}:${f.column} · ${f.cwe.id} · confidence ${f.confidence}**`, '', f.message, '', mappings(f.ruleId, f.cwe.id), '', '**Observed code**', '', fence(f.snippet), '', '**Suggested remediation**', '', ...f.remediation.map(x => `- ${x}`), '', '**Illustrative before / after (adapt and validate; not an automatic patch)**', '', fence(f.insecureExample), '', fence(f.secureExample), '');
  }
  if (!result.findings.length) lines.push('No findings reported for the selected rules and files.', '');
  return lines.join('\n') + '\n';
}

const escapeHtml = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
/** All project content is escaped. The only script is a fixed local filter. */
export function formatHtml(result: ScanResult): string {
  const md = formatMarkdown(result);
  const entries = result.findings.map(f => `<article data-severity="${escapeHtml(f.severity)}"><h3>${escapeHtml(f.severity.toUpperCase() + ': ' + f.title)}</h3><p>${escapeHtml(`${f.filePath}:${f.line}:${f.column} · ${f.ruleId} · ${f.cwe.id}`)}</p><pre>${escapeHtml(f.snippet)}</pre><p>${escapeHtml(f.message)}</p><ul>${f.remediation.map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ul></article>`).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Executive Security Report</title><style>body{background:#101722;color:#e8effa;font:16px system-ui;max-width:1000px;margin:auto;padding:2rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1b2738;padding:1rem;border-radius:6px}article{border:1px solid #34455b;padding:1rem;margin:1rem 0;border-radius:8px}select{background:#1b2738;color:white;padding:.5rem}</style></head><body><h1>Executive Security Report</h1><label>Filter findings by severity <select id="severity"><option value="all">All</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></label><section>${entries}</section><details open><summary>Full report</summary><pre>${escapeHtml(md)}</pre></details><script>document.getElementById('severity').addEventListener('change',function(){document.querySelectorAll('article[data-severity]').forEach(function(e){e.hidden=this.value!=='all'&&e.dataset.severity!==this.value},this)})</script></body></html>\n`;
}
