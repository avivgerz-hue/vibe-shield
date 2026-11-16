import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { scanProject, auditSkills, ALL_RULES, scoreFindings } from '../dist/src/index.js';

const COHORTS = [
  { id: 'mcp-servers', title: 'MCP Servers & Tool Providers', queries: ['mcp-server', 'modelcontextprotocol server'], target: 40 },
  { id: 'agent-skills', title: 'Agent Skills, Cursor Rules & Coding Plugins', queries: ['claude skill', 'cursorrules', 'claude-code', 'agent-skills'], target: 40 },
  { id: 'fullstack-ai', title: 'Next.js / Supabase / Stripe AI Web Packages', queries: ['nextjs supabase', 'nextjs stripe', 'supabase auth next', 't3 stack'], target: 40 },
  { id: 'llm-agents', title: 'LLM Agent & Prompt Execution Tooling', queries: ['openai agent tool', 'langchain tool', 'ai-sdk tool', 'llm agent'], target: 40 },
];
const EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.md', '.yaml', '.yml', '.sql', '.env', '.sh']);

function untar(tgz, dest) {
  const tar = zlib.gunzipSync(tgz);
  let off = 0, count = 0;
  while (off + 512 <= tar.length) {
    const hdr = tar.subarray(off, off + 512);
    if (hdr[0] === 0) break;
    const name = hdr.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const pref = hdr.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const full = (pref ? `${pref}/${name}` : name).replace(/^package\/?/, '');
    const size = parseInt(hdr.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim() || '0', 8) || 0;
    const flag = String.fromCharCode(hdr[156]);
    off += 512;
    if ((flag === '0' || flag === '\0') && full && size > 0 && size < 350000) {
      const ext = path.extname(full).toLowerCase(), base = path.basename(full).toLowerCase();
      if (EXT.has(ext) || base.startsWith('.env') || base === '.cursorrules' || base === 'skill.md') {
        const rel = full.split('/').filter((p) => p && p !== '..' && p !== '.').join(path.sep);
        const out = path.join(dest, rel);
        if (out.startsWith(dest)) {
          fs.mkdirSync(path.dirname(out), { recursive: true });
          fs.writeFileSync(out, tar.subarray(off, off + size));
          count++;
        }
      }
    }
    off += Math.ceil(size / 512) * 512;
  }
  return count;
}

async function getJson(u) {
  const r = await fetch(u, { headers: { 'user-agent': 'vibe-shield-bench/2.1.2' } });
  if (!r.ok) throw new Error(String(r.status));
  return r.json();
}

async function scanPkg(pkg) {
  const meta = await getJson(`https://registry.npmjs.org/${encodeURIComponent(pkg.name).replace('%40', '@')}/latest`);
  if (!meta?.dist?.tarball) return null;
  const r = await fetch(meta.dist.tarball);
  if (!r.ok) return null;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vsb-'));
  try {
    const fc = untar(Buffer.from(await r.arrayBuffer()), tmp);
    if (!fc) return null;
    const sr = await scanProject({ rootDir: tmp, includeTests: false, includeDocs: true });
    let sf = [];
    try { sf = (await auditSkills({ rootDir: tmp }))?.findings || []; } catch {}
    const seen = new Set();
    const findings = [...(sr.findings || []), ...sf].filter((f) => {
      if (f.ruleId === 'VSB-DEPS-006') return false;
      const k = `${f.ruleId}:${f.file}:${f.line}`;
      return seen.has(k) ? false : (seen.add(k), true);
    });
    const sc = scoreFindings ? scoreFindings(findings) : sr.score;
    return { cohort: pkg.cohort, files: sr.stats?.filesScanned || fc, score: sc?.score ?? 100, findings };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

async function main() {
  const seen = new Set(), queue = [];
  for (const c of COHORTS) {
    let added = 0;
    for (const q of c.queries) {
      if (added >= c.target) break;
      try {
        const d = await getJson(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(q)}&size=60`);
        for (const o of d.objects || []) {
          const n = o?.package?.name;
          if (!n || seen.has(n) || n.startsWith('@vibefoundry/') || n === 'unslop-mcp' || n === 'ghost-qa') continue;
          seen.add(n); queue.push({ name: n, cohort: c.id }); added++;
          if (added >= c.target) break;
        }
      } catch {}
    }
  }
  const res = [];
  for (let i = 0; i < queue.length; i += 8) {
    const b = await Promise.all(queue.slice(i, i + 8).map((p) => scanPkg(p).catch(() => null)));
    for (const x of b) if (x) res.push(x);
  }
  const totalPkgs = res.length, totalFiles = res.reduce((a, b) => a + b.files, 0);
  const allF = res.flatMap((r) => r.findings);
  const anyPkg = res.filter((r) => r.findings.length > 0).length;
  const chPkg = res.filter((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high')).length;
  const sev = { critical: 0, high: 0, medium: 0, low: 0 }, cat = {}, rules = {}, cwes = {};
  for (const f of allF) {
    sev[f.severity] = (sev[f.severity] || 0) + 1;
    cat[f.category] = (cat[f.category] || 0) + 1;
    const rk = `${f.ruleId}: ${f.title}`;
    rules[rk] = (rules[rk] || 0) + 1;
    const cweStr = typeof f.cwe === 'object' && f.cwe !== null ? `${f.cwe.id}: ${f.cwe.title || f.cwe.name || ''}`.replace(/:\s*$/, '') : String(f.cwe || 'CWE-Other');
    cwes[cweStr] = (cwes[cweStr] || 0) + 1;
  }
  const cohorts = COHORTS.map((c) => {
    const cr = res.filter((r) => r.cohort === c.id), n = cr.length || 1;
    const anyC = cr.filter((r) => r.findings.length > 0).length;
    const ch = cr.filter((r) => r.findings.some((f) => f.severity === 'critical' || f.severity === 'high')).length;
    return { id: c.id, title: c.title, packages: cr.length, avgScore: Number((cr.reduce((a, b) => a + b.score, 0) / n).toFixed(1)), anyRate: `${((anyC / n) * 100).toFixed(1)}%`, critHighRate: `${((ch / n) * 100).toFixed(1)}%`, findings: cr.reduce((a, b) => a + b.findings.length, 0) };
  });
  const topRules = Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 12);
  const topCwes = Object.entries(cwes).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const summary = { benchmarkVersion: '2026.03', scanner: '@vibefoundry/vibe-shield@2.1.2', ruleCount: ALL_RULES.length, packagesAnalyzed: totalPkgs, filesAnalyzed: totalFiles, totalFindings: allF.length, anyFindingCount: anyPkg, anyFindingPct: Number(((anyPkg / totalPkgs) * 100).toFixed(1)), critHighCount: chPkg, critHighPct: Number(((chPkg / totalPkgs) * 100).toFixed(1)), sev, cat, cohorts, topRules, topCwes };
  fs.writeFileSync('benchmark/results-summary.json', JSON.stringify(summary, null, 2) + '\n');

  const md = [
    '# 2026 Empirical Security Benchmark: AI-Generated Code, MCP Servers & Agent Skills',
    '',
    `> **Dataset:** **${totalPkgs}** published packages (**${totalFiles.toLocaleString()}** source, SQL, and agent configuration files) sampled across 4 AI-native cohorts from the public npm registry and audited statically with **[\`@vibefoundry/vibe-shield\`](https://github.com/avivgerz-hue/vibe-shield)** (${ALL_RULES.length} rules mapped to CWE & OWASP Top 10:2025).`,
    '> **Methodological Control & Responsible Disclosure:** Because `npm pack` strips `package-lock.json` from published tarballs by specification, rule `VSB-DEPS-006` (missing lockfile) is excluded from tarball scoring to prevent packaging-artifact inflation. All package-level findings are aggregated and anonymized in [`benchmark/results-summary.json`](./benchmark/results-summary.json).',
    '',
    '## Executive Findings',
    '',
    '| Metric | Empirical Result |',
    '| :--- | :--- |',
    `| **Published Packages Audited** | **${totalPkgs}** across 4 AI-native cohorts |`,
    `| **Source & Agent Files Inspected** | **${totalFiles.toLocaleString()}** files |`,
    `| **Total Actionable Security Findings** | **${allF.length}** (**${sev.critical}** Critical, **${sev.high}** High, **${sev.medium}** Medium, **${sev.low}** Low) |`,
    `| **Packages with >= 1 Vulnerability / Hardening Flaw** | **${anyPkg} / ${totalPkgs} (${summary.anyFindingPct}%)** |`,
    `| **Packages with Critical or High Severity Flaws** | **${chPkg} / ${totalPkgs} (${summary.critHighPct}%)** |`,
    '',
    '## Cohort Breakdown',
    '',
    '| Cohort | Packages | Mean Score (0-100) | Affected Packages | Critical / High Rate | Total Findings |',
    '| :--- | :---: | :---: | :---: | :---: | :---: |',
    ...cohorts.map((c) => `| **${c.title}** | ${c.packages} | **${c.avgScore}** | ${c.anyRate} | **${c.critHighRate}** | ${c.findings} |`),
    '',
    '## Top Vulnerability Rules Triggered in the Wild',
    '',
    '| Rank | Rule ID & Title | Occurrences |',
    '| :---: | :--- | :---: |',
    ...topRules.map(([r, cnt], i) => `| ${i + 1} | \`${r}\` | **${cnt}** |`),
    '',
    '## Top CWE Classifications Observed',
    '',
    '| CWE Identifier | Occurrences |',
    '| :--- | :---: |',
    ...topCwes.map(([c, cnt]) => `| **${c}** | ${cnt} |`),
    '',
    '## Attack Vector Distribution',
    '',
    '| Vector Category | Findings |',
    '| :--- | :---: |',
    ...Object.entries(cat).sort((a, b) => b[1] - a[1]).map(([k, v]) => `| \`${k}\` | **${v}** |`),
    '',
    '## Reproducing Locally',
    '',
    '```bash',
    'npx -y @vibefoundry/vibe-shield@latest scan .',
    'npx -y @vibefoundry/vibe-shield@latest audit-skills .',
    'node scripts/run-benchmark-2026.mjs',
    '```',
    ''
  ].join('\n');
  fs.writeFileSync('BENCHMARK-2026.md', md, 'utf8');
  console.log(JSON.stringify(summary, null, 2));
}
main();