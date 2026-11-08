import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { run, type CliIo } from '../bin/vibe-shield';
import { auditSkills } from '../src/mcp-guard/skill-auditor';
import { installScaffold } from '../src/init/scaffold';
import { makeProject } from './helpers';

function io(cwd: string): CliIo {
  return {cwd, env:{}, stdout:{write:()=>true}, stderr:{write:()=>true}};
}
const readJson = (root:string, name:string): any => JSON.parse(readFileSync(path.join(root,name),'utf8'));
const files = [
  '.mcp.json', 'CLAUDE.md', '.claude/skills/vibe-shield/SKILL.md', '.claude-plugin/plugin.json',
  'opencode.json', 'AGENTS.md', '.agents/skills/vibe-shield/SKILL.md', '.cursor/mcp.json',
  '.cursor/rules/vibe-shield.mdc', '.windsurfrules', '.vscode/mcp.json', '.github/copilot-instructions.md',
  '.clinerules', '.zed/settings.json',
];

describe('universal agent setup', () => {
  it('installs all native integrations, audits them and is idempotent', async () => {
    const p = makeProject({'package.json':'{"name":"test"}'});
    try {
      expect(await run(['init','--agents','all','--no-workflow'],io(p.root))).toBe(0);
      for (const f of files) expect(existsSync(path.join(p.root,f)), f).toBe(true);
      expect(readJson(p.root,'opencode.json').mcp['vibe-shield']).toEqual({type:'local',command:['npx','--yes','@vibefoundry/vibe-shield@2.0.0','mcp'],enabled:true});
      expect(readJson(p.root,'.vscode/mcp.json').servers['vibe-shield'].type).toBe('stdio');
      expect(readJson(p.root,'.zed/settings.json').context_servers['vibe-shield'].args).toContain('@vibefoundry/vibe-shield@2.0.0');
      expect(readJson(p.root,'.claude-plugin/plugin.json').skills).toBe('./.claude/skills/');
      const result = await auditSkills(p.root);
      for (const f of ['opencode.json','.vscode/mcp.json','.zed/settings.json','.github/copilot-instructions.md']) expect(result.scannedPaths).toContain(f);
      expect(result.findings).toEqual([]);
      for (const f of ['opencode.json','.vscode/mcp.json','.zed/settings.json']) expect(result.attackSurface?.agentFiles).toContainEqual({file:f,kind:'mcp',name:'vibe-shield'});
      const before = Object.fromEntries(files.map(f => [f,readFileSync(path.join(p.root,f),'utf8')]));
      expect(await run(['init','--agents','all','--no-workflow'],io(p.root))).toBe(0);
      for (const f of files) expect(readFileSync(path.join(p.root,f),'utf8'), f).toBe(before[f]);
    } finally {p.cleanup();}
  });
  it('supports comma-separated selections, legacy --agent, and validates bad lists before writing', async () => {
    const p = makeProject({});
    try {
      expect(await run(['init','--agents','opencode,zed','--no-workflow'],io(p.root))).toBe(0);
      expect(existsSync(path.join(p.root,'opencode.json'))).toBe(true);
      expect(existsSync(path.join(p.root,'.zed/settings.json'))).toBe(true);
      expect(existsSync(path.join(p.root,'AGENTS.md'))).toBe(true);
      expect(existsSync(path.join(p.root,'.cursor/mcp.json'))).toBe(false);
      expect(await run(['init','--agent','cursor','--no-workflow'],io(p.root))).toBe(0);
      expect(existsSync(path.join(p.root,'.cursor/mcp.json'))).toBe(true);
      expect(await run(['init','--agents','zed,unknown'],io(p.root))).toBe(2);
      expect(await run(['init','--agent','claude','--agents','zed'],io(p.root))).toBe(2);
    } finally {p.cleanup();}
  });
  it('preserves unrelated JSON, rejects invalid configs, and force updates only its own key', async () => {
    const p = makeProject({
      'opencode.json':JSON.stringify({theme:'night',mcp:{other:{type:'local',command:['other']},'vibe-shield':{type:'local',command:['old']}}}),
      '.zed/settings.json':JSON.stringify({font_size:17,context_servers:{other:{command:'keep'}}}),
      '.cursor/mcp.json':'{ invalid',
      '.vscode/mcp.json':JSON.stringify({servers:[]}),
    });
    try {
      const r=await installScaffold({rootDir:p.root,agents:['opencode','zed','cursor','copilot'],workflow:false,force:true});
      expect(r.blocked).toEqual(expect.arrayContaining(['.cursor/mcp.json','.vscode/mcp.json']));
      expect(readFileSync(path.join(p.root,'.cursor/mcp.json'),'utf8')).toBe('{ invalid');
      expect(readJson(p.root,'opencode.json').theme).toBe('night');
      expect(readJson(p.root,'opencode.json').mcp.other.command).toEqual(['other']);
      expect(readJson(p.root,'opencode.json').mcp['vibe-shield'].command[2]).toBe('@vibefoundry/vibe-shield@2.0.0');
      expect(readJson(p.root,'.zed/settings.json').context_servers.other.command).toBe('keep');
      expect(readJson(p.root,'.zed/settings.json').font_size).toBe(17);
    } finally {p.cleanup();}
  });
  it.each(['untrusted-package@latest','untrusted-package@^1.2.3','untrusted-package@1.2'])('rejects non-exact npm specs: %s', async spec => {
    const p = makeProject({'opencode.json': JSON.stringify({mcp:{bad:{type:'local',command:['npx','-y',spec]}}})});
    try { expect((await auditSkills(p.root)).findings.some(f=>f.ruleId==='VSB-AGENT-004')).toBe(true); }
    finally { p.cleanup(); }
  });
  it.each([
    ['opencode.json',{mcp:{bad:{type:'local',command:['npx','-y','untrusted-package']}}}],
    ['.vscode/mcp.json',{servers:{bad:{type:'stdio',command:'npx',args:['-y','untrusted-package']}}}],
    ['.zed/settings.json',{context_servers:{bad:{command:'npx',args:['-y','untrusted-package']}}}],
  ])('audits unpinned servers in %s', async (name, config) => {
    const p=makeProject({[name]:JSON.stringify(config)});
    try {
      const result=await auditSkills(p.root);
      expect(result.scannedPaths).toContain(name);
      expect(result.findings.some(f=>f.ruleId==='VSB-AGENT-004')).toBe(true);
    } finally {p.cleanup();}
  });
});

describe('Marketplace composite action', () => {
  const action=readFileSync(path.join(__dirname,'../action.yml'),'utf8');
  const runBlocks=Array.from(action.matchAll(/^      run: \|\n((?:        .*\n|\n)+)/gm), m=>m[1]!.split('\n').map(line=>line.startsWith('        ')?line.slice(8):line).join('\n'));
  it('declares Marketplace branding, supported inputs, and a composite action', () => {
    expect(action).toMatch(/branding:\s*\n\s+icon: shield\s*\n\s+color: purple/);
    for(const input of ['target','fail-on','audit-skills','sarif-file']) expect(action).toContain(`  ${input}:`);
    expect(action).toContain('using: composite');
    expect(readFileSync(path.join(__dirname,'../.claude/skills/vibe-shield/SKILL.md'),'utf8')).toBe(readFileSync(path.join(__dirname,'../SKILL.md'),'utf8'));
    expect(runBlocks).toHaveLength(3);
    expect(action).toContain("if: ${{ always() }}");
  });
  it('quotes untrusted inputs, passes SARIF options, and propagates failed gates', () => {
    const p=makeProject({'bin/npx':'#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\nexit "${NPX_EXIT:-0}"\n'});
    try {
      chmodSync(path.join(p.root,'bin/npx'),0o755);
      const capture=path.join(p.root,'args.txt');
      const target='path with spaces; touch SHOULD_NOT_EXIST';
      const env={...process.env,PATH:`${path.join(p.root,'bin')}:${process.env.PATH}`,CAPTURE:capture,VIBE_TARGET:target,VIBE_FAIL_ON:'high',VIBE_SARIF_FILE:'report with spaces.sarif'};
      execFileSync('bash',['-c',runBlocks[0]!],{cwd:p.root,env});
      expect(readFileSync(capture,'utf8').trim().split('\n')).toEqual(['-y','@vibefoundry/vibe-shield@2.0.0','scan',target,'--fail-on','high','--format','sarif','--out','report with spaces.sarif']);
      expect(existsSync(path.join(p.root,'SHOULD_NOT_EXIST'))).toBe(false);
      execFileSync('bash',['-c',runBlocks[1]!],{cwd:p.root,env});
      expect(readFileSync(capture,'utf8')).toContain('audit-skills\n'+target+'\n');
      expect(() => execFileSync('bash',['-c',runBlocks[2]!],{cwd:p.root,env:{...env,VIBE_SCAN_OUTCOME:'failure',VIBE_AUDIT_OUTCOME:'success',VIBE_AUDIT_ENABLED:'true'},stdio:'pipe'})).toThrow();
      expect(() => execFileSync('bash',['-c',runBlocks[2]!],{cwd:p.root,env:{...env,VIBE_SCAN_OUTCOME:'success',VIBE_AUDIT_OUTCOME:'skipped',VIBE_AUDIT_ENABLED:'false'},stdio:'pipe'})).not.toThrow();
      writeFileSync(capture,'');
    } finally {p.cleanup();}
  });
});
