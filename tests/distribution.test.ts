/**
 * Distribution-surface tests: the MCP directory manifests, the citation file,
 * and the `.mcp.json` merge behaviour.
 *
 * These files are pure metadata, so nothing else would notice them rotting —
 * a manifest with a 120-character description or a broken name pattern is
 * silently rejected by the registry crawler.
 */

import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildScaffold, installScaffold, mergeMcpConfig, MCP_SERVER_ENTRY, MCP_SERVER_KEY } from '../src/init/scaffold';
import { makeProject } from './helpers';
import { ALL_RULES, SCAN_RULES } from '../src/scanner/rules';
import { AGENT_RULES } from '../src/mcp-guard/skill-auditor';

const ROOT = path.join(__dirname, '..');
const read = (relativePath: string): string => readFileSync(path.join(ROOT, relativePath), 'utf8');
const readJson = <T = Record<string, unknown>>(relativePath: string): T =>
  JSON.parse(read(relativePath)) as T;

const manifest = readJson('package.json') as { name: string; version: string; mcpName: string };

describe('mcp registry manifests', () => {
  it('server.json follows the official registry schema', () => {
    const server = readJson<Record<string, unknown>>('server.json');
    // name must be namespace/server, which is how the registry verifies ownership.
    expect(String(server.name)).toMatch(/^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
    expect(server.name).toBe('io.github.avivgerz-hue/vibe-shield');
    expect(manifest.mcpName).toBe(server.name);
    expect(Object.keys(server).sort()).toEqual(['$schema', 'description', 'name', 'packages', 'repository', 'title', 'version', 'websiteUrl'].sort());
    expect(server.version).toBe(manifest.version);
    // The registry rejects descriptions over 100 characters.
    expect(String(server.description).length).toBeLessThanOrEqual(100);
    expect(String(server.description).length).toBeGreaterThan(20);
    expect((server.repository as { url?: string }).url).toBe('https://github.com/avivgerz-hue/vibe-shield');
    expect((server.repository as { source?: string }).source).toBe('github');

    // The package is published as `@vibefoundry/vibe-shield`. The bare name
    // `vibe-shield` on the registry belongs to a different publisher, so the
    // identifier must stay scoped or every registry consumer is sent to a
    // stranger's scanner.
    const packages = server.packages as Array<Record<string, unknown>>;
    expect(packages).toHaveLength(1);
    const pkg = packages[0] ?? {};
    expect(pkg.registryType).toBe('npm');
    expect(pkg.identifier).toBe(manifest.name);
    expect(pkg.identifier).toBe('@vibefoundry/vibe-shield');
    expect(pkg.identifier).not.toBe('vibe-shield');
    expect(pkg.version).toBe(manifest.version);
    const transport = pkg.transport as { type?: string };
    expect(transport).toEqual({ type: 'stdio' });
    expect(pkg.packageArguments).toEqual([{ type: 'positional', value: 'mcp' }]);
    expect(Object.keys(pkg).sort()).toEqual(['registryType', 'identifier', 'version', 'transport', 'packageArguments'].sort());
  });

  it('names the GitHub entry point wherever a command is advertised', () => {
    const entry = '@vibefoundry/vibe-shield';
    expect(read('glama.json')).toContain(entry);
    expect(read('smithery.yaml')).toContain(entry);
  });

  it('smithery.yaml declares a stdio start command', () => {
    const yaml = read('smithery.yaml');
    expect(yaml).toMatch(/^startCommand:/m);
    expect(yaml).toMatch(/^\s+type:\s*stdio/m);
    expect(yaml).toMatch(/^\s+configSchema:/m);
    expect(yaml).toMatch(/^\s+commandFunction:/m);
    // Tabs are invalid YAML indentation and would break the crawler.
    expect(yaml).not.toMatch(/\t/);
    // The command must actually launch our MCP subcommand.
    expect(yaml).toContain('mcp');
  });

  it('glama.json is valid and lists the three tools', () => {
    const glama = readJson<Record<string, unknown>>('glama.json');
    expect(String(glama.repository)).toBe('https://github.com/avivgerz-hue/vibe-shield');
    expect(glama.version).toBe(manifest.version);
    expect(glama.transport).toBe('stdio');
    const tools = (glama.tools as Array<{ name: string }>).map((tool) => tool.name);
    expect(tools).toEqual(['vibe_shield_scan', 'vibe_shield_audit_skills', 'vibe_shield_explain_rule']);
    expect((glama.maintainers as string[]).length).toBeGreaterThan(0);
  });
});

describe('README catalogue counts', () => {
  it('distinguishes the code scanner and agent auditor from the full catalogue', () => {
    const readme = read('README.md');
    expect(ALL_RULES).toHaveLength(SCAN_RULES.length + AGENT_RULES.length);
    expect(readme).toContain(`${SCAN_RULES.length} code signatures + ${AGENT_RULES.length} agent-integrity signatures = ${ALL_RULES.length}`);
    expect(readme).toContain(`detection%20signatures-${ALL_RULES.length}-`);
    expect(readme).toContain(`${SCAN_RULES.length} code rules; ${AGENT_RULES.length} agent-integrity rules`);
    expect(readme).not.toMatch(/\b(?:79|85|91) rules\b/);
  });
});

describe('citation metadata', () => {
  it('CITATION.cff is parseable and versioned with the package', () => {
    const cff = read('CITATION.cff');
    expect(cff).toMatch(/^cff-version:\s*1\.2\.0/m);
    expect(cff).toMatch(/^message:/m);
    expect(cff).toMatch(/^title:/m);
    expect(cff).toMatch(/^type:\s*software/m);
    // GitHub shows the "Cite this repository" widget only when this parses.
    expect(cff).toContain(`version: "${manifest.version}"`);
    expect(cff).toContain('https://github.com/avivgerz-hue/vibe-shield');
    expect(cff).toMatch(/^authors:/m);
    expect(cff).toMatch(/name:\s*"?VibeFoundry"?/);
    expect(cff).toMatch(/^license:\s*MIT/m);
    // Unquoted version strings like 1.1.0 are read as strings, but dates and
    // versions must stay quoted so YAML never coerces them.
    expect(cff).toMatch(/^date-released:\s*"\d{4}-\d{2}-\d{2}"$/m);
  });
});

describe('mcp config merge', () => {
  it('creates a config when none exists', () => {
    const merged = mergeMcpConfig(null);
    expect(merged.changed).toBe(true);
    const parsed = JSON.parse(merged.contents) as { mcpServers: Record<string, unknown> };
    expect(parsed.mcpServers[MCP_SERVER_KEY]).toEqual(MCP_SERVER_ENTRY);
  });

  it('preserves existing servers and unrelated top-level keys', () => {
    const existing = JSON.stringify({
      mcpServers: { github: { command: 'npx', args: ['-y', 'gh-mcp'] } },
      custom: 42,
    });
    const merged = mergeMcpConfig(existing);
    expect(merged.changed).toBe(true);
    const parsed = JSON.parse(merged.contents) as { mcpServers: Record<string, unknown>; custom: number };
    expect(parsed.mcpServers.github).toEqual({ command: 'npx', args: ['-y', 'gh-mcp'] });
    expect(parsed.custom).toBe(42);
    expect(parsed.mcpServers[MCP_SERVER_KEY]).toEqual(MCP_SERVER_ENTRY);
  });

  it('is a no-op when the server already exists', () => {
    const existing = JSON.stringify({ mcpServers: { [MCP_SERVER_KEY]: MCP_SERVER_ENTRY } });
    const merged = mergeMcpConfig(existing);
    expect(merged.changed).toBe(false);
    expect(merged.contents).toBe(existing);
  });

  it('updates only its own key when forced', () => {
    const existing = JSON.stringify({ mcpServers: { [MCP_SERVER_KEY]: { command: 'old' }, keep: { command: 'k' } } });
    const merged = mergeMcpConfig(existing, { force: true });
    const parsed = JSON.parse(merged.contents) as { mcpServers: Record<string, unknown> };
    expect(parsed.mcpServers[MCP_SERVER_KEY]).toEqual(MCP_SERVER_ENTRY);
    expect(parsed.mcpServers.keep).toEqual({ command: 'k' });
  });

  it('never overwrites a malformed file', () => {
    const broken = '{ "mcpServers": { broken';
    const merged = mergeMcpConfig(broken);
    expect(merged.changed).toBe(false);
    expect(merged.contents).toBe(broken);
    expect(merged.error).toMatch(/not valid JSON/i);
  });

  it('rejects a non-object mcpServers rather than clobbering it', () => {
    const existing = JSON.stringify({ mcpServers: ['not', 'an', 'object'] });
    const merged = mergeMcpConfig(existing);
    expect(merged.changed).toBe(false);
    expect(merged.error).toMatch(/non-object/);
  });

  it('rejects a top-level array', () => {
    const merged = mergeMcpConfig('[]');
    expect(merged.changed).toBe(false);
    expect(merged.error).toBeDefined();
  });
});

describe('init writes the mcp config', () => {
  it('includes .mcp.json in the scaffold for every agent target', () => {
    for (const agents of ['claude', 'cursor', 'generic', 'all'] as const) {
      const files = buildScaffold({ rootDir: '/tmp/x', agents });
      expect(files.map((file) => file.relativePath), agents).toContain('.mcp.json');
    }
  });

  it('merges into an existing .mcp.json on disk', async () => {
    const project = makeProject({
      'package.json': JSON.stringify({ name: 'x' }),
      '.mcp.json': JSON.stringify({ mcpServers: { existing: { command: 'keep-me' } } }),
    });
    try {
      await installScaffold({ rootDir: project.root });
      const parsed = JSON.parse(readFileSync(path.join(project.root, '.mcp.json'), 'utf8')) as {
        mcpServers: Record<string, unknown>;
      };
      expect(parsed.mcpServers.existing).toEqual({ command: 'keep-me' });
      expect(parsed.mcpServers[MCP_SERVER_KEY]).toEqual(MCP_SERVER_ENTRY);
    } finally {
      project.cleanup();
    }
  });

  it('reports a blocked file instead of a normal skip for invalid JSON', async () => {
    const project = makeProject({
      'package.json': JSON.stringify({ name: 'x' }),
      '.mcp.json': '{ not json',
    });
    try {
      const result = await installScaffold({ rootDir: project.root });
      expect(result.blocked).toContain('.mcp.json');
      expect(result.skipped).not.toContain('.mcp.json');
      expect(result.warnings.join(' ')).toMatch(/not valid JSON/i);
      // The file itself must be byte-identical afterwards.
      expect(readFileSync(path.join(project.root, '.mcp.json'), 'utf8')).toBe('{ not json');
    } finally {
      project.cleanup();
    }
  });
});

describe('repository MCP pin', () => {
  it('pins the published v2 scoped version', () => {
    const config = readJson<{ mcpServers: { 'vibe-shield': { command: string; args: string[] } } }>('.mcp.json');
    expect(config.mcpServers['vibe-shield']).toEqual({ command: 'npx', args: ['--yes', '@vibefoundry/vibe-shield@2.1.0', 'mcp'] });
  });
});

describe('distribution files exist', () => {
  it('ships every directory manifest at the repository root', () => {
    for (const file of ['server.json', 'smithery.yaml', 'glama.json', 'CITATION.cff', 'LICENSE', 'SECURITY.md']) {
      expect(existsSync(path.join(ROOT, file)), file).toBe(true);
    }
  });
});

describe('README badges', () => {
  // The *unscoped* name `vibe-shield` on npm belongs to an unrelated project,
  // so a badge pointing at it would render a stranger's version and download
  // count on our front page. The scoped package is ours; that one may be badged.
  it('never renders a badge for the unscoped name', () => {
    const readme = read('README.md');
    expect(readme).not.toMatch(/img\.shields\.io\/npm\/[vd]m?\/vibe-shield(\.svg)?\?/);
    expect(readme).not.toMatch(/img\.shields\.io\/node\/v\//);
    expect(readme).not.toMatch(/npmjs\.com\/package\/vibe-shield/);
  });

  it('shows the scoped npm version and download badges', () => {
    const readme = read('README.md');
    expect(readme).toContain('https://img.shields.io/npm/v/@vibefoundry/vibe-shield.svg');
    expect(readme).toContain('https://img.shields.io/npm/dm/@vibefoundry/vibe-shield.svg');
    expect(readme).toContain('https://www.npmjs.com/package/@vibefoundry/vibe-shield');
  });
});

describe('README first impression', () => {
  it('shows the star CTA, animated demo and immediately following quickstart near the top', () => {
    const readme = read('README.md');
    expect(readme).toContain('⭐ **If this tool helps your AI coding workflow, please give this repository a Star!**');
    const marker = '![Live Terminal Demo](assets/demo.svg)';
    const line = readme.split('\n').findIndex((l) => l.includes(marker));
    expect(line).toBeGreaterThan(0);
    expect(line).toBeLessThan(25);
    expect(readme).toContain(`${marker}\n\n\`\`\`bash\nnpx -y @vibefoundry/vibe-shield@latest scan .\n\`\`\``);
    expect(readme).toContain('fixes are applied manually');
  });

  it('links all three suite repositories and their requested commands', () => {
    const readme = read('README.md');
    for (const repo of ['unslop', 'vibe-shield', 'ghost-qa']) expect(readme).toContain(`https://github.com/avivgerz-hue/${repo}`);
    for (const command of ['npx -y unslop-mcp@latest init', 'npx -y @vibefoundry/vibe-shield@latest scan .', 'npx -y ghost-qa@latest test http://localhost:3000']) expect(readme).toContain(command);
  });

  it('ships a standalone accessible looping SVG with a reduced-motion fallback', () => {
    const svgPath = path.join(ROOT, 'assets', 'demo.svg');
    expect(existsSync(svgPath), 'assets/demo.svg').toBe(true);
    const svg = readFileSync(svgPath, 'utf8');
    expect(svg.trimStart().startsWith('<svg')).toBe(true);
    expect(svg).toContain('viewBox');
    expect(svg).toContain('@keyframes');
    expect(svg).toContain('infinite');
    expect(svg).toContain('prefers-reduced-motion');
    expect(svg).toContain('<title');
    expect(svg).toContain('<desc');
    expect(svg).toContain('VSB-AUTH-001');
    expect(svg).toContain('VSB-DB-001');
    expect(svg).toContain('29/100');
    expect(svg).toContain('100/100');
    expect(svg).toContain('Manually add session ownership');
    expect(svg).not.toMatch(/<script|<image|<foreignObject|(?:href|src)\s*=/i);
    expect(svg.length).toBeLessThan(200 * 1024);
  });
});

describe('container entrypoint', () => {
  it('ships a Dockerfile whose entrypoint is the stdio MCP server', () => {
    const dockerfile = read('Dockerfile');
    expect(dockerfile).toMatch(/^FROM node:2[24]-alpine/m);
    expect(dockerfile).toContain('npm ci --omit=dev --ignore-scripts');
    // Glama drives `initialize`/`tools/list` over stdio, so `mcp` must be the
    // entrypoint and the prebuilt CLI must be the command.
    expect(dockerfile).toContain('"node", "/app/dist/bin/vibe-shield.js", "mcp"');
  });

  it('keeps build inputs out of the image context', () => {
    const ignored = read('.dockerignore').split('\n').map((l) => l.trim()).filter(Boolean);
    for (const entry of ['node_modules', '.git', 'tests', 'coverage', 'src']) {
      expect(ignored, entry).toContain(entry);
    }
  });
});

describe('scoped npm identity', () => {
  it('publishes as the scoped name with a warning-free bin path', () => {
    const pkg = readJson<{ name: string; bin: Record<string, string>; publishConfig?: { access?: string } }>(
      'package.json',
    );
    expect(pkg.name).toBe('@vibefoundry/vibe-shield');
    // npm v11 warns about a leading `./` in bin entries.
    expect(pkg.bin['vibe-shield']).toBe('dist/bin/vibe-shield.js');
    expect(pkg.bin['vibe-shield'].startsWith('./')).toBe(false);
    // Scoped packages default to restricted; publishing requires this.
    expect(pkg.publishConfig?.access).toBe('public');
  });

  it('keeps the lockfile name in sync, or npm ci refuses to run', () => {
    const lock = readJson<{ name: string; packages: Record<string, { name?: string }> }>('package-lock.json');
    const pkg = readJson<{ name: string }>('package.json');
    expect(lock.name).toBe(pkg.name);
    expect(lock.packages['']?.name).toBe(pkg.name);
  });

  it('pins the .mcp.json entry so VSB-AGENT-004 stays satisfied', () => {
    const pkg = readJson<{ version: string }>('package.json');
    const args = MCP_SERVER_ENTRY.args;
    expect(args).toContain(`@vibefoundry/vibe-shield@${pkg.version}`);
  });
});
