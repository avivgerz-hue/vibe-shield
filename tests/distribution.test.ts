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

const ROOT = path.join(__dirname, '..');
const read = (relativePath: string): string => readFileSync(path.join(ROOT, relativePath), 'utf8');
const readJson = <T = Record<string, unknown>>(relativePath: string): T =>
  JSON.parse(read(relativePath)) as T;

const manifest = readJson('package.json') as { version: string };

describe('mcp registry manifests', () => {
  it('server.json follows the official registry schema', () => {
    const server = readJson<Record<string, unknown>>('server.json');
    // name must be namespace/server, which is how the registry verifies ownership.
    expect(String(server.name)).toMatch(/^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
    expect(String(server.name)).toMatch(/^io\.github\./);
    expect(server.version).toBe(manifest.version);
    // The registry rejects descriptions over 100 characters.
    expect(String(server.description).length).toBeLessThanOrEqual(100);
    expect(String(server.description).length).toBeGreaterThan(20);
    expect((server.repository as { url?: string }).url).toBe('https://github.com/avivgerz-hue/vibe-shield');
    expect((server.repository as { source?: string }).source).toBe('github');

    // No npm package serves this code: the bare name `vibe-shield` on the
    // registry belongs to a different publisher, so advertising it would send
    // every registry consumer to someone else's scanner.
    const packages = server.packages as Array<Record<string, unknown>>;
    expect(packages).toEqual([]);
  });

  it('names the GitHub entry point wherever a command is advertised', () => {
    const entry = 'github:avivgerz-hue/vibe-shield';
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

describe('distribution files exist', () => {
  it('ships every directory manifest at the repository root', () => {
    for (const file of ['server.json', 'smithery.yaml', 'glama.json', 'CITATION.cff', 'LICENSE', 'SECURITY.md']) {
      expect(existsSync(path.join(ROOT, file)), file).toBe(true);
    }
  });
});

describe('README badges', () => {
  // The `vibe-shield` name on the npm registry belongs to an unrelated
  // project. A shields.io npm badge would therefore render *their* version
  // and download count on our front page, so every badge must be backed by
  // data we actually control (GitHub, or a literal).
  it('never renders a badge sourced from the npm registry', () => {
    const readme = read('README.md');
    expect(readme).not.toMatch(/img\.shields\.io\/npm\//);
    expect(readme).not.toMatch(/img\.shields\.io\/node\/v\//);
    expect(readme).not.toMatch(/npmjs\.com\/package\/vibe-shield/);
  });

  it('sources the version badge from this repository', () => {
    expect(read('README.md')).toContain(
      'img.shields.io/github/package-json/v/avivgerz-hue/vibe-shield',
    );
  });
});
