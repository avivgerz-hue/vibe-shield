/** Heuristic inventory of observed surface, not evidence of effective protection. */
import { AUTH_VERIFICATION_REGEX } from './lexicon';
import type { AttackSurface, FileContext, ProjectContext } from './types';

export const emptyAttackSurface = (): AttackSurface => ({ routes: [], tables: [], aiEntrypoints: [], agentFiles: [] });

export function inventoryFile(ctx: FileContext, surface: AttackSurface): void {
  const { relativePath: file, code } = ctx;
  if (ctx.flags.isMcpConfig) {
    try {
      const config = JSON.parse(ctx.content) as Record<string, unknown>;
      const key = /(?:^|\/)opencode\.json$/i.test(file) ? 'mcp'
        : /(?:^|\/)\.vscode\/mcp\.json$/i.test(file) ? 'servers'
          : /(?:^|\/)\.zed\/settings\.json$/i.test(file) ? 'context_servers' : 'mcpServers';
      const map = config[key];
      const servers = map && typeof map === 'object' && !Array.isArray(map) ? Object.keys(map) : [];
      if (servers.length) for (const name of servers) surface.agentFiles.push({ file, kind: 'mcp', name });
      else surface.agentFiles.push({ file, kind: 'mcp' });
    } catch { surface.agentFiles.push({ file, kind: 'mcp' }); }
  }
  else if (ctx.flags.isAgentInstructionFile) surface.agentFiles.push({ file, kind: 'skill' });
  if (ctx.flags.mentionsLlm && (ctx.flags.isAppRouterRoute || ctx.flags.isPagesApiRoute || ctx.flags.isServerFrameworkFile)) {
    surface.aiEntrypoints.push({ file, line: 1 });
  }
  const auth = AUTH_VERIFICATION_REGEX.test(code) ? 'guard-signal' : 'unknown';
  const add = (method: string, route: string, offset: number): void => {
    surface.routes.push({ file, line: ctx.locate(offset).line, method: method.toUpperCase(), path: route, auth });
  };
  if (ctx.flags.isAppRouterRoute) {
    const route = '/' + file.replace(/^.*?app\//, '').replace(/\/route\.[^.]+$/, '').replace(/\([^/]+\)\/?/g, '');
    for (const match of code.matchAll(/\bexport\s+(?:async\s+function|const|function)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)) add(match[1]!, route.replace(/\/$/, '') || '/', match.index!);
  } else if (ctx.flags.isPagesApiRoute) {
    add('ANY', '/' + file.replace(/^.*?pages\//, '').replace(/\.[^.]+$/, '').replace(/\/index$/, ''), 0);
  }
  for (const match of code.matchAll(/\b(?:app|router|server|fastify)\.(get|post|put|patch|delete|all)\s*\(\s*['"]([^'"]+)['"]/gi)) add(match[1]!, match[2]!, match.index!);
}

export function inventoryTables(surface: AttackSurface, project: ProjectContext, scannedPaths: Set<string>): void {
  surface.tables = project.sqlTables.filter(t => scannedPaths.has(t.file) && !t.internal).map(t => ({
    file: t.file, line: t.line, table: t.table, rls: t.rlsEnabled ? 'enabled-signal' : 'not-observed',
  }));
}
