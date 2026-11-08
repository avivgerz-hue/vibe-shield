#!/usr/bin/env node
/**
 * vibe-shield :: MCP handshake probe
 * ----------------------------------
 * Drivers the MCP server over stdio exactly the way a directory crawler
 * (Glama, and friends) does when it introspects a container image:
 *
 *   initialize  ->  notifications/initialized  ->  tools/list
 *
 * Exits 0 only when every assertion below holds, so CI can gate on it.
 *
 * Usage:
 *   node scripts/mcp-handshake.mjs [--command "node dist/bin/vibe-shield.js mcp"]
 *                                  [--expect-tools 3]
 *                                  [--timeout-ms 20000]
 *
 * With no `--command` it launches the compiled CLI in this checkout.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const out = { command: null, expectTools: 3, timeoutMs: 20_000 };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === '--command') {
      out.command = value;
      i += 1;
    } else if (flag === '--expect-tools') {
      out.expectTools = Number(value);
      i += 1;
    } else if (flag === '--timeout-ms') {
      out.timeoutMs = Number(value);
      i += 1;
    } else {
      throw new Error(`unknown argument: ${flag}`);
    }
  }
  return out;
}

/** Split a shell-ish command string, honouring simple quoting. */
function splitCommand(command) {
  return command.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((part) => part.replace(/^["']|["']$/g, '')) ?? [];
}

const REQUESTS = [
  {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'vibe-shield-ci', version: '1.0.0' },
    },
  },
  { jsonrpc: '2.0', method: 'notifications/initialized' },
  { jsonrpc: '2.0', id: 2, method: 'tools/list' },
];

function fail(message, extra = '') {
  console.error(`\n✗ ${message}`);
  if (extra) console.error(extra);
  console.error('\nHandshake FAILED.');
  process.exit(1);
}

const args = parseArgs(process.argv.slice(2));
const [cmd, ...cmdArgs] = args.command
  ? splitCommand(args.command)
  : [process.execPath, path.join(ROOT, 'dist', 'bin', 'vibe-shield.js'), 'mcp'];

console.log(`→ launching: ${cmd} ${cmdArgs.join(' ')}`);

const child = spawn(cmd, cmdArgs, { stdio: ['pipe', 'pipe', 'pipe'] });

let stdout = '';
let stderr = '';
const timer = setTimeout(() => {
  fail(`no complete handshake within ${args.timeoutMs} ms`, `stdout so far:\n${stdout}\nstderr:\n${stderr}`);
}, args.timeoutMs);

// Send every frame up front, newline-delimited, then close stdin once both
// responses have arrived. The server reads line-by-line, so a frame without its
// trailing newline is never dispatched.
child.stdin.write(`${REQUESTS.map((r) => JSON.stringify(r)).join('\n')}\n`);

child.stdout.on('data', (chunk) => {
  stdout += chunk.toString();
  if (stdout.split('\n').filter((line) => line.trim()).length >= 2) {
    child.stdin.end();
  }
});
child.stderr.on('data', (chunk) => {
  stderr += chunk.toString();
});
child.on('error', (error) => {
  clearTimeout(timer);
  fail(`could not start the server: ${error.message}`);
});

child.on('close', (code) => {
  clearTimeout(timer);

  const lines = stdout.split('\n').filter((line) => line.trim());
  if (!lines.length) fail('server produced no stdout', `stderr:\n${stderr}`);

  // stdout is the protocol channel: every line must be a JSON-RPC frame. A
  // stray log line here corrupts the client session.
  const messages = lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      return fail(`stdout line ${index + 1} is not JSON (a log leaked into the protocol channel)`, line);
    }
  });

  const init = messages.find((m) => m.id === 1);
  if (!init) fail('no response to `initialize`', `stdout:\n${stdout}`);
  if (init.error) fail('`initialize` returned an error', JSON.stringify(init.error));

  const info = init.result?.serverInfo;
  if (!info?.name) fail('`initialize` result has no serverInfo.name', JSON.stringify(init.result));
  if (!/^\d+\.\d+\.\d+/.test(info.version ?? '')) {
    fail(`serverInfo.version is not a semver string: ${JSON.stringify(info.version)}`);
  }
  if (!init.result?.protocolVersion) fail('`initialize` result has no protocolVersion');

  const list = messages.find((m) => m.id === 2);
  if (!list) fail('no response to `tools/list`', `stdout:\n${stdout}`);
  if (list.error) fail('`tools/list` returned an error', JSON.stringify(list.error));

  const tools = list.result?.tools;
  if (!Array.isArray(tools)) fail('`tools/list` result has no tools array');
  if (tools.length !== args.expectTools) {
    fail(`expected ${args.expectTools} tools, got ${tools.length}: ${tools.map((t) => t.name).join(', ')}`);
  }
  for (const tool of tools) {
    if (!tool.name || !tool.title || !tool.description) {
      fail(`tool is missing name/title/description: ${JSON.stringify(tool).slice(0, 120)}`);
    }
    if (!tool.inputSchema || tool.inputSchema.type !== 'object') {
      fail(`tool \`${tool.name}\` has no object inputSchema`);
    }
  }

  if (code !== 0) fail(`server exited with code ${code} after the handshake`, `stderr:\n${stderr}`);

  console.log(`✓ initialize   serverInfo ${info.name} v${info.version} (protocol ${init.result.protocolVersion})`);
  console.log(`✓ tools/list   ${tools.length} tools: ${tools.map((t) => t.name).join(', ')}`);
  console.log(`✓ stdout       ${messages.length} JSON-RPC frames, no stray output`);
  console.log(`✓ exit         ${code}`);
  console.log('\nHandshake OK.');
});
