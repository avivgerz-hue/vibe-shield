#!/usr/bin/env node
/**
 * vibe-shield :: postbuild
 * ------------------------
 * `tsc` emits the CLI without the executable bit and without a guaranteed
 * shebang on every platform, which breaks `npx vibe-shield` and `npm link`.
 * This script fixes both, then asserts that the entry points really exist so a
 * silent build regression fails here instead of at the user's shell.
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const binPath = join(root, 'dist', 'bin', 'vibe-shield.js');
const indexPath = join(root, 'dist', 'src', 'index.js');
const SHEBANG = '#!/usr/bin/env node';

const fail = (message) => {
  process.stderr.write(`postbuild: ${message}\n`);
  process.exit(1);
};

if (!existsSync(binPath)) fail(`missing ${binPath} — did \`tsc -p tsconfig.build.json\` run?`);
if (!existsSync(indexPath)) fail(`missing ${indexPath} — check the \`include\` list in tsconfig.build.json`);

// 1. Guarantee the shebang is the first line.
const source = readFileSync(binPath, 'utf8');
if (!source.startsWith('#!')) {
  writeFileSync(binPath, `${SHEBANG}\n${source}`, 'utf8');
}

// 2. Make it executable (no-op on Windows, harmless there).
try {
  chmodSync(binPath, 0o755);
} catch {
  // Windows: POSIX permissions do not exist.
}

// 3. Ship a CommonJS marker so Node never guesses the module system wrong when
//    the package is installed into an ESM-only consumer.
writeFileSync(join(root, 'dist', 'package.json'), `${JSON.stringify({ type: 'commonjs' }, null, 2)}\n`, 'utf8');

// 4. Fail loudly if the compiled CLI lost its self-execution guard.
const compiled = readFileSync(binPath, 'utf8');
if (!compiled.includes('require.main === module')) {
  fail('compiled CLI is missing its `require.main === module` guard');
}

process.stdout.write(`postbuild: ${binPath.replace(root + '/', '')} is executable\n`);
