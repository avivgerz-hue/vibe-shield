#!/usr/bin/env node
/**
 * vibe-shield :: prepare
 * ----------------------
 * Runs on every `npm install` of this package, including a bare git install
 * (`npx github:avivgerz-hue/vibe-shield`) where devDependencies may not be
 * present.
 *
 * `dist/` is committed, so a git install already has a runnable CLI. Today's
 * release therefore copies the build output into place instead of requiring
 * TypeScript:
 *
 *   - dist/ present (the committed build)      → nothing to do, exit 0
 *   - dist/ missing, no `typescript` available → warn, exit 0 (never fail an
 *                                                 install over a build step)
 *   - dist/ missing, `typescript` available    → compile
 *
 * Exiting non-zero here would abort the user's install, which is a far worse
 * outcome than a stale build they can refresh with `npm run build`.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import * as path from 'node:path';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const binPath = path.join(root, 'dist', 'bin', 'vibe-shield.js');

const log = (message) => process.stderr.write(`vibe-shield prepare: ${message}\n`);

if (existsSync(binPath)) {
  // The normal path for every published install and every GitHub install:
  // the committed build is already here, so the CLI is ready instantly.
  process.exit(0);
}

log('dist/ is missing — attempting a local build.');

const localTsc = path.join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'tsc.cmd' : 'tsc');
if (!existsSync(localTsc)) {
  log('TypeScript is not installed here (no devDependencies), and the committed dist/ is missing.');
  log('The CLI will not run until you build it:');
  log('  npm ci && npm run build');
  // Never fail someone's install over this: an exit code here aborts `npm install`.
  process.exit(0);
}

try {
  execFileSync(localTsc, ['-p', 'tsconfig.build.json'], { cwd: root, stdio: 'inherit' });
  execFileSync(process.execPath, [path.join(root, 'scripts', 'postbuild.mjs')], { cwd: root, stdio: 'inherit' });
} catch (error) {
  log(`build failed (${error instanceof Error ? error.message : String(error)}).`);
  log('Run `npm run build` to see the full compiler output.');
}
process.exit(0);
