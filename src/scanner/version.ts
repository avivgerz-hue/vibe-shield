import { promises as fs } from 'node:fs';
import * as path from 'node:path';

const VERSION = process.env.npm_package_version ?? '1.0.0';

let cachedVersion: string | null = null;

/** Package version, resolved once from the nearest package.json. */
export async function packageVersion(): Promise<string> {
  if (cachedVersion) return cachedVersion;
  let dir = __dirname;
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      const raw = await fs.readFile(path.join(dir, 'package.json'), 'utf8');
      const parsed = JSON.parse(raw) as { name?: string; version?: string };
      // Match the scoped name *or* the legacy bare one, so an install made
      // before the package was published under `@vibefoundry/` still resolves
      // its own version instead of reporting the fallback.
      const isThisPackage = parsed.name === '@vibefoundry/vibe-shield' || parsed.name === 'vibe-shield';
      if (isThisPackage && parsed.version) {
        cachedVersion = parsed.version;
        return cachedVersion;
      }
    } catch {
      // Keep walking up.
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  cachedVersion = VERSION;
  return cachedVersion;
}

