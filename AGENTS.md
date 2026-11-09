# Repository security guidance

This repository develops the Vibe-Shield static security auditor. Preserve existing functionality and avoid destructive operations when making changes. Findings and attack-surface labels are heuristics, not proof of security; report limitations and false positives honestly.

Before completing changes, run `npm run verify`. For agent or MCP configuration changes, also run `node dist/bin/vibe-shield.js audit-skills --fail-on high`. Never weaken checks merely to achieve a clean score; ask the user to rotate exposed credentials.

The root MCP configuration pins `@vibefoundry/vibe-shield@2.1.0` (verify availability on npm before use); the local `dist/` build is the source of truth for changes in this checkout.
