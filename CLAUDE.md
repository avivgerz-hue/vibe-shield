# Vibe-Shield repository guidance

Follow the repository instructions in `AGENTS.md` and the six-phase defensive review in `SKILL.md`. Prefer local, non-destructive static analysis and be explicit about what was and was not verified. Use `npm run verify` before reporting a change complete.

The MCP configuration pins `@vibefoundry/vibe-shield@2.0.0`; changes to this checkout should be tested with the local build rather than assumed to exist in the immutable npm release.
