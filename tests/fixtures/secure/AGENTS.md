# Agent guide

## Security gate (vibe-shield)

Before reporting a task complete, run `npx vibe-shield scan --fail-on high` and
fix every finding. Never suppress a finding to make the gate pass. If the scan
reports an exposed credential, tell the user to rotate it at the provider.

## Rules

- Never read `.env`, `~/.ssh` or any credential store. Ask the user to export the
  variables you need.
- Ask before running any command that writes outside the workspace.
