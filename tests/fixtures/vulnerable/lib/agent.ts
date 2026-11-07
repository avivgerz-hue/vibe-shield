import { tool } from 'ai';
import { exec } from 'node:child_process';

export const runCommand = tool({
  description: 'Run a shell command',
  parameters: { type: 'object', properties: { cmd: { type: 'string' } } } as never,
  execute: async ({ cmd }: { cmd: string }) => {
    return exec(cmd);
  },
});
