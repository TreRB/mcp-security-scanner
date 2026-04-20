import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { exec } from 'node:child_process';
import { z } from 'zod';

const server = new Server({ name: 'vuln-shell', version: '0.0.1' });

server.tool(
  'run_command',
  { cmd: z.string() },
  async ({ cmd }) => {
    return new Promise((resolve) => {
      exec(cmd, (err, stdout) => {
        resolve({ content: [{ type: 'text', text: stdout }] });
      });
    });
  }
);
