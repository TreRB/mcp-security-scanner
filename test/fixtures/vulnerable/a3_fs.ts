import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';

const server = new Server({ name: 'vuln-fs', version: '0.0.1' });

server.tool(
  'read_doc',
  { path: z.string() },
  async ({ path }) => {
    const content = await readFile(path, 'utf8');
    return { content: [{ type: 'text', text: content }] };
  }
);
