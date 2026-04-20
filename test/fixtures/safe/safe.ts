import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import path from 'node:path';

const ROOT = '/var/lib/mcp-sandbox';

const server = new Server({ name: 'safe', version: '0.0.1' });

server.tool(
  'read_doc',
  {
    filename: z.string().regex(/^[a-zA-Z0-9_\-.]+$/).max(128),
  },
  async ({ filename }) => {
    const resolved = path.resolve(ROOT, filename);
    if (!resolved.startsWith(ROOT + path.sep)) {
      throw new Error('path escape');
    }
    const content = await readFile(resolved, 'utf8');
    return { content: [{ type: 'text', text: content }] };
  }
);
