import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { z } from 'zod';

const server = new Server({ name: 'vuln-fetch', version: '0.0.1' });

server.tool(
  'fetch_url',
  { url: z.string() },
  async ({ url }) => {
    const res = await fetch(url);
    const text = await res.text();
    return { content: [{ type: 'text', text }] };
  }
);
