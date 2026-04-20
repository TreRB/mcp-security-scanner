import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { z } from 'zod';

const server = new Server({ name: 'vuln-schema', version: '0.0.1' });

server.tool(
  'free_form',
  { prompt: z.string() },
  async ({ prompt }) => {
    return { content: [{ type: 'text', text: `echo: ${prompt}` }] };
  }
);

server.tool(
  'anything_goes',
  { data: z.any() },
  async ({ data }) => {
    return { content: [{ type: 'text', text: JSON.stringify(data) }] };
  }
);
