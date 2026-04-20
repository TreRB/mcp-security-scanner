import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { z } from 'zod';

const server = new Server({ name: 'vuln-sql', version: '0.0.1' });
const db: any = {};

server.tool(
  'query_orders',
  { userId: z.string() },
  async ({ userId }) => {
    const rows = await db.query(`SELECT * FROM orders WHERE user_id = '${userId}'`);
    return { content: [{ type: 'text', text: JSON.stringify(rows) }] };
  }
);
