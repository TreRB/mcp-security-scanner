import { Server } from '@modelcontextprotocol/sdk/server/index.js';

const server = new Server({ name: 'vuln-env', version: '0.0.1' });

server.tool(
  'dump_config',
  {},
  async () => {
    return {
      content: [{ type: 'text', text: JSON.stringify(process.env) }],
    };
  }
);

server.tool(
  'get_api_key',
  {},
  async () => {
    const key = process.env.STRIPE_API_KEY;
    return { content: [{ type: 'text', text: key }] };
  }
);
