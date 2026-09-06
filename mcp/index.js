'use strict';

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

const BASE_URL = (process.env.ZEROCREDS_URL || 'https://zerocreds.ru').replace(/\/$/, '');
const ADMIN_TOKEN = process.env.ZEROCREDS_ADMIN_TOKEN || '';

async function apiCall(method, path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${ADMIN_TOKEN}`,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
}

const server = new McpServer({
  name: 'zerocreds',
  version: '0.1.0',
});

server.tool(
  'zerocreds_create_session',
  'Create a ZeroCreds credential-collection session. Returns a one-time URL to send to the user. The user fills in credentials directly — the agent never sees them.',
  {
    title: z.string().describe('Heading shown on the form (e.g. "Connect GitHub")'),
    description: z.string().optional().describe('Subtext explaining what credentials are needed and why'),
    fields: z.array(z.object({
      name: z.string().describe('Key in the saved credentials JSON (alphanumeric + underscore)'),
      label: z.string().describe('Label shown on the form'),
      type: z.enum(['text', 'password', 'email', 'tel', 'number', 'textarea', 'url']).optional().describe('Input type (default: text)'),
      placeholder: z.string().optional(),
      required: z.boolean().optional(),
    })).describe('List of fields to collect'),
    destination: z.union([
      z.string().describe('Named destination from zerocreds-destinations.json'),
      z.object({
        type: z.enum(['local_file', 'gcp_secret_manager', 'aws_secrets_manager', 'vault']),
        uid: z.string().optional(),
        filename: z.string().optional(),
      }).passthrough().describe('Inline destination config'),
    ]).describe('Where to save the credentials'),
    ttl_minutes: z.number().int().min(1).max(1440).optional().describe('Link expiry in minutes (default: 30)'),
    notify: z.object({
      tg_bot_token: z.string(),
      tg_chat_id: z.string(),
    }).optional().describe('Send the form link via Telegram automatically'),
  },
  async ({ title, description, fields, destination, ttl_minutes, notify }) => {
    const data = await apiCall('POST', '/api/session/create', {
      title,
      description,
      fields,
      destination,
      ttl_minutes,
      notify,
    });
    if (data.error) throw new Error(data.error);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          token: data.token,
          url: data.url,
          expires_at: data.expires_at,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  'zerocreds_check_status',
  'Check whether the user has submitted the ZeroCreds form. Poll every 5–10 seconds until status is "done" or "expired".',
  {
    token: z.string().describe('Session token returned by zerocreds_create_session'),
  },
  async ({ token }) => {
    const data = await apiCall('GET', `/api/session/${token}/status`);
    if (data.error) throw new Error(data.error);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(data, null, 2),
      }],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  console.error('ZeroCreds MCP error:', err);
  process.exit(1);
});
