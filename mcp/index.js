#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const BASE_URL = process.env.ZEROCREDS_URL ?? "https://zerocreds.ru";
const TOKEN = process.env.ZEROCREDS_TOKEN ?? "";

const server = new McpServer({
  name: "zerocreds",
  version: "0.1.0",
});

async function apiPost(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (TOKEN) headers["Authorization"] = `Bearer ${TOKEN}`;
  const res = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`ZeroCreds ${res.status}: ${text}`);
  }
  return res.json();
}

async function apiGet(path) {
  const headers = {};
  if (TOKEN) headers["Authorization"] = `Bearer ${TOKEN}`;
  const res = await fetch(`${BASE_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`ZeroCreds ${res.status}`);
  return res.json();
}

async function pollStatus(token, intervalMs = 5000, timeoutMs = 600_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const data = await apiGet(`/api/session/${token}/status`);
    if (data.status !== "pending") return data.status;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return "timeout";
}

const FieldSchema = z.object({
  name: z.string().describe("Field key, e.g. 'token' or 'username'"),
  label: z.string().describe("Label shown to the user"),
  type: z
    .enum(["text", "password", "email", "tel", "number", "textarea", "url"])
    .optional()
    .default("text"),
  placeholder: z.string().optional(),
  required: z.boolean().optional().default(true),
});

server.tool(
  "collect_credentials",
  "Ask the user to fill in credentials via a secure web form. The user fills the form directly — the values never pass through the LLM. Returns when credentials are saved.",
  {
    title: z.string().describe("Form heading shown to the user, e.g. 'Connect GitHub'"),
    description: z.string().optional().describe("Subtext on the form"),
    fields: z.array(FieldSchema).min(1).describe("Fields to collect"),
    destination: z
      .string()
      .optional()
      .default("local-dev")
      .describe("Named destination from zerocreds-destinations.json, or 'local-dev'"),
    ttl_minutes: z.number().optional().default(30).describe("Link expiry in minutes"),
    notify_tg_bot_token: z.string().optional().describe("Telegram bot token to send the link"),
    notify_tg_chat_id: z.string().optional().describe("Telegram chat_id to send the link"),
  },
  async ({ title, description, fields, destination, ttl_minutes, notify_tg_bot_token, notify_tg_chat_id }) => {
    const body = { title, fields, destination, ttl_minutes };
    if (description) body.description = description;
    if (notify_tg_bot_token && notify_tg_chat_id) {
      body.notify = { tg_bot_token: notify_tg_bot_token, tg_chat_id: notify_tg_chat_id };
    }

    let session;
    try {
      session = await apiPost("/api/session/create", body);
    } catch (err) {
      return { content: [{ type: "text", text: `❌ Failed to create session: ${err.message}` }] };
    }

    const formUrl = session.url ?? `${BASE_URL}/f/${session.token}`;

    // Tell Claude to show the URL to the user, then we poll
    const status = await pollStatus(session.token);

    if (status === "done") {
      return {
        content: [
          {
            type: "text",
            text: `✅ Credentials collected successfully.\n\nForm URL was: ${formUrl}\nSession: ${session.token}\nDestination: ${destination}`,
          },
        ],
      };
    }

    return {
      content: [
        {
          type: "text",
          text: `⚠️ Credential collection ${status}.\n\nForm URL: ${formUrl}\nPlease ask the user to fill in the form and try again if needed.`,
        },
      ],
    };
  }
);

// Separate tool just to get the form URL without waiting — useful if the agent
// wants to send the link via Telegram or email itself and poll separately.
server.tool(
  "create_credential_form",
  "Create a credential collection form and return its URL immediately, without waiting for the user to fill it.",
  {
    title: z.string(),
    description: z.string().optional(),
    fields: z.array(FieldSchema).min(1),
    destination: z.string().optional().default("local-dev"),
    ttl_minutes: z.number().optional().default(30),
  },
  async ({ title, description, fields, destination, ttl_minutes }) => {
    const body = { title, fields, destination, ttl_minutes };
    if (description) body.description = description;

    let session;
    try {
      session = await apiPost("/api/session/create", body);
    } catch (err) {
      return { content: [{ type: "text", text: `❌ Failed: ${err.message}` }] };
    }

    const formUrl = session.url ?? `${BASE_URL}/f/${session.token}`;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ url: formUrl, token: session.token, expires_at: session.expires_at }),
        },
      ],
    };
  }
);

server.tool(
  "check_credential_status",
  "Check whether a credential form has been filled by the user.",
  {
    session_token: z.string().describe("The session token returned by create_credential_form"),
  },
  async ({ session_token }) => {
    try {
      const data = await apiGet(`/api/session/${session_token}/status`);
      return { content: [{ type: "text", text: JSON.stringify(data) }] };
    } catch (err) {
      return { content: [{ type: "text", text: `❌ ${err.message}` }] };
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
