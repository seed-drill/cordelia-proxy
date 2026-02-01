#!/usr/bin/env node
/**
 * Cordelia MCP Client - Hook-side MCP client over SSE
 *
 * Hooks use this to call memory_read_hot / memory_write_hot via the
 * same MCP tool interface that Claude uses. Single store, single API.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

/**
 * Create an MCP client connected to the local HTTP server via SSE.
 * @param {string} baseUrl - e.g. "http://127.0.0.1:3847"
 * @returns {Promise<Client>}
 */
export async function createMcpClient(baseUrl) {
  const transport = new SSEClientTransport(new URL(`${baseUrl}/sse`));
  const client = new Client(
    { name: 'cordelia-hook', version: '1.0.0' },
    { capabilities: {} }
  );
  await client.connect(transport);
  return client;
}

/**
 * Read L1 hot context via MCP.
 * @param {Client} client
 * @param {string} userId
 * @returns {Promise<object|null>}
 */
export async function readL1(client, userId) {
  const result = await client.callTool({
    name: 'memory_read_hot',
    arguments: { user_id: userId },
  });
  const text = result.content?.[0]?.text;
  if (!text) return null;
  const parsed = JSON.parse(text);
  if (parsed.error) return null;
  return parsed;
}

/**
 * Write L1 hot context via MCP.
 * @param {Client} client
 * @param {string} userId
 * @param {'patch'|'replace'} operation
 * @param {object} data
 * @param {string} [expectedUpdatedAt]
 * @returns {Promise<object>}
 */
export async function writeL1(client, userId, operation, data, expectedUpdatedAt) {
  const args = { user_id: userId, operation, data };
  if (expectedUpdatedAt) args.expected_updated_at = expectedUpdatedAt;
  const result = await client.callTool({
    name: 'memory_write_hot',
    arguments: args,
  });
  const text = result.content?.[0]?.text;
  return text ? JSON.parse(text) : null;
}
