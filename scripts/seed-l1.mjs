#!/usr/bin/env node
/**
 * Seed L1 hot context for a new user via the MCP server.
 *
 * Uses the same ensureServer + MCP client path that hooks use,
 * so L1 is written to SQLite through the proper storage layer
 * with encryption.
 *
 * Usage: CORDELIA_ENCRYPTION_KEY="..." node scripts/seed-l1.mjs <user_id>
 */
import { ensureServer } from '../hooks/server-manager.mjs';
import { createMcpClient, readL1, writeL1 } from '../hooks/mcp-client.mjs';
import { getEncryptionKey, getMemoryRoot } from '../hooks/lib.mjs';

const userId = process.argv[2];
if (!userId) {
  console.error('Usage: node scripts/seed-l1.mjs <user_id>');
  process.exit(1);
}

// Capitalize first letter
const userName = userId.charAt(0).toUpperCase() + userId.slice(1);

const l1Template = {
  version: 1,
  updated_at: new Date().toISOString(),
  identity: {
    id: userId,
    name: userName,
    roles: [],
    orgs: [],
    key_refs: [],
    style: [],
    tz: 'Europe/London',
  },
  active: {
    project: null,
    sprint: null,
    focus: 'Getting started with Cordelia',
    blockers: [],
    next: ['Explore Cordelia memory system', 'Configure personal preferences'],
    context_refs: [],
    sprint_plan: {},
    notes: ['Welcome to Cordelia - your AI memory system'],
  },
  prefs: {
    planning_mode: 'important',
    feedback_style: 'continuous',
    verbosity: 'concise',
    emoji: false,
    proactive_suggestions: true,
    auto_commit: false,
  },
  delegation: {
    allowed: true,
    max_parallel: 3,
    require_approval: ['git_push', 'destructive_operations', 'external_api_calls', 'file_delete'],
    autonomous: ['file_read', 'file_write', 'git_commit', 'code_execution_sandbox'],
  },
};

try {
  const passphrase = getEncryptionKey();
  const memoryRoot = await getMemoryRoot();

  // Start sidecar (or connect to existing)
  const { baseUrl } = await ensureServer(passphrase, memoryRoot);

  // Connect MCP client
  const client = await createMcpClient(baseUrl);

  // Check if L1 already exists
  const existing = await readL1(client, userId);
  if (existing) {
    console.log(`L1 context already exists for ${userId} - skipping seed`);
    await client.close();
    process.exit(0);
  }

  // Write L1 via MCP (goes through encryption + SQLite)
  await writeL1(client, userId, 'replace', l1Template);
  console.log(`L1 context seeded for ${userId}`);

  await client.close();
  process.exit(0);
} catch (err) {
  console.error(`Failed to seed L1: ${err.message}`);
  process.exit(1);
}
