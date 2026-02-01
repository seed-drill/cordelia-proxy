#!/usr/bin/env node
/**
 * Seed L1 hot context for a new user directly via storage + crypto layers.
 *
 * Bypasses MCP (which requires an existing user for write_hot) and writes
 * the initial L1 context directly to SQLite with encryption.
 *
 * Usage: CORDELIA_ENCRYPTION_KEY="..." node scripts/seed-l1.mjs <user_id>
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const distDir = join(__dirname, '..', 'dist');

// Import compiled modules from dist/
const { initStorageProvider, getStorageProvider } = await import(join(distDir, 'storage.js'));
const { initCrypto, getDefaultCryptoProvider } = await import(join(distDir, 'crypto.js'));
const { getMemoryRoot, getEncryptionKey } = await import(join(__dirname, '..', 'hooks', 'lib.mjs'));

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
  const passphrase = await getEncryptionKey();
  const memoryRoot = await getMemoryRoot();

  // Initialize storage (SQLite)
  process.env.CORDELIA_STORAGE = process.env.CORDELIA_STORAGE || 'sqlite';
  await initStorageProvider(memoryRoot);
  const storage = getStorageProvider();

  // Check if L1 already exists
  const existing = await storage.readL1(userId);
  if (existing) {
    console.log(`L1 context already exists for ${userId} - skipping seed`);
    await storage.close();
    process.exit(0);
  }

  // Initialize crypto
  const saltPath = join(memoryRoot, 'L2-warm', '.salt', 'global.salt');
  const salt = readFileSync(saltPath);
  await initCrypto(passphrase, salt);
  const crypto = getDefaultCryptoProvider();

  // Encrypt and write L1
  const plaintext = Buffer.from(JSON.stringify(l1Template, null, 2), 'utf-8');
  let fileContent;
  if (crypto.isUnlocked() && crypto.name !== 'none') {
    const encrypted = await crypto.encrypt(plaintext);
    fileContent = JSON.stringify(encrypted, null, 2);
  } else {
    fileContent = JSON.stringify(l1Template, null, 2);
  }

  await storage.writeL1(userId, Buffer.from(fileContent, 'utf-8'));
  console.log(`L1 context seeded for ${userId}`);

  await storage.close();
  process.exit(0);
} catch (err) {
  console.error(`Failed to seed L1: ${err.message}`);
  process.exit(1);
}
