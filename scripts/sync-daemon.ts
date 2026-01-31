#!/usr/bin/env npx tsx
/**
 * Cordelia Sync Daemon
 *
 * Automatically syncs local L1 hot context with remote server every 30 seconds.
 * Uses updated_at timestamps to determine sync direction.
 * Validates uploads with MD5 hash and updates chain_hash for integrity.
 *
 * Usage:
 *   CORDELIA_API_KEY=ck_xxx npx tsx scripts/sync-daemon.ts [userId]
 *
 * Or run via npm:
 *   CORDELIA_API_KEY=ck_xxx npm run sync
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const REMOTE_URL = process.env.CORDELIA_REMOTE_URL || 'https://cordelia-seed-drill.fly.dev';
const API_KEY = process.env.CORDELIA_API_KEY;
const SYNC_INTERVAL = parseInt(process.env.CORDELIA_SYNC_INTERVAL || '30000', 10); // 30 seconds
const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(import.meta.dirname, '..', 'memory');

// Get user ID from args or default to budgester
const userId = process.argv[2] || 'budgester';
const localPath = path.join(MEMORY_ROOT, 'L1-hot', `${userId}.json`);

interface Integrity {
  chain_hash: string;
  previous_hash: string;
  genesis: string;
}

interface Ephemeral {
  session_count: number;
  current_session_start: string;
  last_session_end: string | null;
  last_summary: string | null;
  open_threads: string[];
  vessel: string | null;
  integrity: Integrity;
  last_sync_check?: string;
}

interface L1HotContext {
  version: number;
  updated_at: string;
  identity: Record<string, unknown>;
  active: Record<string, unknown>;
  prefs: Record<string, unknown>;
  delegation: Record<string, unknown>;
  ephemeral?: Ephemeral;
}

let lastSyncedAt: string | null = null;
let syncInProgress = false;

function log(message: string, level: 'info' | 'warn' | 'error' | 'success' = 'info') {
  const timestamp = new Date().toISOString();
  const prefix = level === 'error' ? '✗' : level === 'warn' ? '⚠' : level === 'success' ? '✓' : '↔';
  console.log(`[${timestamp}] ${prefix} ${message}`);
}

/**
 * Deep sort object keys for consistent hashing
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Compute MD5 hash of content (excluding integrity fields to avoid circular dependency)
 */
function computeContentHash(context: L1HotContext): string {
  // Create a copy without the integrity block for hashing
  const hashable = {
    version: context.version,
    identity: context.identity,
    active: context.active,
    prefs: context.prefs,
    delegation: context.delegation,
    ephemeral: context.ephemeral ? {
      session_count: context.ephemeral.session_count,
      current_session_start: context.ephemeral.current_session_start,
      last_session_end: context.ephemeral.last_session_end,
      last_summary: context.ephemeral.last_summary,
      open_threads: context.ephemeral.open_threads,
      vessel: context.ephemeral.vessel,
      // Exclude integrity from hash computation
    } : undefined,
  };

  // Deep sort keys for consistent hashing
  const sorted = sortObjectKeys(hashable);
  const content = JSON.stringify(sorted);
  return crypto.createHash('md5').update(content).digest('hex');
}

/**
 * Compute new chain hash: SHA256(previous_hash + content_hash + timestamp)
 */
function computeChainHash(previousHash: string, contentHash: string, timestamp: string): string {
  const input = `${previousHash}:${contentHash}:${timestamp}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Update context with new integrity information
 */
function updateIntegrity(context: L1HotContext): L1HotContext {
  const now = new Date().toISOString();
  const contentHash = computeContentHash(context);

  const previousHash = context.ephemeral?.integrity?.chain_hash ||
    '0000000000000000000000000000000000000000000000000000000000000000';

  const newChainHash = computeChainHash(previousHash, contentHash, now);

  return {
    ...context,
    updated_at: now,
    ephemeral: {
      ...context.ephemeral!,
      integrity: {
        ...context.ephemeral!.integrity,
        previous_hash: previousHash,
        chain_hash: newChainHash,
      },
    },
  };
}

async function loadLocal(): Promise<L1HotContext | null> {
  try {
    if (!fs.existsSync(localPath)) {
      return null;
    }
    const content = fs.readFileSync(localPath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    log(`Failed to load local: ${(error as Error).message}`, 'error');
    return null;
  }
}

async function saveLocal(context: L1HotContext): Promise<void> {
  const dir = path.dirname(localPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(localPath, JSON.stringify(context, null, 2));
}

async function loadRemote(): Promise<L1HotContext | null> {
  try {
    const response = await fetch(`${REMOTE_URL}/api/hot/${userId}`);
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    log(`Failed to load remote: ${(error as Error).message}`, 'error');
    return null;
  }
}

async function saveRemote(context: L1HotContext): Promise<{ success: boolean; hash?: string }> {
  if (!API_KEY) {
    log('No API key configured - cannot push to remote', 'warn');
    return { success: false };
  }

  // Compute hash before upload
  const uploadHash = computeContentHash(context);
  log(`Upload hash: ${uploadHash.substring(0, 8)}...`);

  try {
    const response = await fetch(`${REMOTE_URL}/api/hot/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify(context),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(error.error || response.statusText);
    }

    // Verify upload by fetching and comparing hash
    const remoteAfter = await loadRemote();
    if (!remoteAfter) {
      throw new Error('Failed to verify upload - could not fetch remote');
    }

    const remoteHash = computeContentHash(remoteAfter);
    if (remoteHash !== uploadHash) {
      throw new Error(`Hash mismatch after upload: expected ${uploadHash}, got ${remoteHash}`);
    }

    log(`Verified: ${remoteHash.substring(0, 8)}...`, 'success');
    return { success: true, hash: uploadHash };
  } catch (error) {
    log(`Failed to save remote: ${(error as Error).message}`, 'error');
    return { success: false };
  }
}

async function sync(): Promise<void> {
  if (syncInProgress) {
    return;
  }

  syncInProgress = true;

  try {
    const [local, remote] = await Promise.all([loadLocal(), loadRemote()]);

    // No data anywhere
    if (!local && !remote) {
      log('No local or remote data found');
      return;
    }

    // Update last_sync_check timestamp on local file
    const updateLastSyncCheck = async (context: L1HotContext) => {
      const now = new Date().toISOString();
      if (context.ephemeral) {
        context.ephemeral.last_sync_check = now;
      }
      await saveLocal(context);
    };

    // Only local exists - push to remote
    if (local && !remote) {
      log(`Pushing local to remote (remote empty)`);
      const updated = updateIntegrity(local);
      const result = await saveRemote(updated);
      if (result.success) {
        await saveLocal(updated); // Save updated integrity locally
        lastSyncedAt = updated.updated_at;
        log(`Synced: local → remote (${userId}) [${updated.ephemeral?.integrity.chain_hash.substring(0, 8)}...]`, 'success');
      }
      return;
    }

    // Only remote exists - pull to local
    if (!local && remote) {
      log(`Pulling remote to local (local empty)`);
      await saveLocal(remote);
      lastSyncedAt = remote.updated_at;
      log(`Synced: remote → local (${userId})`, 'success');
      return;
    }

    // Both exist - compare timestamps
    const localTime = new Date(local!.updated_at).getTime();
    const remoteTime = new Date(remote!.updated_at).getTime();

    // Also compare content hashes to detect changes
    const localHash = computeContentHash(local!);
    const remoteHash = computeContentHash(remote!);

    if (localTime === remoteTime && localHash === remoteHash) {
      // Already in sync - just update last_sync_check
      if (lastSyncedAt !== local!.updated_at) {
        log(`In sync (${userId}) [${localHash.substring(0, 8)}...]`);
        lastSyncedAt = local!.updated_at;
      }
      await updateLastSyncCheck(local!);
      return;
    }

    // Content differs - determine direction by timestamp
    if (localTime > remoteTime || (localTime === remoteTime && localHash !== remoteHash)) {
      // Local is newer or has different content - push
      log(`Local changed (hash: ${localHash.substring(0, 8)}... vs ${remoteHash.substring(0, 8)}...)`);
      const updated = updateIntegrity(local!);
      const result = await saveRemote(updated);
      if (result.success) {
        await saveLocal(updated); // Save updated integrity locally
        lastSyncedAt = updated.updated_at;
        log(`Synced: local → remote (${userId}) [${updated.ephemeral?.integrity.chain_hash.substring(0, 8)}...]`, 'success');
      }
    } else {
      // Remote is newer - pull
      log(`Remote newer (${remote!.updated_at} > ${local!.updated_at})`);
      await saveLocal(remote!);
      lastSyncedAt = remote!.updated_at;
      log(`Synced: remote → local (${userId}) [${remoteHash.substring(0, 8)}...]`, 'success');
    }
  } catch (error) {
    log(`Sync error: ${(error as Error).message}`, 'error');
  } finally {
    syncInProgress = false;
  }
}

async function main() {
  if (!API_KEY) {
    log('Warning: CORDELIA_API_KEY not set - will only pull, not push', 'warn');
  }

  log(`Starting sync daemon for user: ${userId}`);
  log(`Local path: ${localPath}`);
  log(`Remote URL: ${REMOTE_URL}`);
  log(`Sync interval: ${SYNC_INTERVAL / 1000}s`);
  log('');

  // Initial sync
  await sync();

  // Periodic sync
  setInterval(sync, SYNC_INTERVAL);

  // Handle shutdown
  process.on('SIGINT', () => {
    log('Shutting down...');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    log('Shutting down...');
    process.exit(0);
  });
}

main().catch((error) => {
  log(`Fatal error: ${error.message}`, 'error');
  process.exit(1);
});
