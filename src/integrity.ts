/**
 * Project Cordelia - Integrity Module (R2-014)
 *
 * Provides integrity verification for the memory system:
 * - L1 chain hash verification (extracted from session-start.mjs)
 * - L2 item checksum verification
 * - Integrity canary (storage corruption detection)
 * - Periodic integrity check with report
 */

import * as crypto from 'crypto';
import { getStorageProvider } from './storage.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

export interface IntegrityReport {
  ok: boolean;
  timestamp: string;
  checks: {
    database: { ok: boolean; errors: string[] };
    chainHash: { ok: boolean; errors: string[] };
    canary: { ok: boolean; errors: string[] };
    checksums: { ok: boolean; errors: string[]; checked: number; failed: number };
  };
}

/**
 * Compute content hash of L1 data (excluding integrity block).
 * Mirrors hooks/lib.mjs computeContentHash for consistency.
 */
export function computeContentHash(l1Data: Record<string, unknown>): string {
  const dataWithoutIntegrity = { ...l1Data };
  if (dataWithoutIntegrity.ephemeral && typeof dataWithoutIntegrity.ephemeral === 'object') {
    dataWithoutIntegrity.ephemeral = { ...(dataWithoutIntegrity.ephemeral as Record<string, unknown>) };
    delete (dataWithoutIntegrity.ephemeral as Record<string, unknown>).integrity;
  }
  const content = JSON.stringify(dataWithoutIntegrity);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Compute chain hash: SHA256(previous_hash + session_count + content_hash).
 * Mirrors hooks/lib.mjs computeChainHash for consistency.
 */
export function computeChainHash(previousHash: string, sessionCount: number, contentHash: string): string {
  const input = `${previousHash}${sessionCount}${contentHash}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Verify the integrity chain hash for a user's L1 hot context.
 * Recomputes the chain hash and compares to stored value.
 */
export async function verifyChainHash(userId: string): Promise<{ ok: boolean; errors: string[] }> {
  const errors: string[] = [];
  const storage = getStorageProvider();

  const buffer = await storage.readL1(userId);
  if (!buffer) {
    return { ok: false, errors: [`No L1 data found for user: ${userId}`] };
  }

  let l1Data: Record<string, unknown>;
  try {
    l1Data = JSON.parse(buffer.toString('utf-8'));
  } catch {
    return { ok: false, errors: ['Failed to parse L1 data as JSON'] };
  }

  // Handle encrypted payloads -- cannot verify without decryption key
  if (l1Data._encrypted === true) {
    return { ok: true, errors: ['L1 data is encrypted - chain verification requires decryption (skipped)'] };
  }

  const ephemeral = l1Data.ephemeral as Record<string, unknown> | undefined;
  if (!ephemeral) {
    return { ok: true, errors: [] }; // No ephemeral data (pre-S7)
  }

  const integrity = ephemeral.integrity as { chain_hash: string; previous_hash: string; genesis: string } | undefined;
  if (!integrity) {
    errors.push('Missing integrity block in ephemeral data');
    return { ok: false, errors };
  }

  const contentHash = computeContentHash(l1Data);
  const expectedHash = computeChainHash(
    integrity.previous_hash,
    ephemeral.session_count as number,
    contentHash,
  );

  if (expectedHash !== integrity.chain_hash) {
    errors.push(`Chain hash mismatch: expected ${expectedHash}, got ${integrity.chain_hash}`);
    return { ok: false, errors };
  }

  return { ok: true, errors: [] };
}

/**
 * Verify a specific L2 item's checksum matches its stored data.
 * Requires SQLite provider (checksums stored in v3 schema).
 */
export async function verifyItem(itemId: string): Promise<{ ok: boolean; errors: string[] }> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    return { ok: true, errors: ['Checksum verification requires SQLite provider'] };
  }

  const db = (storage as SqliteStorageProvider).getDatabase();
  const row = db.prepare('SELECT data, checksum FROM l2_items WHERE id = ?').get(itemId) as
    { data: Buffer; checksum: string | null } | undefined;

  if (!row) {
    return { ok: false, errors: [`Item not found: ${itemId}`] };
  }

  if (!row.checksum) {
    return { ok: true, errors: ['No checksum stored for this item (pre-v3)'] };
  }

  const computed = crypto.createHash('sha256').update(row.data).digest('hex');
  if (computed !== row.checksum) {
    return { ok: false, errors: [`Checksum mismatch: expected ${row.checksum}, got ${computed}`] };
  }

  return { ok: true, errors: [] };
}

/**
 * Verify the integrity canary value is present and readable.
 * The canary is a known value written at server startup. If it's missing
 * or unreadable, storage may be corrupted.
 */
export function canaryCheck(): { ok: boolean; errors: string[] } {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    return { ok: true, errors: ['Canary check requires SQLite provider'] };
  }

  const sqliteProvider = storage as SqliteStorageProvider;
  const value = sqliteProvider.getCanaryValue();

  if (!value) {
    return { ok: false, errors: ['Integrity canary missing or unreadable'] };
  }

  // Verify it's a valid hex string (64 chars = 32 bytes)
  if (!/^[0-9a-f]{64}$/.test(value)) {
    return { ok: false, errors: [`Invalid canary value format: ${value.slice(0, 20)}...`] };
  }

  return { ok: true, errors: [] };
}

/**
 * Run all integrity checks and produce a comprehensive report.
 * Designed for periodic execution (default: 30 min interval).
 */
export async function periodicCheck(userIds?: string[]): Promise<IntegrityReport> {
  const storage = getStorageProvider();
  const now = new Date().toISOString();

  // Database-level integrity
  let dbCheck: { ok: boolean; errors: string[] };
  try {
    dbCheck = await storage.integrityCheck();
  } catch (e) {
    dbCheck = { ok: false, errors: [(e as Error).message] };
  }

  // Chain hash verification for all users
  const chainErrors: string[] = [];
  const users = userIds || await storage.listL1Users();
  for (const userId of users) {
    const result = await verifyChainHash(userId);
    if (!result.ok) {
      chainErrors.push(`${userId}: ${result.errors.join(', ')}`);
    }
  }

  // Canary check
  const canaryResult = canaryCheck();

  // Sample checksum verification (check all items)
  let checksumChecked = 0;
  let checksumFailed = 0;
  const checksumErrors: string[] = [];

  if (storage.name === 'sqlite') {
    const db = (storage as SqliteStorageProvider).getDatabase();
    const items = db.prepare('SELECT id, data, checksum FROM l2_items WHERE checksum IS NOT NULL').all() as
      Array<{ id: string; data: Buffer; checksum: string }>;

    for (const item of items) {
      checksumChecked++;
      const computed = crypto.createHash('sha256').update(item.data).digest('hex');
      if (computed !== item.checksum) {
        checksumFailed++;
        checksumErrors.push(`Item ${item.id}: expected ${item.checksum}, got ${computed}`);
      }
    }
  }

  const allOk = dbCheck.ok && chainErrors.length === 0 && canaryResult.ok && checksumFailed === 0;

  return {
    ok: allOk,
    timestamp: now,
    checks: {
      database: dbCheck,
      chainHash: { ok: chainErrors.length === 0, errors: chainErrors },
      canary: canaryResult,
      checksums: {
        ok: checksumFailed === 0,
        errors: checksumErrors,
        checked: checksumChecked,
        failed: checksumFailed,
      },
    },
  };
}
