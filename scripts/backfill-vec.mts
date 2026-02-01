#!/usr/bin/env node
/**
 * Backfill l2_vec table from existing L2 index entries.
 * Usage: node --import tsx scripts/backfill-vec.mts
 */

import { initStorageProvider, getStorageProvider } from '../src/storage.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from '../src/crypto.js';
import { backfillVec, loadIndex, search } from '../src/l2.js';
import type { SqliteStorageProvider } from '../src/storage-sqlite.js';
import * as path from 'path';

const memRoot = process.env.CORDELIA_MEMORY_ROOT || path.join(
  path.dirname(new URL(import.meta.url).pathname), '..', 'memory'
);

// Init storage
const storage = await initStorageProvider(memRoot);
console.log(`Storage: ${storage.name}`);

// Init encryption
const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
if (passphrase) {
  const config = getCryptoConfig(memRoot);
  if (config.enabled) {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Encryption: enabled');
  }
} else {
  console.log('Encryption: disabled (no CORDELIA_ENCRYPTION_KEY)');
}

// Check pre-state
const sqliteStorage = getStorageProvider() as SqliteStorageProvider;
const index = await loadIndex();
console.log(`\nPre-backfill state:`);
console.log(`  Index entries: ${index.entries.length}`);
console.log(`  sqlite-vec available: ${sqliteStorage.vecAvailable()}`);
console.log(`  Embedding cache (DB): ${sqliteStorage.embeddingCacheCount()}`);
console.log(`  Vec rows: ${sqliteStorage.vecCount()}`);

if (!sqliteStorage.vecAvailable()) {
  console.error('\nERROR: sqlite-vec not available. Cannot backfill.');
  process.exit(1);
}

// Backfill
console.log('\nRunning backfill...');
const result = await backfillVec();
console.log(`\nBackfill complete:`);
console.log(`  Total entries: ${result.total}`);
console.log(`  From cache: ${result.cached}`);
console.log(`  Generated (Ollama): ${result.generated}`);
console.log(`  Skipped: ${result.skipped}`);
console.log(`  Errors: ${result.errors}`);
console.log(`  Vec rows now: ${sqliteStorage.vecCount()}`);

// Debug: check FTS state
console.log(`\nFTS count: ${sqliteStorage.hasFtsData()}`);
console.log(`FTS rows: ${(sqliteStorage as any).db.prepare('SELECT COUNT(*) as cnt FROM l2_fts').get().cnt}`);

// Verification searches
for (const q of ['Manchester Hinton', '386', '386DX33', 'Reagan movie actor']) {
  console.log(`\n--- Search: "${q}" ---`);
  const results = await search({ query: q, limit: 5 });
  for (const r of results) {
    console.log(`  [${r.score.toFixed(3)}] ${r.name} (${r.type}${r.subtype ? '/' + r.subtype : ''}) - ${r.id}`);
  }
  if (results.length === 0) console.log('  No results');
}

await storage.close();
