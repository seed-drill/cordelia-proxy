#!/usr/bin/env node
/**
 * Cordelia - Domain Backfill Script
 *
 * Re-classifies L2 items by reading through the decryption layer
 * and checking actual subtypes. Promotes learning/principle to value.
 *
 * Usage: CORDELIA_MEMORY_ROOT=/path node --import tsx src/backfill-domains.ts
 */

import * as path from 'path';
import { initStorageProvider } from './storage.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from './crypto.js';
import { backfillDomains } from './l2.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT
  || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');

async function main(): Promise<void> {
  console.log('Cordelia: Domain Backfill');
  console.log('='.repeat(40));

  // Init crypto
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);
  if (config.enabled && passphrase) {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Crypto: initialized (AES-256-GCM)');
  } else {
    console.log('WARNING: Encryption not initialized - encrypted items will error');
  }

  // Init storage
  const provider = await initStorageProvider(MEMORY_ROOT);
  console.log(`Storage: ${provider.name}`);

  // Domain counts before
  if (provider.name === 'sqlite') {
    const counts = await (provider as SqliteStorageProvider).getDomainCounts();
    console.log(`\nBefore: ${JSON.stringify(counts)}`);
  }

  // Run backfill
  const result = await backfillDomains();
  console.log(`\nBackfill complete:`);
  console.log(`  total:          ${result.total}`);
  console.log(`  reclassified:   ${result.reclassified}`);
  console.log(`  skipped:        ${result.skipped}`);
  console.log(`  errors:         ${result.errors}`);

  if (result.changes.length > 0) {
    console.log(`\n  Changes:`);
    for (const c of result.changes) {
      console.log(`    ${c.id}: ${c.from} -> ${c.to} (${c.reason})`);
    }
  }

  // Domain counts after
  if (provider.name === 'sqlite') {
    const counts = await (provider as SqliteStorageProvider).getDomainCounts();
    console.log(`\nAfter: ${JSON.stringify(counts)}`);
  }

  await provider.close();
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
