#!/usr/bin/env node
/**
 * Cordelia - L2 Index Rebuild Script
 *
 * Rebuilds the L2 search index by scanning all JSON item files on disk.
 * Initializes encryption so encrypted items can be decrypted and re-indexed.
 * Use this to recover from index corruption.
 *
 * Usage: node --import tsx src/rebuild-index.ts
 */

import * as path from 'path';
import { initStorageProvider } from './storage.js';
import { rebuildIndex, loadIndex } from './l2.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from './crypto.js';

const MEMORY_ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');

async function main(): Promise<void> {
  console.log('Cordelia: L2 Index Rebuild');
  console.log('='.repeat(40));

  // Initialize encryption (same as server.ts)
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);

  if (config.enabled && passphrase) {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Encryption initialized (AES-256-GCM)');
  } else {
    console.log('WARNING: Encryption not initialized - encrypted items will be skipped');
  }

  // Initialize storage provider (respects CORDELIA_STORAGE env var)
  const provider = await initStorageProvider(MEMORY_ROOT);
  console.log(`Storage provider initialized (${provider.name})`);

  // Load current index for comparison
  const before = await loadIndex();
  console.log(`Current index: ${before.entries.length} entries`);

  // Rebuild
  const result = await rebuildIndex();

  if ('error' in result) {
    console.error(`Rebuild failed: ${result.error}`);
    process.exit(1);
  }

  // Load rebuilt index
  const after = await loadIndex();
  console.log(`Rebuilt index: ${after.entries.length} entries`);

  // Summary
  console.log('\n' + '='.repeat(40));
  console.log('Rebuilt entries by type:');
  const byType = { entity: 0, session: 0, learning: 0 };
  for (const entry of after.entries) {
    byType[entry.type]++;
  }
  console.log(`  Entities:  ${byType.entity}`);
  console.log(`  Sessions:  ${byType.session}`);
  console.log(`  Learnings: ${byType.learning}`);
  console.log(`  Total:     ${after.entries.length}`);

  // List all entries
  console.log('\nAll indexed entries:');
  for (const entry of after.entries) {
    console.log(`  [${entry.type}] ${entry.id} - ${entry.name}`);
  }
}

try {
  await main();
} catch (error) {
  console.error('Rebuild failed:', error);
  process.exit(1);
}
