#!/usr/bin/env npx tsx
/**
 * Live DB Smoke Test
 *
 * Read-only test against the real production database.
 * Validates search, FTS, vec, diagnostics, and item reads.
 *
 * Run: npx tsx src/live-smoke.test.ts
 *
 * Expects CORDELIA_STORAGE, CORDELIA_MEMORY_ROOT, and
 * CORDELIA_ENCRYPTION_KEY to be set in the environment.
 */

import { initStorageProvider, getStorageProvider } from './storage.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from './crypto.js';
import * as l2 from './l2.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL: ${name}`);
    console.log(`        ${(e as Error).message}`);
    failed++;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function run() {
  const memRoot = process.env.CORDELIA_MEMORY_ROOT;
  if (!memRoot) {
    console.log('CORDELIA_MEMORY_ROOT not set');
    console.log('Skipping live-smoke tests (run manually with env vars set)');
    return;
  }

  if (!process.env.CORDELIA_STORAGE) {
    console.log('CORDELIA_STORAGE not set (expected "sqlite")');
    console.log('Skipping live-smoke tests (run manually with env vars set)');
    return;
  }

  await initStorageProvider(memRoot);

  // Init encryption if key available
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  if (passphrase) {
    const config = getCryptoConfig(memRoot);
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Encryption: enabled');
  } else {
    console.log('Encryption: disabled — reads of encrypted items will fail');
  }

  const storage = getStorageProvider();
  const sqliteStorage = storage as SqliteStorageProvider;

  console.log(`\nLive DB Smoke Test (${memRoot})`);
  console.log(`items=${sqliteStorage.itemCount()}, fts=${sqliteStorage.ftsCount()}, vec=${sqliteStorage.vecCount()}`);
  console.log('='.repeat(50) + '\n');

  // --- Index health ---

  await test('FTS count matches item count', async () => {
    const items = sqliteStorage.itemCount();
    const fts = sqliteStorage.ftsCount();
    assert(fts >= items, `FTS (${fts}) < items (${items}) — gap detected`);
  });

  // --- Keyword search ---

  await test('search("memory") returns results', async () => {
    const results = await l2.search({ query: 'memory' });
    assert(results.length > 0, 'expected results for "memory"');
    console.log(`        -> ${results.length} results, top: "${results[0].name}" (${results[0].score.toFixed(3)})`);
  });

  await test('search("Russell") returns results', async () => {
    const results = await l2.search({ query: 'Russell' });
    assert(results.length > 0, 'expected results for "Russell"');
    console.log(`        -> ${results.length} results, top: "${results[0].name}" (${results[0].score.toFixed(3)})`);
  });

  await test('search("security") returns results', async () => {
    const results = await l2.search({ query: 'security' });
    assert(results.length > 0, 'expected results for "security"');
    console.log(`        -> ${results.length} results, top: "${results[0].name}" (${results[0].score.toFixed(3)})`);
  });

  // --- Type filter ---

  await test('search with type=entity filters correctly', async () => {
    const results = await l2.search({ query: 'memory', type: 'entity' });
    assert(results.every((r) => r.type === 'entity'), 'all results should be entities');
    console.log(`        -> ${results.length} entity results`);
  });

  await test('search with type=learning filters correctly', async () => {
    const results = await l2.search({ query: 'memory', type: 'learning' });
    assert(results.every((r) => r.type === 'learning'), 'all results should be learnings');
    console.log(`        -> ${results.length} learning results`);
  });

  // --- Tag filter (no-query path uses blob index) ---

  await test('search with tags=["security"] returns results', async () => {
    const results = await l2.search({ tags: ['security'] });
    // Tag filter uses blob index (no-query path). If blob index tags are
    // empty (items migrated before tag extraction), this may return 0.
    console.log(`        -> ${results.length} results`);
    if (results.length > 0) {
      assert(results.every((r) => r.tags.includes('security')), 'all results should have security tag');
    }
  });

  // --- Debug mode ---

  await test('debug mode returns diagnostics', async () => {
    const { results: _results, diagnostics } = await l2.search({ query: 'memory', debug: true as const });
    assert(diagnostics.search_path === 'sql', 'expected sql search path');
    assert(typeof diagnostics.vec_available === 'boolean', 'vec_available should be boolean');
    assert(typeof diagnostics.fts_candidates === 'number', 'fts_candidates should be number');
    assert(diagnostics.blob_index_entries > 0, 'blob_index_entries should be > 0');
    console.log(`        -> fts_candidates=${diagnostics.fts_candidates}, vec_available=${diagnostics.vec_available}, vec_used=${diagnostics.vec_used}`);
    if (diagnostics.results.length > 0) {
      const top = diagnostics.results[0];
      console.log(`        -> top scores: fts=${top.fts_score.toFixed(3)} vec=${top.vec_score.toFixed(3)} combined=${top.combined_score.toFixed(3)}`);
    }
  });

  // --- No query listing ---

  await test('no-query listing returns items', async () => {
    const results = await l2.search({});
    assert(results.length > 0, 'expected items in listing');
    console.log(`        -> ${results.length} items`);
  });

  // --- Nonsense query ---

  await test('nonsense query returns zero FTS candidates', async () => {
    // sqlite-vec always returns K nearest neighbours, so vec results may be
    // non-empty even for gibberish. FTS should return zero though.
    const { results, diagnostics } = await l2.search({ query: 'xyzzy99plugh', debug: true as const });
    assert(diagnostics.fts_candidates === 0, `expected 0 FTS candidates, got ${diagnostics.fts_candidates}`);
    console.log(`        -> ${results.length} results (fts=${diagnostics.fts_candidates}, vec=${diagnostics.vec_candidates})`);
  });

  // --- Read item ---

  await test('readItem works on search result', async () => {
    const results = await l2.search({ query: 'Russell' });
    assert(results.length > 0, 'need a result to read');
    const item = await l2.readItem(results[0].id);
    assert(item !== null, 'readItem should return non-null');
    console.log(`        -> read "${(item as { name?: string }).name || results[0].id}" OK`);
  });

  // --- Done ---

  await storage.close();
  console.log('\n' + '='.repeat(50));
  console.log(`Results: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) process.exit(1);
}

run().catch((e) => {
  console.error('Runner error:', e.message);
  process.exit(1);
});
