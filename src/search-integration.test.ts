#!/usr/bin/env npx tsx
/**
 * Search Integration Tests
 *
 * End-to-end tests for the unified search path.
 * Validates FTS, vec, diagnostics, and degradation behavior.
 *
 * Run: npx tsx src/search-integration.test.ts
 *   Requires: CORDELIA_STORAGE=sqlite (default)
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { initStorageProvider, getStorageProvider } from './storage.js';
import * as l2 from './l2.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

// --- Test harness ---

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>): Promise<boolean> {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    return true;
  } catch (e) {
    console.log(`  FAIL: ${name}`);
    console.log(`        ${(e as Error).message}`);
    return false;
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function countPass(): void { passed++; }
function countFail(): void { failed++; }
function count(result: { ok: boolean }): void {
  if (result.ok) countPass(); else countFail();
}

// --- Tests ---

async function runTests(): Promise<void> {
  // Use a temp directory for isolated test DB
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cordelia-search-test-'));
  process.env.CORDELIA_STORAGE = 'sqlite';
  process.env.CORDELIA_EMBEDDING_PROVIDER = 'none'; // Disable Ollama for deterministic tests

  await initStorageProvider(tmpDir);
  const storage = getStorageProvider();
  const isSqlite = storage.name === 'sqlite';

  console.log('\nSearch Integration Tests\n' + '='.repeat(50));
  console.log(`  Storage: ${storage.name}, temp dir: ${tmpDir}\n`);

  // --- 1. Write entity with details ---
  count({ ok: await test('write entity with details containing "386DX33"', async () => {
    const result = await l2.writeItem('entity', {
      type: 'concept',
      name: 'Connectionist Research',
      summary: 'Neural network experiments in Manchester',
      details: {
        hardware: 'Trained ANNs on 386DX33',
        location: 'Manchester 1993',
        framework: 'Custom C code',
      },
      tags: ['ai', 'neural-networks', 'manchester'],
    });
    assert('success' in result && result.success === true, `write failed: ${JSON.stringify(result)}`);
  }) });

  // --- 2. Write a second entity for multi-result tests ---
  count({ ok: await test('write second entity', async () => {
    const result = await l2.writeItem('entity', {
      type: 'person',
      name: 'Ada Lovelace',
      summary: 'Pioneer of computing',
      tags: ['computing', 'history'],
    });
    assert('success' in result && result.success === true, `write failed: ${JSON.stringify(result)}`);
  }) });

  // --- 3. Verify FTS entry exists (SQLite only) ---
  if (isSqlite) {
    count({ ok: await test('FTS entry exists for written entity', async () => {
      const sqliteStorage = storage as SqliteStorageProvider;
      const ftsResults = await sqliteStorage.ftsSearch('386DX33', 10);
      assert(ftsResults.length > 0, 'FTS should find entity by details content "386DX33"');
    }) });

    count({ ok: await test('FTS entry exists for entity name', async () => {
      const sqliteStorage = storage as SqliteStorageProvider;
      const ftsResults = await sqliteStorage.ftsSearch('Connectionist', 10);
      assert(ftsResults.length > 0, 'FTS should find entity by name');
    }) });
  }

  // --- 4. Search by keyword returns results ---
  count({ ok: await test('search finds entity by details keyword "386"', async () => {
    const results = await l2.search({ query: '386DX33' });
    assert(results.length > 0, 'should find entity containing "386DX33" in details');
    assert(results[0].name === 'Connectionist Research', `expected "Connectionist Research", got "${results[0].name}"`);
  }) });

  count({ ok: await test('search finds entity by name', async () => {
    const results = await l2.search({ query: 'Connectionist' });
    assert(results.length > 0, 'should find entity by name');
  }) });

  count({ ok: await test('search finds entity by tag-adjacent keyword "manchester"', async () => {
    const results = await l2.search({ query: 'manchester' });
    assert(results.length > 0, 'should find entity with "manchester" in details/tags');
  }) });

  // --- 5. Search with type filter ---
  count({ ok: await test('search with type filter only returns matching type', async () => {
    const results = await l2.search({ query: 'Connectionist', type: 'learning' });
    assert(results.length === 0, 'should not find entity when filtering for learnings');
  }) });

  // --- 6. Search with tag filter ---
  count({ ok: await test('search with tag filter', async () => {
    const results = await l2.search({ tags: ['ai'] });
    assert(results.length > 0, 'should find items tagged "ai"');
    assert(results.every((r) => r.tags.includes('ai')), 'all results should have "ai" tag');
  }) });

  // --- 7. Debug mode returns diagnostics ---
  count({ ok: await test('search with debug=true returns diagnostics', async () => {
    const { results, diagnostics } = await l2.search({ query: 'Connectionist', debug: true as const });
    assert(results.length > 0, 'should still return results');
    assert(diagnostics.search_path === 'sql', `expected search_path "sql", got "${diagnostics.search_path}"`);
    assert(typeof diagnostics.vec_available === 'boolean', 'vec_available should be boolean');
    assert(typeof diagnostics.fts_candidates === 'number', 'fts_candidates should be number');
    assert(typeof diagnostics.blob_index_entries === 'number', 'blob_index_entries should be number');
    assert(diagnostics.results.length > 0, 'diagnostics.results should have entries');

    // Since embeddings are disabled, vec should not be used
    assert(diagnostics.vec_used === false, 'vec should not be used with none provider');
    assert(diagnostics.query_embedding_generated === false, 'no embedding should be generated with none provider');
  }) });

  count({ ok: await test('search with debug=true and no query returns diagnostics', async () => {
    const { diagnostics } = await l2.search({ debug: true as const });
    assert(diagnostics.fts_candidates === 0, 'no FTS candidates for no-query search');
  }) });

  // --- 8. No results for nonsense query ---
  count({ ok: await test('search returns empty for nonsense query', async () => {
    const results = await l2.search({ query: 'xyzzy99plugh' });
    assert(results.length === 0, 'should return no results for nonsense query');
  }) });

  // --- 9. Delete entity and verify search no longer finds it ---
  count({ ok: await test('deleted entity disappears from search', async () => {
    const before = await l2.search({ query: 'Ada Lovelace' });
    assert(before.length > 0, 'should find Ada Lovelace before delete');

    const deleteResult = await l2.deleteItem(before[0].id);
    assert('success' in deleteResult, 'delete should succeed');

    const after = await l2.search({ query: 'Ada Lovelace' });
    assert(after.length === 0, 'should not find Ada Lovelace after delete');
  }) });

  // --- 10. Backfill recovers FTS after manual deletion (SQLite only) ---
  if (isSqlite) {
    count({ ok: await test('backfill recovers FTS after manual deletion', async () => {
      const sqliteStorage = storage as SqliteStorageProvider;
      const db = sqliteStorage.getDatabase();

      // Manually clear FTS
      db.exec('DELETE FROM l2_fts');
      const ftsCountBefore = sqliteStorage.ftsCount();
      assert(ftsCountBefore === 0, 'FTS should be empty after manual delete');

      // Run backfill
      const result = await l2.backfillVec();
      assert(result.fts_updated > 0, `should have rebuilt FTS entries, got fts_updated=${result.fts_updated}`);

      // Verify search works again
      const searchResults = await l2.search({ query: 'Connectionist' });
      assert(searchResults.length > 0, 'search should work after backfill');
    }) });
  }

  // --- Cleanup ---
  await storage.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log('\n' + '='.repeat(50));
  console.log(`Results: ${passed} passed, ${failed} failed\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

await runTests();
