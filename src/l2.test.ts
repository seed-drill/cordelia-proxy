#!/usr/bin/env npx tsx
/**
 * L2 Warm Index Tests
 *
 * Run: npx tsx src/l2.test.ts
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { initStorageProvider, getStorageProvider } from './storage.js';
import * as l2 from './l2.js';

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
  if (!condition) {
    throw new Error(message);
  }
}

async function runCase(
  tally: { passed: number; failed: number },
  name: string,
  fn: () => Promise<void>,
): Promise<void> {
  if (await test(name, fn)) tally.passed++;
  else tally.failed++;
}

async function runTests(): Promise<void> {
  // Use temp SQLite database for isolation — keyword search requires FTS5
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cordelia-l2-test-'));
  process.env.CORDELIA_STORAGE = 'sqlite';
  process.env.CORDELIA_EMBEDDING_PROVIDER = 'none';
  await initStorageProvider(tmpDir);

  console.log('\nL2 Warm Index Tests\n' + '='.repeat(40));

  const tally = { passed: 0, failed: 0 };

  await runCase(tally, 'loadIndex returns valid index', async () => {
    const index = await l2.loadIndex();
    assert(index.version === 1, 'version should be 1');
    assert(Array.isArray(index.entries), 'entries should be array');
  });

  await runCase(tally, 'writeItem creates entity', async () => {
    const result = await l2.writeItem('entity', {
      type: 'person',
      name: 'Test Person',
      summary: 'A test person for unit tests',
      tags: ['test', 'person'],
    });
    assert('success' in result && result.success === true, 'should succeed');
    assert('id' in result && typeof result.id === 'string', 'should return id');
  });

  await runCase(tally, 'writeItem creates learning', async () => {
    const result = await l2.writeItem('learning', {
      type: 'insight',
      content: 'Testing is important for reliability',
      tags: ['testing', 'quality'],
      confidence: 0.9,
    });
    assert('success' in result && result.success === true, 'should succeed');
  });

  await runCase(tally, 'search finds by keyword', async () => {
    const results = await l2.search({ query: 'test' });
    assert(results.length > 0, 'should find results');
    assert(results[0].score > 0, 'should have positive score');
  });

  await runCase(tally, 'search filters by type', async () => {
    const entities = await l2.search({ type: 'entity' });
    const learnings = await l2.search({ type: 'learning' });
    assert(entities.every((e) => e.type === 'entity'), 'all should be entities');
    assert(learnings.every((e) => e.type === 'learning'), 'all should be learnings');
  });

  await runCase(tally, 'search filters by tags', async () => {
    const results = await l2.search({ tags: ['testing'] });
    assert(results.length > 0, 'should find tagged items');
  });

  await runCase(tally, 'readItem retrieves written item', async () => {
    const searchResults = await l2.search({ query: 'Test Person' });
    assert(searchResults.length > 0, 'should find test person');

    const item = await l2.readItem(searchResults[0].id);
    assert(item !== null, 'should return item');
    assert((item as { name: string }).name === 'Test Person', 'should have correct name');
  });

  await runCase(tally, 'index encrypts and decrypts correctly', async () => {
    const indexBefore = await l2.loadIndex();
    const entryCount = indexBefore.entries.length;
    await l2.saveIndex(indexBefore);

    const indexAfter = await l2.loadIndex();
    assert(indexAfter.version === 1, 'version should survive round-trip');
    assert(indexAfter.entries.length === entryCount, `entry count should survive round-trip (expected ${entryCount}, got ${indexAfter.entries.length})`);

    for (const entry of indexAfter.entries) {
      assert(typeof entry.id === 'string' && entry.id.length > 0, 'entry should have id');
      assert(typeof entry.name === 'string', 'entry should have name');
      assert(Array.isArray(entry.tags), 'entry should have tags array');
      assert(Array.isArray(entry.keywords), 'entry should have keywords array');
    }
  });

  await runCase(tally, 'writeItem preserves details field', async () => {
    const result = await l2.writeItem('entity', {
      type: 'concept',
      name: 'Connectionist Test',
      summary: 'Neural network concepts',
      details: {
        hardware: 'Trained ANNs on 386DX33',
        location: 'Manchester 1993',
      },
      tags: ['test-details'],
    });
    assert('success' in result && result.success === true, 'should create entity');

    const searchResults = await l2.search({ query: 'Connectionist Test' });
    assert(searchResults.length > 0, 'should find by name');

    const item = await l2.readItem(searchResults[0].id);
    assert(item !== null, 'should return item');
    const details = (item as { details?: Record<string, unknown> }).details;
    assert(details !== undefined, 'should have details');
    assert(details!.hardware === 'Trained ANNs on 386DX33', 'should preserve hardware detail');
    assert(details!.location === 'Manchester 1993', 'should preserve location detail');
  });

  await runCase(tally, 'rebuildIndex scans files', async () => {
    const result = await l2.rebuildIndex();
    assert('success' in result && result.success === true, 'should succeed');
    assert('count' in result && result.count >= 0, 'should return count');
  });

  // Cleanup
  await getStorageProvider().close();
  fs.rmSync(tmpDir, { recursive: true, force: true });

  console.log('\n' + '='.repeat(40));
  console.log(`Results: ${tally.passed} passed, ${tally.failed} failed\n`);

  if (tally.failed > 0) {
    process.exit(1);
  }
}

await runTests();
