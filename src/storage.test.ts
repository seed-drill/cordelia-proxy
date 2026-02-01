/**
 * Project Cordelia - Storage Provider Tests
 *
 * Provider-agnostic tests run against both JSON and SQLite providers.
 * SQLite-specific tests for access tracking and WAL mode.
 * Migration tests for JSON -> SQLite.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import * as os from 'os';
import { JsonStorageProvider } from './storage-json.js';
import { SqliteStorageProvider } from './storage-sqlite.js';
import type { StorageProvider } from './storage.js';

function runProviderTests(name: string, createProvider: () => Promise<{ provider: StorageProvider; cleanup: () => Promise<void> }>) {
  describe(`${name} provider`, () => {
    let provider: StorageProvider;
    let cleanup: () => Promise<void>;

    before(async () => {
      const result = await createProvider();
      provider = result.provider;
      cleanup = result.cleanup;
    });

    after(async () => {
      await provider.close();
      await cleanup();
    });

    it('should read/write L1 round-trip', async () => {
      const userId = 'test-user';
      const data = Buffer.from(JSON.stringify({ version: 1, name: 'Test' }));

      await provider.writeL1(userId, data);
      const result = await provider.readL1(userId);

      assert.ok(result, 'should return data');
      assert.deepStrictEqual(JSON.parse(result.toString('utf-8')), { version: 1, name: 'Test' });
    });

    it('should return null for non-existent L1 user', async () => {
      const result = await provider.readL1('nonexistent');
      assert.strictEqual(result, null);
    });

    it('should list L1 users', async () => {
      await provider.writeL1('alice', Buffer.from('{}'));
      await provider.writeL1('bob', Buffer.from('{}'));
      const users = await provider.listL1Users();
      assert.ok(users.includes('alice'), 'should include alice');
      assert.ok(users.includes('bob'), 'should include bob');
    });

    it('should read/write L2 item round-trip', async () => {
      const id = 'item-1';
      const data = Buffer.from(JSON.stringify({ id: 'item-1', type: 'person', name: 'Test' }));

      await provider.writeL2Item(id, 'entity', data, { type: 'entity' });
      const result = await provider.readL2Item(id);

      assert.ok(result, 'should return item');
      assert.strictEqual(result.type, 'entity');
      assert.deepStrictEqual(JSON.parse(result.data.toString('utf-8')), { id: 'item-1', type: 'person', name: 'Test' });
    });

    it('should return null for non-existent L2 item', async () => {
      const result = await provider.readL2Item('nonexistent');
      assert.strictEqual(result, null);
    });

    it('should delete L2 item', async () => {
      const id = 'item-to-delete';
      const data = Buffer.from('{"test": true}');

      await provider.writeL2Item(id, 'learning', data, { type: 'learning' });
      const deleted = await provider.deleteL2Item(id);
      assert.strictEqual(deleted, true);

      const result = await provider.readL2Item(id);
      assert.strictEqual(result, null);
    });

    it('should return false when deleting non-existent item', async () => {
      const deleted = await provider.deleteL2Item('nonexistent-delete');
      assert.strictEqual(deleted, false);
    });

    it('should read/write L2 index round-trip', async () => {
      const indexData = Buffer.from(JSON.stringify({ version: 1, entries: [], updated_at: '2025-01-01' }));
      await provider.writeL2Index(indexData);
      const result = await provider.readL2Index();

      assert.ok(result, 'should return index');
      const parsed = JSON.parse(result.toString('utf-8'));
      assert.strictEqual(parsed.version, 1);
    });

    it('should append audit entries', async () => {
      // Just verify it doesn't throw
      await provider.appendAudit(JSON.stringify({ ts: new Date().toISOString(), op: 'test' }));
      await provider.appendAudit(JSON.stringify({ ts: new Date().toISOString(), op: 'test2' }));
    });
  });
}

// Run tests against JSON provider
runProviderTests('JSON', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-json-'));
  const provider = new JsonStorageProvider(tmpDir);
  await provider.initialize();
  return {
    provider,
    cleanup: async () => {
      await fs.rm(tmpDir, { recursive: true, force: true });
    },
  };
});

// Run tests against SQLite provider
runProviderTests('SQLite', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-sqlite-'));
  const provider = new SqliteStorageProvider(tmpDir);
  await provider.initialize();
  return {
    provider,
    cleanup: async () => {
      await fs.rm(tmpDir, { recursive: true, force: true });
    },
  };
});

// SQLite-specific tests
describe('SQLite-specific features', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-sqlite-specific-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should set WAL mode', async () => {
    const db = provider.getDatabase();
    const result = db.pragma('journal_mode') as Array<{ journal_mode: string }>;
    assert.strictEqual(result[0].journal_mode, 'wal');
  });

  it('should create database file on initialize', () => {
    const dbPath = path.join(tmpDir, 'cordelia.db');
    assert.ok(fsSync.existsSync(dbPath), 'database file should exist');
  });

  it('should increment access count on recordAccess', async () => {
    const id = 'access-test-item';
    await provider.writeL2Item(id, 'entity', Buffer.from('{}'), { type: 'entity' });

    // Initial state
    let stats = await provider.getAccessStats(id);
    assert.ok(stats, 'should have stats');
    assert.strictEqual(stats.access_count, 0);
    assert.strictEqual(stats.last_accessed_at, null);

    // Record access
    await provider.recordAccess(id);
    stats = await provider.getAccessStats(id);
    assert.ok(stats, 'should have stats after access');
    assert.strictEqual(stats.access_count, 1);
    assert.ok(stats.last_accessed_at, 'should have last_accessed_at');

    // Record another access
    await provider.recordAccess(id);
    stats = await provider.getAccessStats(id);
    assert.ok(stats, 'should have stats after second access');
    assert.strictEqual(stats.access_count, 2);
  });

  it('should return null access stats for non-existent item', async () => {
    const stats = await provider.getAccessStats('nonexistent');
    assert.strictEqual(stats, null);
  });
});

// FTS5 tests
describe('SQLite FTS5 search', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-fts-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should upsert and search FTS entries', async () => {
    await provider.ftsUpsert('item-1', 'Russell Wing', 'founder product leader engineer', 'person team');
    await provider.ftsUpsert('item-2', 'Memory System', 'cordelia memory cache embedding', 'project tech');

    const results = await provider.ftsSearch('memory', 10);
    assert.ok(results.length > 0, 'should find results for "memory"');
    assert.ok(results.some((r) => r.item_id === 'item-2'), 'should find Memory System');
  });

  it('should delete FTS entries', async () => {
    await provider.ftsUpsert('item-del', 'Deletable', 'this will be deleted', 'test');
    await provider.ftsDelete('item-del');
    const results = await provider.ftsSearch('deletable', 10);
    assert.strictEqual(results.filter((r) => r.item_id === 'item-del').length, 0, 'deleted entry should not appear');
  });

  it('should handle empty query gracefully', async () => {
    const results = await provider.ftsSearch('', 10);
    assert.strictEqual(results.length, 0);
  });

  it('should sanitize FTS query operators', async () => {
    // Should not throw on operator-like input
    const results = await provider.ftsSearch('NOT OR AND "test"', 10);
    assert.ok(Array.isArray(results), 'should return array');
  });

  it('should report hasFtsData correctly', async () => {
    assert.strictEqual(provider.hasFtsData(), true, 'should have FTS data after inserts');
  });

  it('should find content from details field via FTS', async () => {
    // Simulate indexing an entity with details field content
    const detailsText = 'Trained ANNs on 386DX33. Manchester 1993. Which president was an ex movie actor married to Nancy';
    await provider.ftsUpsert(
      'entity-details',
      'Connectionist Models',
      `Connectionist Models Neural network concepts ${detailsText}`,
      'ai neural pdp',
    );

    // Search by content only found in the details portion
    const results386 = await provider.ftsSearch('386DX33', 10);
    assert.ok(results386.some((r) => r.item_id === 'entity-details'), 'should find by "386DX33" from details');

    const resultsManchester = await provider.ftsSearch('Manchester', 10);
    assert.ok(resultsManchester.some((r) => r.item_id === 'entity-details'), 'should find by "Manchester" from details');

    const resultsActor = await provider.ftsSearch('movie actor', 10);
    assert.ok(resultsActor.some((r) => r.item_id === 'entity-details'), 'should find by "movie actor" from details');
  });

  it('should find content via prefix search', async () => {
    // "386" should match "386DX33" via prefix matching
    const results = await provider.ftsSearch('386', 10);
    assert.ok(results.some((r) => r.item_id === 'entity-details'), 'prefix "386" should match "386DX33"');
  });

  it('should list all item IDs from l2_items', async () => {
    // Write an item to l2_items first
    const data = Buffer.from(JSON.stringify({ id: 'list-test', type: 'concept', name: 'Test' }));
    await provider.writeL2Item('list-test', 'entity', data, {
      type: 'entity',
      owner_id: 'test',
      visibility: 'private',
    });

    const items = provider.listL2ItemIds();
    assert.ok(items.some((i) => i.id === 'list-test'), 'should list the written item');
    assert.ok(items.some((i) => i.type === 'entity'), 'should include type');
  });
});

// Embedding cache tests
describe('SQLite embedding cache', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-embed-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should round-trip embedding cache entries', async () => {
    const hash = 'abc123hash';
    const embedding = new Float32Array([0.1, 0.2, 0.3, 0.4]);
    const buf = Buffer.from(embedding.buffer, embedding.byteOffset, embedding.byteLength);

    await provider.putEmbedding(hash, 'ollama', 'nomic-embed-text', 4, buf);
    const result = await provider.getEmbedding(hash, 'ollama', 'nomic-embed-text');

    assert.ok(result, 'should return cached embedding');
    const f32 = new Float32Array(result.buffer, result.byteOffset, result.byteLength / 4);
    assert.strictEqual(f32.length, 4);
    assert.ok(Math.abs(f32[0] - 0.1) < 0.001, 'first value should be ~0.1');
    assert.ok(Math.abs(f32[3] - 0.4) < 0.001, 'last value should be ~0.4');
  });

  it('should return null for cache miss', async () => {
    const result = await provider.getEmbedding('nonexistent', 'ollama', 'nomic-embed-text');
    assert.strictEqual(result, null);
  });

  it('should differentiate by provider and model', async () => {
    const hash = 'shared-hash';
    const buf1 = Buffer.from(new Float32Array([1.0, 2.0]).buffer);
    const buf2 = Buffer.from(new Float32Array([3.0, 4.0]).buffer);

    await provider.putEmbedding(hash, 'ollama', 'model-a', 2, buf1);
    await provider.putEmbedding(hash, 'ollama', 'model-b', 2, buf2);

    const result1 = await provider.getEmbedding(hash, 'ollama', 'model-a');
    const result2 = await provider.getEmbedding(hash, 'ollama', 'model-b');

    assert.ok(result1 && result2, 'both should exist');
    const f1 = new Float32Array(result1.buffer, result1.byteOffset, result1.byteLength / 4);
    const f2 = new Float32Array(result2.buffer, result2.byteOffset, result2.byteLength / 4);
    assert.ok(Math.abs(f1[0] - 1.0) < 0.001);
    assert.ok(Math.abs(f2[0] - 3.0) < 0.001);
  });
});

// Schema migration tests
describe('SQLite v1 to v2 migration', () => {
  it('should migrate v1 schema to v2 with FTS population', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-migrate-v2-'));

    // Create a v1 database manually
    const Database = (await import('better-sqlite3')).default;
    const dbPath = path.join(tmpDir, 'cordelia.db');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    // Create v1 tables
    db.exec(`
      CREATE TABLE IF NOT EXISTS l1_hot (
        user_id TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_items (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
        owner_id TEXT,
        visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private', 'team', 'public')),
        data BLOB NOT NULL,
        last_accessed_at TEXT,
        access_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_index (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        entry TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER NOT NULL,
        migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Insert v1 schema version and test index data
    db.prepare('INSERT INTO schema_version (version) VALUES (1)').run();
    const indexData = JSON.stringify({
      version: 1,
      updated_at: '2026-01-29T00:00:00.000Z',
      entries: [
        { id: 'test-1', type: 'entity', name: 'Test Entity', tags: ['test'], keywords: ['entity', 'test'], path: 'entities/test-1.json', visibility: 'private' },
      ],
    });
    db.prepare('INSERT INTO l2_index (id, data) VALUES (1, ?)').run(Buffer.from(indexData));
    db.close();

    // Now open with SqliteStorageProvider - should trigger v1->v2 migration
    const provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();

    // Verify schema version is current (4, after v1->v2->v3->v4 migration)
    const versionRow = provider.getDatabase().prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number };
    assert.strictEqual(versionRow.version, 4, 'schema version should be 4 after full migration chain');

    // Verify FTS table exists and is populated from index
    assert.strictEqual(provider.hasFtsData(), true, 'FTS should be populated from index');

    // Verify embedding_cache table exists
    const cacheTable = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='embedding_cache'"
    ).get() as { name: string } | undefined;
    assert.ok(cacheTable, 'embedding_cache table should exist');

    // Verify FTS search works
    const results = await provider.ftsSearch('test entity', 10);
    assert.ok(results.length > 0, 'FTS search should find migrated data');

    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});

// Vec search tests - sqlite-vec is a hard dependency, must load
describe('SQLite vec search', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-vec-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should load sqlite-vec extension', () => {
    // sqlite-vec is in dependencies - it must load or the ESM fix is broken
    assert.strictEqual(provider.vecAvailable(), true, 'sqlite-vec must be available');
  });

  it('should report vec and embedding cache counts', () => {
    assert.strictEqual(typeof provider.vecCount(), 'number');
    assert.strictEqual(typeof provider.embeddingCacheCount(), 'number');
  });

  it('should upsert and search vec embeddings', async () => {
    // Create a known embedding (768 dims, mostly zeros with a signal)
    const embedding = new Float32Array(768);
    embedding[0] = 1.0;
    embedding[1] = 0.5;

    await provider.vecUpsert('vec-test-1', embedding);
    assert.strictEqual(provider.vecCount(), 1, 'vec table should have 1 row');

    // Search with the same embedding - should find it
    const results = await provider.vecSearch(embedding, 5);
    assert.strictEqual(results.length, 1);
    assert.strictEqual(results[0].item_id, 'vec-test-1');
    assert.strictEqual(results[0].distance, 0, 'identical embedding should have 0 distance');
  });

  it('should return nearest neighbours in order', async () => {
    // Insert a second embedding that differs from the first
    const similar = new Float32Array(768);
    similar[0] = 0.9;
    similar[1] = 0.4;
    await provider.vecUpsert('vec-test-2', similar);

    const different = new Float32Array(768);
    different[100] = 1.0;
    different[200] = 1.0;
    await provider.vecUpsert('vec-test-3', different);

    // Query with something close to vec-test-1
    const query = new Float32Array(768);
    query[0] = 1.0;
    query[1] = 0.5;

    const results = await provider.vecSearch(query, 5);
    assert.ok(results.length >= 2, 'should return multiple results');
    // Nearest should be vec-test-1 (exact match)
    assert.strictEqual(results[0].item_id, 'vec-test-1');
    // vec-test-2 should be closer than vec-test-3
    const idx2 = results.findIndex(r => r.item_id === 'vec-test-2');
    const idx3 = results.findIndex(r => r.item_id === 'vec-test-3');
    assert.ok(idx2 < idx3, 'similar embedding should rank higher than different one');
  });

  it('should delete vec entries', async () => {
    await provider.vecDelete('vec-test-1');
    await provider.vecDelete('vec-test-2');
    await provider.vecDelete('vec-test-3');

    const query = new Float32Array(768);
    query[0] = 1.0;
    const results = await provider.vecSearch(query, 5);
    assert.strictEqual(results.length, 0, 'should be empty after deletes');
  });
});

// Migration tests
describe('JSON to SQLite migration', () => {
  it('should migrate JSON files to SQLite', async () => {
    // Set up source JSON structure
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-migrate-src-'));
    await fs.mkdir(path.join(srcDir, 'L1-hot'), { recursive: true });
    await fs.mkdir(path.join(srcDir, 'L2-warm', 'entities'), { recursive: true });
    await fs.mkdir(path.join(srcDir, 'L2-warm', 'sessions'), { recursive: true });
    await fs.mkdir(path.join(srcDir, 'L2-warm', 'learnings'), { recursive: true });

    // Write test data
    const l1Data = JSON.stringify({ version: 1, name: 'Test User' });
    await fs.writeFile(path.join(srcDir, 'L1-hot', 'testuser.json'), l1Data);

    const indexData = JSON.stringify({ version: 1, updated_at: '2025-01-01', entries: [] });
    await fs.writeFile(path.join(srcDir, 'L2-warm', 'index.json'), indexData);

    const entityData = JSON.stringify({ id: 'ent-1', type: 'person', name: 'Alice' });
    await fs.writeFile(path.join(srcDir, 'L2-warm', 'entities', 'ent-1.json'), entityData);

    const auditData = '{"ts":"2025-01-01","op":"test"}\n{"ts":"2025-01-02","op":"test2"}\n';
    await fs.writeFile(path.join(srcDir, 'audit.jsonl'), auditData);

    // Create SQLite provider pointing at same directory
    const sqlite = new SqliteStorageProvider(srcDir);
    await sqlite.initialize();

    // Manual migration logic (same as migrate.ts)
    const jsonProvider = new JsonStorageProvider(srcDir);
    await jsonProvider.initialize();

    // Migrate L1
    const users = await jsonProvider.listL1Users();
    for (const userId of users) {
      const data = await jsonProvider.readL1(userId);
      if (data) await sqlite.writeL1(userId, data);
    }

    // Migrate L2 index
    const idx = await jsonProvider.readL2Index();
    if (idx) await sqlite.writeL2Index(idx);

    // Migrate L2 item
    await sqlite.writeL2Item('ent-1', 'entity', Buffer.from(entityData), { type: 'entity' });

    // Migrate audit
    const auditContent = await fs.readFile(path.join(srcDir, 'audit.jsonl'), 'utf-8');
    const auditLines = auditContent.split('\n').filter((l) => l.trim());
    for (const line of auditLines) {
      await sqlite.appendAudit(line);
    }

    // Verify
    const l1Result = await sqlite.readL1('testuser');
    assert.ok(l1Result, 'should have L1 data');
    assert.deepStrictEqual(JSON.parse(l1Result.toString('utf-8')), JSON.parse(l1Data));

    const idxResult = await sqlite.readL2Index();
    assert.ok(idxResult, 'should have L2 index');

    const itemResult = await sqlite.readL2Item('ent-1');
    assert.ok(itemResult, 'should have L2 item');
    assert.strictEqual(itemResult.type, 'entity');

    await sqlite.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });

  it('should handle empty source cleanly', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-migrate-empty-'));
    await fs.mkdir(path.join(srcDir, 'L1-hot'), { recursive: true });
    await fs.mkdir(path.join(srcDir, 'L2-warm'), { recursive: true });

    const sqlite = new SqliteStorageProvider(srcDir);
    await sqlite.initialize();

    const users = await sqlite.listL1Users();
    assert.strictEqual(users.length, 0);

    const idx = await sqlite.readL2Index();
    assert.strictEqual(idx, null);

    await sqlite.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });
});

// L2 delete integration test (via l2 module)
// INCIDENT-001: This test previously used the real memory path, which caused
// index corruption. Now uses an isolated temp directory.
describe('L2 deleteItem', () => {
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-l2-delete-'));
    // Create required subdirectories for L2
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'entities'), { recursive: true });
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'sessions'), { recursive: true });
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'learnings'), { recursive: true });
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should delete an item and remove from index', async () => {
    const { initStorageProvider } = await import('./storage.js');
    await initStorageProvider(tmpDir);

    const l2 = await import('./l2.js');

    // Write an item
    const writeResult = await l2.writeItem('learning', {
      type: 'insight',
      content: 'This item will be deleted',
      tags: ['delete-test'],
      confidence: 0.5,
    });
    assert.ok('success' in writeResult && writeResult.success);
    const id = (writeResult as { success: true; id: string }).id;

    // Verify it exists
    const item = await l2.readItem(id);
    assert.ok(item, 'item should exist before delete');

    // Delete it
    const deleteResult = await l2.deleteItem(id);
    assert.ok('success' in deleteResult && deleteResult.success);

    // Verify it's gone
    const afterDelete = await l2.readItem(id);
    assert.strictEqual(afterDelete, null, 'item should not exist after delete');

    // Verify not in search results
    const searchResults = await l2.search({ tags: ['delete-test'] });
    const found = searchResults.find((r) => r.id === id);
    assert.strictEqual(found, undefined, 'deleted item should not appear in search');
  });

  it('should return not_found for non-existent item', async () => {
    const l2 = await import('./l2.js');
    const result = await l2.deleteItem('nonexistent-id-12345');
    assert.ok('error' in result);
    assert.strictEqual(result.error, 'not_found');
  });
});

// S3: Concurrent access tests (WAL isolation)
describe('SQLite concurrent access (WAL)', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-concurrent-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should handle concurrent L1 writes', async () => {
    const writes = Array.from({ length: 10 }, (_, i) =>
      provider.writeL1(`concurrent-user-${i}`, Buffer.from(JSON.stringify({ version: 1, idx: i }))),
    );
    await Promise.all(writes);

    const users = await provider.listL1Users();
    const concurrentUsers = users.filter((u) => u.startsWith('concurrent-user-'));
    assert.strictEqual(concurrentUsers.length, 10);
  });

  it('should handle concurrent L2 writes', async () => {
    const writes = Array.from({ length: 10 }, (_, i) =>
      provider.writeL2Item(`concurrent-item-${i}`, 'entity',
        Buffer.from(JSON.stringify({ id: `concurrent-item-${i}`, idx: i })),
        { type: 'entity' }),
    );
    await Promise.all(writes);

    // Verify all items readable
    for (let i = 0; i < 10; i++) {
      const item = await provider.readL2Item(`concurrent-item-${i}`);
      assert.ok(item, `Item concurrent-item-${i} should exist`);
    }
  });

  it('should handle read during write', async () => {
    await provider.writeL1('rw-test', Buffer.from(JSON.stringify({ version: 1, state: 'initial' })));

    // Start a write and read concurrently
    const [, readResult] = await Promise.all([
      provider.writeL1('rw-test', Buffer.from(JSON.stringify({ version: 1, state: 'updated' }))),
      provider.readL1('rw-test'),
    ]);

    assert.ok(readResult, 'Read should succeed during concurrent write');
    const parsed = JSON.parse(readResult.toString('utf-8'));
    // WAL allows the read to see either initial or updated state
    assert.ok(parsed.state === 'initial' || parsed.state === 'updated');
  });
});

// S3: Edge case tests
describe('SQLite storage edge cases', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-edge-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should handle zero-byte L2 items', async () => {
    await provider.writeL2Item('zero-byte', 'entity', Buffer.alloc(0), { type: 'entity' });
    const result = await provider.readL2Item('zero-byte');
    assert.ok(result);
    assert.strictEqual(result.data.length, 0);
  });

  it('should handle invalid JSON in L2 item data', async () => {
    // Storage stores opaque blobs -- it shouldn't care about JSON validity
    const invalidJson = Buffer.from('not json at all {{{', 'utf-8');
    await provider.writeL2Item('invalid-json', 'entity', invalidJson, { type: 'entity' });
    const result = await provider.readL2Item('invalid-json');
    assert.ok(result);
    assert.strictEqual(result.data.toString('utf-8'), 'not json at all {{{');
  });

  it('should handle binary data in L2 items', async () => {
    const binary = Buffer.from([0x00, 0xff, 0x80, 0x01, 0xfe, 0xba, 0xbe]);
    await provider.writeL2Item('binary-data', 'entity', binary, { type: 'entity' });
    const result = await provider.readL2Item('binary-data');
    assert.ok(result);
    assert.deepStrictEqual(result.data, binary);
  });

  it('should store and verify checksums on write', async () => {
    const data = Buffer.from('{"id":"checksum-test","name":"Checksum"}');
    await provider.writeL2Item('checksum-test', 'entity', data, { type: 'entity' });

    const db = provider.getDatabase();
    const row = db.prepare('SELECT checksum FROM l2_items WHERE id = ?').get('checksum-test') as { checksum: string };
    assert.ok(row.checksum, 'Should have checksum');

    const crypto = await import('crypto');
    const expected = crypto.createHash('sha256').update(data).digest('hex');
    assert.strictEqual(row.checksum, expected);
  });

  it('should update checksum on overwrite', async () => {
    const data1 = Buffer.from('version 1');
    await provider.writeL2Item('checksum-update', 'entity', data1, { type: 'entity' });

    const db = provider.getDatabase();
    const row1 = db.prepare('SELECT checksum FROM l2_items WHERE id = ?').get('checksum-update') as { checksum: string };

    const data2 = Buffer.from('version 2');
    await provider.writeL2Item('checksum-update', 'entity', data2, { type: 'entity' });

    const row2 = db.prepare('SELECT checksum FROM l2_items WHERE id = ?').get('checksum-update') as { checksum: string };
    assert.notStrictEqual(row1.checksum, row2.checksum, 'Checksum should change after update');
  });

  it('should create integrity canary on initialization', () => {
    const canary = provider.getCanaryValue();
    assert.ok(canary, 'Canary should exist after initialization');
    assert.ok(/^[0-9a-f]{64}$/.test(canary), 'Canary should be 64-char hex string');
  });

  it('should run integrityCheck successfully on healthy DB', async () => {
    const result = await provider.integrityCheck();
    assert.strictEqual(result.ok, true, `Errors: ${result.errors.join(', ')}`);
  });
});

// S3: Schema v3 migration tests
describe('SQLite v2 to v3 migration', () => {
  it('should migrate v2 schema to v3 with checksums and canary', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-migrate-v3-'));

    // Create a v2 database manually
    const Database = (await import('better-sqlite3')).default;
    const dbPath = path.join(tmpDir, 'cordelia.db');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    db.exec(`
      CREATE TABLE IF NOT EXISTS l1_hot (
        user_id TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_items (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
        owner_id TEXT,
        visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private', 'team', 'public')),
        data BLOB NOT NULL,
        last_accessed_at TEXT,
        access_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_index (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        entry TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER NOT NULL,
        migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS l2_fts USING fts5(
        item_id UNINDEXED, name, content, tags, tokenize = 'porter unicode61'
      );
      CREATE TABLE IF NOT EXISTS embedding_cache (
        content_hash TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
        dimensions INTEGER NOT NULL, vector BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (content_hash, provider, model)
      );
    `);

    db.prepare('INSERT INTO schema_version (version) VALUES (2)').run();
    // Insert items without checksum
    db.prepare('INSERT INTO l2_items (id, type, data) VALUES (?, ?, ?)').run(
      'v2-item-1', 'entity', Buffer.from('{"id":"v2-item-1","name":"Pre-v3"}'),
    );
    db.prepare('INSERT INTO l2_items (id, type, data) VALUES (?, ?, ?)').run(
      'v2-item-2', 'learning', Buffer.from('{"id":"v2-item-2","content":"Old"}'),
    );
    db.close();

    // Open with SqliteStorageProvider -- should trigger v2->v3 migration
    const provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();

    // Verify schema version is 4 after full chain
    const versionRow = provider.getDatabase().prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number };
    assert.strictEqual(versionRow.version, 4, 'Schema should be v4 after full migration chain');

    // Verify checksum column exists and is backfilled
    const items = provider.getDatabase().prepare('SELECT id, checksum FROM l2_items').all() as Array<{ id: string; checksum: string | null }>;
    for (const item of items) {
      assert.ok(item.checksum, `Item ${item.id} should have checksum after migration`);
    }

    // Verify canary exists
    const canary = provider.getCanaryValue();
    assert.ok(canary, 'Should have canary after migration');

    // Verify integrity_canary table exists
    const canaryTable = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='integrity_canary'",
    ).get() as { name: string } | undefined;
    assert.ok(canaryTable, 'integrity_canary table should exist');

    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});

// S5: Schema v3 to v4 migration tests
describe('SQLite v3 to v4 migration', () => {
  it('should migrate v3 schema to v4 with groups and new columns', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-migrate-v4-'));

    // Create a v3 database manually
    const Database = (await import('better-sqlite3')).default;
    const dbPath = path.join(tmpDir, 'cordelia.db');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');

    db.exec(`
      CREATE TABLE IF NOT EXISTS l1_hot (
        user_id TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_items (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
        owner_id TEXT,
        visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private', 'team', 'public')),
        data BLOB NOT NULL,
        last_accessed_at TEXT,
        access_count INTEGER NOT NULL DEFAULT 0,
        checksum TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS l2_index (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL DEFAULT (datetime('now')),
        entry TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER NOT NULL,
        migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS integrity_canary (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        value TEXT NOT NULL,
        written_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS l2_fts USING fts5(
        item_id UNINDEXED, name, content, tags, tokenize = 'porter unicode61'
      );
      CREATE TABLE IF NOT EXISTS embedding_cache (
        content_hash TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
        dimensions INTEGER NOT NULL, vector BLOB NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (content_hash, provider, model)
      );
    `);

    db.prepare('INSERT INTO schema_version (version) VALUES (3)').run();
    db.prepare("INSERT INTO integrity_canary (id, value) VALUES (1, 'test-canary')").run();

    // Insert L1 users so FK seed works
    db.prepare("INSERT INTO l1_hot (user_id, data) VALUES ('russell', X'7B7D')").run();
    db.prepare("INSERT INTO l1_hot (user_id, data) VALUES ('martin', X'7B7D')").run();

    // Insert an item with 'team' visibility to test reconciliation
    db.prepare("INSERT INTO l2_items (id, type, owner_id, visibility, data) VALUES ('team-item', 'entity', 'russell', 'team', X'7B7D')").run();

    db.close();

    // Open with SqliteStorageProvider -- should trigger v3->v4 migration
    const provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();

    // Verify schema version is 4
    const versionRow = provider.getDatabase().prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number };
    assert.strictEqual(versionRow.version, 4, 'Schema should be v4');

    // Verify groups table exists
    const groupsTable = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='groups'",
    ).get() as { name: string } | undefined;
    assert.ok(groupsTable, 'groups table should exist');

    // Verify group_members table exists
    const membersTable = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='group_members'",
    ).get() as { name: string } | undefined;
    assert.ok(membersTable, 'group_members table should exist');

    // Verify access_log table exists
    const accessLogTable = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='access_log'",
    ).get() as { name: string } | undefined;
    assert.ok(accessLogTable, 'access_log table should exist');

    // Verify seed-drill group was created
    const group = await provider.readGroup('seed-drill');
    assert.ok(group, 'seed-drill group should exist');
    assert.strictEqual(group.name, 'Seed Drill');

    // Verify founders were added (only those with l1_hot entries)
    const members = await provider.listMembers('seed-drill');
    assert.ok(members.length >= 2, 'should have at least 2 members (russell, martin)');
    assert.ok(members.some((m) => m.entity_id === 'russell' && m.role === 'owner'));
    assert.ok(members.some((m) => m.entity_id === 'martin' && m.role === 'owner'));

    // Verify new columns on l2_items
    const item = provider.getDatabase().prepare('SELECT group_id, author_id, key_version, parent_id, is_copy FROM l2_items WHERE id = ?').get('team-item') as { group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number };
    assert.strictEqual(item.author_id, 'russell', 'author_id should be backfilled from owner_id');
    assert.strictEqual(item.key_version, 1, 'key_version should be backfilled to 1');
    assert.strictEqual(item.is_copy, 0, 'is_copy should default to 0');

    // Verify 'team' visibility was reconciled to 'group'
    const visibility = provider.getDatabase().prepare('SELECT visibility FROM l2_items WHERE id = ?').get('team-item') as { visibility: string };
    assert.strictEqual(visibility.visibility, 'group', 'team visibility should be reconciled to group');

    // Verify indexes exist
    const indexes = provider.getDatabase().prepare(
      "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
    ).all() as Array<{ name: string }>;
    const idxNames = indexes.map((i) => i.name);
    assert.ok(idxNames.includes('idx_l2_items_group'), 'group_id index should exist');
    assert.ok(idxNames.includes('idx_l2_items_parent'), 'parent_id index should exist');
    assert.ok(idxNames.includes('idx_l2_items_author'), 'author_id index should exist');
    assert.ok(idxNames.includes('idx_access_log_entity'), 'access_log entity index should exist');
    assert.ok(idxNames.includes('idx_access_log_group'), 'access_log group index should exist');

    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});

// S5: Group CRUD tests
describe('SQLite group operations', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-groups-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();

    // Create test users
    await provider.writeL1('alice', Buffer.from('{}'));
    await provider.writeL1('bob', Buffer.from('{}'));
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should create and read a group', async () => {
    await provider.createGroup('grp-1', 'Test Group', '{"broadcast_eagerness":"moderate"}', '{}');
    const group = await provider.readGroup('grp-1');
    assert.ok(group);
    assert.strictEqual(group.name, 'Test Group');
    assert.strictEqual(group.culture, '{"broadcast_eagerness":"moderate"}');
  });

  it('should list groups', async () => {
    const groups = await provider.listGroups();
    assert.ok(groups.length >= 1);
    assert.ok(groups.some((g) => g.id === 'grp-1'));
  });

  it('should return null for non-existent group', async () => {
    const group = await provider.readGroup('nonexistent');
    assert.strictEqual(group, null);
  });

  it('should add and list members', async () => {
    await provider.addMember('grp-1', 'alice', 'owner');
    await provider.addMember('grp-1', 'bob', 'member');
    const members = await provider.listMembers('grp-1');
    assert.strictEqual(members.length, 2);
    assert.ok(members.some((m) => m.entity_id === 'alice' && m.role === 'owner'));
    assert.ok(members.some((m) => m.entity_id === 'bob' && m.role === 'member'));
  });

  it('should get specific membership', async () => {
    const m = await provider.getMembership('grp-1', 'alice');
    assert.ok(m);
    assert.strictEqual(m.role, 'owner');
    assert.strictEqual(m.posture, 'active');
  });

  it('should return null for non-member', async () => {
    const m = await provider.getMembership('grp-1', 'nobody');
    assert.strictEqual(m, null);
  });

  it('should update member posture', async () => {
    const updated = await provider.updateMemberPosture('grp-1', 'bob', 'emcon');
    assert.strictEqual(updated, true);
    const m = await provider.getMembership('grp-1', 'bob');
    assert.ok(m);
    assert.strictEqual(m.posture, 'emcon');
  });

  it('should remove a member', async () => {
    const removed = await provider.removeMember('grp-1', 'bob');
    assert.strictEqual(removed, true);
    const members = await provider.listMembers('grp-1');
    assert.strictEqual(members.length, 1);
  });

  it('should return false when removing non-member', async () => {
    const removed = await provider.removeMember('grp-1', 'nobody');
    assert.strictEqual(removed, false);
  });

  it('should delete a group', async () => {
    await provider.createGroup('grp-del', 'Delete Me', '{}', '{}');
    await provider.addMember('grp-del', 'alice', 'owner');
    const deleted = await provider.deleteGroup('grp-del');
    assert.strictEqual(deleted, true);
    const group = await provider.readGroup('grp-del');
    assert.strictEqual(group, null);
    const members = await provider.listMembers('grp-del');
    assert.strictEqual(members.length, 0);
  });

  it('should log access entries', async () => {
    await provider.logAccess({
      entity_id: 'alice',
      action: 'read',
      resource_type: 'entity',
      resource_id: 'ent-1',
      group_id: 'grp-1',
      detail: 'test access',
    });

    const db = provider.getDatabase();
    const row = db.prepare('SELECT * FROM access_log WHERE entity_id = ? ORDER BY id DESC LIMIT 1').get('alice') as { action: string; resource_type: string };
    assert.ok(row);
    assert.strictEqual(row.action, 'read');
    assert.strictEqual(row.resource_type, 'entity');
  });

  it('should list group items', async () => {
    await provider.writeL2Item('grp-item-1', 'entity', Buffer.from('{"test":true}'), {
      type: 'entity',
      group_id: 'grp-1',
      visibility: 'group',
    });
    const items = await provider.listGroupItems('grp-1');
    assert.ok(items.length >= 1);
    assert.ok(items.some((i) => i.id === 'grp-item-1'));
  });

  it('should read L2 item metadata', async () => {
    await provider.writeL2Item('meta-test', 'entity', Buffer.from('{}'), {
      type: 'entity',
      owner_id: 'alice',
      visibility: 'group',
      group_id: 'grp-1',
      author_id: 'alice',
      key_version: 1,
      parent_id: 'original-1',
      is_copy: true,
    });
    const meta = await provider.readL2ItemMeta('meta-test');
    assert.ok(meta);
    assert.strictEqual(meta.owner_id, 'alice');
    assert.strictEqual(meta.visibility, 'group');
    assert.strictEqual(meta.group_id, 'grp-1');
    assert.strictEqual(meta.author_id, 'alice');
    assert.strictEqual(meta.key_version, 1);
    assert.strictEqual(meta.parent_id, 'original-1');
    assert.strictEqual(meta.is_copy, 1);
  });

  it('should return null metadata for non-existent item', async () => {
    const meta = await provider.readL2ItemMeta('nonexistent');
    assert.strictEqual(meta, null);
  });
});

// R3-012: Prefetch tests
describe('SQLite getRecentItems', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-prefetch-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();

    // Set up: users, group with member, private + group items
    await provider.writeL1('alice', Buffer.from('{}'));
    await provider.writeL1('bob', Buffer.from('{}'));
    await provider.createGroup('team', 'Team', '{}', '{}');
    await provider.addMember('team', 'alice', 'member');

    // Write private item
    await provider.writeL2Item('priv-1', 'entity', Buffer.from('{}'), {
      type: 'entity',
      owner_id: 'alice',
      visibility: 'private',
    });
    await provider.recordAccess('priv-1');

    // Write group item
    await provider.writeL2Item('grp-1', 'learning', Buffer.from('{}'), {
      type: 'learning',
      owner_id: 'alice',
      visibility: 'group',
      group_id: 'team',
    });
    await provider.recordAccess('grp-1');

    // Write item by another user (alice shouldn't see this privately)
    await provider.writeL2Item('bob-priv', 'entity', Buffer.from('{}'), {
      type: 'entity',
      owner_id: 'bob',
      visibility: 'private',
    });
    await provider.recordAccess('bob-priv');
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should return private + group items for entity', async () => {
    const items = await provider.getRecentItems('alice', ['team'], 10);
    const ids = items.map(i => i.id);
    assert.ok(ids.includes('priv-1'), 'should include private item');
    assert.ok(ids.includes('grp-1'), 'should include group item');
    assert.ok(!ids.includes('bob-priv'), 'should not include other user private item');
  });

  it('should respect limit', async () => {
    const items = await provider.getRecentItems('alice', ['team'], 1);
    assert.strictEqual(items.length, 1);
  });

  it('should return empty for no groups and no private items', async () => {
    const items = await provider.getRecentItems('nobody', [], 10);
    assert.strictEqual(items.length, 0);
  });
});

// S5: COW share tests
describe('L2 shareItem', () => {
  it('should share an item and create a COW copy', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-share-'));
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'entities'), { recursive: true });
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'sessions'), { recursive: true });
    await fs.mkdir(path.join(tmpDir, 'L2-warm', 'learnings'), { recursive: true });

    const { setStorageProvider } = await import('./storage.js');
    const provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);

    // Set up user + group
    await provider.writeL1('owner-user', Buffer.from('{}'));
    await provider.writeL1('other-user', Buffer.from('{}'));
    await provider.createGroup('share-grp', 'Share Group', '{}', '{}');
    await provider.addMember('share-grp', 'owner-user', 'owner');
    await provider.addMember('share-grp', 'other-user', 'member');

    const l2 = await import('./l2.js');

    // Write a private item
    const writeResult = await l2.writeItem('learning', {
      type: 'insight',
      content: 'Shareable insight',
      tags: ['share-test'],
      confidence: 0.8,
    });
    assert.ok('success' in writeResult && writeResult.success);
    const itemId = (writeResult as { success: true; id: string }).id;

    // Set owner_id on the item
    provider.getDatabase().prepare('UPDATE l2_items SET owner_id = ? WHERE id = ?').run('owner-user', itemId);

    // Share it
    const shareResult = await l2.shareItem(itemId, 'share-grp', 'owner-user');
    assert.ok('success' in shareResult && shareResult.success, `Share failed: ${JSON.stringify(shareResult)}`);
    const copyId = (shareResult as { success: true; copy_id: string }).copy_id;

    // Verify copy exists
    const copy = await provider.readL2Item(copyId);
    assert.ok(copy, 'Copy should exist');

    // Verify copy metadata
    const copyMeta = await provider.readL2ItemMeta(copyId);
    assert.ok(copyMeta);
    assert.strictEqual(copyMeta.parent_id, itemId, 'Copy should point to original');
    assert.strictEqual(copyMeta.is_copy, 1, 'Copy should be flagged');
    assert.strictEqual(copyMeta.visibility, 'group');
    assert.strictEqual(copyMeta.group_id, 'share-grp');
    assert.strictEqual(copyMeta.author_id, 'owner-user');

    // Verify original is untouched
    const originalMeta = await provider.readL2ItemMeta(itemId);
    assert.ok(originalMeta);
    assert.strictEqual(originalMeta.visibility, 'private', 'Original should remain private');
    assert.strictEqual(originalMeta.group_id, null, 'Original should have no group');

    // Verify audit entry
    const db = provider.getDatabase();
    const log = db.prepare('SELECT * FROM access_log WHERE action = ? AND resource_id = ?').get('share', itemId) as { entity_id: string; group_id: string; detail: string } | undefined;
    assert.ok(log, 'Audit entry should exist');
    assert.strictEqual(log.entity_id, 'owner-user');
    assert.strictEqual(log.group_id, 'share-grp');

    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should deny share by non-owner', async () => {
    const tmpDir2 = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-share-deny-'));
    await fs.mkdir(path.join(tmpDir2, 'L2-warm', 'learnings'), { recursive: true });
    await fs.mkdir(path.join(tmpDir2, 'L2-warm', 'entities'), { recursive: true });
    await fs.mkdir(path.join(tmpDir2, 'L2-warm', 'sessions'), { recursive: true });

    const { setStorageProvider } = await import('./storage.js');
    const provider = new SqliteStorageProvider(tmpDir2);
    await provider.initialize();
    setStorageProvider(provider);

    await provider.writeL1('alice2', Buffer.from('{}'));
    await provider.writeL1('bob2', Buffer.from('{}'));
    await provider.createGroup('deny-grp', 'Deny Group', '{}', '{}');
    await provider.addMember('deny-grp', 'alice2', 'owner');
    await provider.addMember('deny-grp', 'bob2', 'member');

    const l2 = await import('./l2.js');
    const writeResult = await l2.writeItem('learning', {
      type: 'insight',
      content: 'Private to alice',
      confidence: 0.5,
    });
    const itemId = (writeResult as { success: true; id: string }).id;
    provider.getDatabase().prepare('UPDATE l2_items SET owner_id = ? WHERE id = ?').run('alice2', itemId);

    // Bob tries to share alice's item
    const shareResult = await l2.shareItem(itemId, 'deny-grp', 'bob2');
    assert.ok('error' in shareResult);
    assert.strictEqual(shareResult.error, 'not_owner');

    await provider.close();
    await fs.rm(tmpDir2, { recursive: true, force: true });
  });
});
