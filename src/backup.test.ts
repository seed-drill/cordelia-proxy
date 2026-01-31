/**
 * Project Cordelia - Backup & Restore Tests
 *
 * Tests for backup/restore round-trip, manifest verification,
 * schema migration on restore, and corruption detection.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageProvider } from './storage-sqlite.js';
import { setStorageProvider } from './storage.js';
import { createBackup, restoreBackup, verifyBackup } from './backup.js';

describe('createBackup', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;
  let backupDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-backup-'));
    backupDir = path.join(tmpDir, 'backups');
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);

    // Seed some data
    await provider.writeL1('alice', Buffer.from(JSON.stringify({ version: 1, name: 'Alice' })));
    await provider.writeL2Item('item-1', 'entity', Buffer.from(JSON.stringify({ id: 'item-1', name: 'Test' })), { type: 'entity' });
    await provider.writeL2Item('item-2', 'learning', Buffer.from(JSON.stringify({ id: 'item-2', content: 'Learning' })), { type: 'learning' });
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should create a valid backup with manifest', async () => {
    const result = await createBackup(backupDir);

    assert.ok(result.manifest, 'should have manifest');
    assert.strictEqual(result.manifest.version, 1);
    assert.strictEqual(result.manifest.item_count, 2);
    assert.ok(result.manifest.l1_users.includes('alice'));
    assert.ok(result.manifest.db_sha256);
    assert.ok(result.size > 0);
    assert.ok(result.duration_ms >= 0);

    // Verify files exist
    assert.ok(fsSync.existsSync(result.dbPath), 'backup DB should exist');
    assert.ok(fsSync.existsSync(result.manifestPath), 'manifest should exist');
  });

  it('should create backup DB that is independently openable', async () => {
    const result = await createBackup(backupDir);
    const Database = (await import('better-sqlite3')).default;
    const backupDb = new Database(result.dbPath, { readonly: true });

    try {
      const items = backupDb.prepare('SELECT COUNT(*) as cnt FROM l2_items').get() as { cnt: number };
      assert.strictEqual(items.cnt, 2);

      const users = backupDb.prepare('SELECT user_id FROM l1_hot').all() as Array<{ user_id: string }>;
      assert.ok(users.some((u) => u.user_id === 'alice'));
    } finally {
      backupDb.close();
    }
  });

  it('should produce valid SHA-256 in manifest', async () => {
    const result = await createBackup(backupDir);
    const actualHash = crypto.createHash('sha256')
      .update(fsSync.readFileSync(result.dbPath))
      .digest('hex');
    assert.strictEqual(result.manifest.db_sha256, actualHash);
  });
});

describe('verifyBackup', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;
  let backupDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-verify-'));
    backupDir = path.join(tmpDir, 'backups');
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);

    await provider.writeL2Item('verify-item', 'entity', Buffer.from('{"id":"verify-item"}'), { type: 'entity' });
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should pass for valid backup', async () => {
    const backup = await createBackup(backupDir);
    const result = await verifyBackup(path.dirname(backup.dbPath));
    assert.strictEqual(result.ok, true, `Errors: ${result.errors.join(', ')}`);
    assert.strictEqual(result.manifest.item_count, 1);
  });

  it('should fail for corrupted backup (bad SHA)', async () => {
    // Use isolated directory to avoid picking up other backup files
    const corruptDir = path.join(tmpDir, 'corrupt-backup');
    const backup = await createBackup(corruptDir);

    // Corrupt the DB file
    const content = fsSync.readFileSync(backup.dbPath);
    content[100] ^= 0xff;
    fsSync.writeFileSync(backup.dbPath, content);

    const result = await verifyBackup(corruptDir);
    assert.strictEqual(result.ok, false, `Expected failure but got: ${JSON.stringify(result)}`);
    assert.ok(result.errors.some((e) => e.includes('SHA-256')));
  });

  it('should fail for missing manifest', async () => {
    const emptyDir = path.join(tmpDir, 'empty-backup');
    await fs.mkdir(emptyDir, { recursive: true });
    await fs.writeFile(path.join(emptyDir, 'test.db'), 'fake');

    const result = await verifyBackup(emptyDir);
    assert.strictEqual(result.ok, false);
  });
});

describe('restoreBackup', () => {
  it('should round-trip backup and restore', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-restore-src-'));
    const backupDir = path.join(srcDir, 'backups');

    const srcProvider = new SqliteStorageProvider(srcDir);
    await srcProvider.initialize();
    setStorageProvider(srcProvider);

    // Seed data
    await srcProvider.writeL1('bob', Buffer.from(JSON.stringify({ version: 1, name: 'Bob' })));
    await srcProvider.writeL2Item('restore-1', 'entity', Buffer.from(JSON.stringify({ id: 'restore-1', name: 'Restore Test' })), { type: 'entity' });
    await srcProvider.writeL2Item('restore-2', 'session', Buffer.from(JSON.stringify({ id: 'restore-2', focus: 'Test' })), { type: 'session' });

    // Create backup
    const backup = await createBackup(backupDir);

    // Modify the live DB (to verify restore overwrites)
    await srcProvider.writeL2Item('restore-3', 'learning', Buffer.from(JSON.stringify({ id: 'restore-3', content: 'New' })), { type: 'learning' });

    // Restore from backup
    const result = await restoreBackup(path.dirname(backup.dbPath));

    assert.strictEqual(result.items, 2, 'should restore 2 items (not 3)');
    assert.strictEqual(result.schemaVersion, 4);

    // Verify data is restored
    const l1 = await srcProvider.readL1('bob');
    assert.ok(l1, 'L1 data should be restored');

    const item = await srcProvider.readL2Item('restore-1');
    assert.ok(item, 'L2 item should be restored');

    // The item added after backup should be gone
    const missing = await srcProvider.readL2Item('restore-3');
    assert.strictEqual(missing, null, 'Post-backup item should not exist');

    await srcProvider.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });

  it('should support dry-run mode', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-dryrun-'));
    const backupDir = path.join(srcDir, 'backups');

    const provider = new SqliteStorageProvider(srcDir);
    await provider.initialize();
    setStorageProvider(provider);

    await provider.writeL2Item('dryrun-1', 'entity', Buffer.from('{"id":"dryrun-1"}'), { type: 'entity' });
    const backup = await createBackup(backupDir);

    // Add more data
    await provider.writeL2Item('dryrun-2', 'entity', Buffer.from('{"id":"dryrun-2"}'), { type: 'entity' });

    // Dry run should not modify anything
    const result = await restoreBackup(path.dirname(backup.dbPath), { dryRun: true });
    assert.strictEqual(result.items, 1);

    // Original data should still include dryrun-2
    const item = await provider.readL2Item('dryrun-2');
    assert.ok(item, 'dryrun-2 should still exist after dry run');

    await provider.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });

  it('should reject corrupted backup', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-reject-'));
    const backupDir = path.join(srcDir, 'backups');

    const provider = new SqliteStorageProvider(srcDir);
    await provider.initialize();
    setStorageProvider(provider);

    await provider.writeL2Item('reject-1', 'entity', Buffer.from('{"id":"reject-1"}'), { type: 'entity' });
    const backup = await createBackup(backupDir);

    // Corrupt the backup
    const content = fsSync.readFileSync(backup.dbPath);
    content[100] ^= 0xff;
    fsSync.writeFileSync(backup.dbPath, content);

    await assert.rejects(
      async () => restoreBackup(path.dirname(backup.dbPath)),
      /SHA-256 mismatch/,
    );

    await provider.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });

  it('should handle empty database backup/restore', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-empty-'));
    const backupDir = path.join(srcDir, 'backups');

    const provider = new SqliteStorageProvider(srcDir);
    await provider.initialize();
    setStorageProvider(provider);

    const backup = await createBackup(backupDir);
    assert.strictEqual(backup.manifest.item_count, 0);
    assert.strictEqual(backup.manifest.l1_users.length, 0);

    const result = await restoreBackup(path.dirname(backup.dbPath));
    assert.strictEqual(result.items, 0);

    await provider.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });
});

describe('Schema migration on restore', () => {
  it('should migrate v2 backup to v3 on restore', async () => {
    const srcDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-migrate-restore-'));
    const backupDir = path.join(srcDir, 'backups');

    // Create a v2 database manually
    const Database = (await import('better-sqlite3')).default;
    const v2DbPath = path.join(backupDir, 'cordelia-backup-v2-test.db');
    await fs.mkdir(backupDir, { recursive: true });

    const v2Db = new Database(v2DbPath);
    v2Db.pragma('journal_mode = WAL');
    v2Db.exec(`
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
    v2Db.prepare('INSERT INTO schema_version (version) VALUES (2)').run();
    v2Db.prepare('INSERT INTO l2_items (id, type, data) VALUES (?, ?, ?)').run(
      'migrate-item', 'entity', Buffer.from('{"id":"migrate-item","name":"Migrated"}'),
    );
    v2Db.close();

    // Write a manifest for it
    const dbSha256 = crypto.createHash('sha256').update(fsSync.readFileSync(v2DbPath)).digest('hex');
    const manifest = {
      version: 1,
      created_at: new Date().toISOString(),
      schema_version: 2,
      item_count: 1,
      l1_users: [],
      db_sha256: dbSha256,
      chain_hashes: {},
    };
    await fs.writeFile(
      path.join(backupDir, 'cordelia-backup-v2-test.manifest.json'),
      JSON.stringify(manifest),
    );

    // Now create a live v3 DB and restore from v2 backup
    const liveProvider = new SqliteStorageProvider(srcDir);
    await liveProvider.initialize();
    setStorageProvider(liveProvider);

    const result = await restoreBackup(backupDir);
    assert.strictEqual(result.schemaVersion, 4, 'Should migrate to v4');
    assert.strictEqual(result.items, 1);

    // Verify checksum column exists (v3 feature)
    const db = liveProvider.getDatabase();
    const columns = db.pragma('table_info(l2_items)') as Array<{ name: string }>;
    assert.ok(columns.some((c) => c.name === 'checksum'), 'Should have checksum column after migration');

    // Verify canary exists (v3 feature)
    const canary = db.prepare('SELECT value FROM integrity_canary WHERE id = 1').get() as { value: string } | undefined;
    assert.ok(canary, 'Should have integrity canary after migration');

    await liveProvider.close();
    await fs.rm(srcDir, { recursive: true, force: true });
  });
});
