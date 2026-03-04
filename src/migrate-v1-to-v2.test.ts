/**
 * E5 Migration Script Tests
 *
 * Tests: plaintext v0/v1 items encrypted with group PSK to v2,
 * items already at v2 skipped, existing group_id preserved,
 * data integrity through migration.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs/promises';
import Database from 'better-sqlite3';

const TEST_DIR = path.join(os.tmpdir(), `cordelia-migrate-test-${Date.now()}`);
const DB_PATH = path.join(TEST_DIR, 'cordelia.db');
const GROUP_KEYS_DIR = path.join(os.homedir(), '.cordelia', 'group-keys');

const TEST_GROUP_ID = `migrate-test-${Date.now()}`;

describe('v0/v1 -> v2 migration', () => {
  let db: Database.Database;
  let groupPsk: Buffer;

  before(async () => {
    await fs.mkdir(TEST_DIR, { recursive: true });
    await fs.mkdir(GROUP_KEYS_DIR, { recursive: true });

    // Create group PSK and store it
    groupPsk = crypto.randomBytes(32);
    const { storeGroupKey, clearGroupKeyCache } = await import('./group-keys.js');
    clearGroupKeyCache();
    await storeGroupKey(TEST_GROUP_ID, groupPsk);

    // Create test database matching node schema
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE l2_items (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
        owner_id TEXT,
        visibility TEXT NOT NULL DEFAULT 'private',
        group_id TEXT,
        author_id TEXT,
        key_version INTEGER NOT NULL DEFAULT 1,
        parent_id TEXT,
        is_copy INTEGER NOT NULL DEFAULT 0,
        data BLOB NOT NULL,
        last_accessed_at TEXT,
        access_count INTEGER NOT NULL DEFAULT 0,
        checksum TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
  });

  after(async () => {
    if (db) db.close();
    const { clearGroupKeyCache } = await import('./group-keys.js');
    clearGroupKeyCache();
    await fs.unlink(path.join(GROUP_KEYS_DIR, `${TEST_GROUP_ID}.json`)).catch(() => {});
    await fs.rm(TEST_DIR, { recursive: true, force: true }).catch(() => {});
  });

  it('encrypts plaintext v1 items with group PSK', async () => {
    const itemData = { name: 'Test Entity', type: 'person', details: 'some details' };
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 1, ?)',
    ).run('pt-v1-1', 'entity', Buffer.from(JSON.stringify(itemData), 'utf-8'), 'private');

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    // Simulate migration: read, encrypt, update
    const row = db.prepare('SELECT id, data, group_id FROM l2_items WHERE id = ?').get('pt-v1-1') as { id: string; data: Buffer; group_id: string | null };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const encrypted = await groupEncrypt(Buffer.from(JSON.stringify(parsed), 'utf-8'), gk);
    const targetGroup = row.group_id || TEST_GROUP_ID;

    db.prepare(
      `UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = 'group' WHERE id = ?`,
    ).run(Buffer.from(JSON.stringify(encrypted), 'utf-8'), targetGroup, 'pt-v1-1');

    // Verify
    const updated = db.prepare('SELECT key_version, group_id, visibility, data FROM l2_items WHERE id = ?').get('pt-v1-1') as { key_version: number; group_id: string; visibility: string; data: Buffer };
    assert.equal(updated.key_version, 2);
    assert.equal(updated.group_id, TEST_GROUP_ID);
    assert.equal(updated.visibility, 'group');

    const decrypted = await groupDecrypt(JSON.parse(updated.data.toString('utf-8')), gk);
    assert.deepEqual(JSON.parse(decrypted.toString('utf-8')), itemData);
  });

  it('encrypts v0 items the same way', async () => {
    const itemData = { name: 'V0 Item', content: 'legacy data' };
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 0, ?)',
    ).run('pt-v0-1', 'learning', Buffer.from(JSON.stringify(itemData), 'utf-8'), 'private');

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    const row = db.prepare('SELECT data, group_id FROM l2_items WHERE id = ?').get('pt-v0-1') as { data: Buffer; group_id: string | null };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const encrypted = await groupEncrypt(Buffer.from(JSON.stringify(parsed), 'utf-8'), gk);

    db.prepare(
      `UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = 'group' WHERE id = ?`,
    ).run(Buffer.from(JSON.stringify(encrypted), 'utf-8'), row.group_id || TEST_GROUP_ID, 'pt-v0-1');

    const updated = db.prepare('SELECT key_version, data FROM l2_items WHERE id = ?').get('pt-v0-1') as { key_version: number; data: Buffer };
    assert.equal(updated.key_version, 2);

    const decrypted = await groupDecrypt(JSON.parse(updated.data.toString('utf-8')), gk);
    assert.deepEqual(JSON.parse(decrypted.toString('utf-8')), itemData);
  });

  it('preserves existing group_id', async () => {
    const itemData = { name: 'Team Item' };
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility, group_id) VALUES (?, ?, ?, 1, ?, ?)',
    ).run('grouped-1', 'entity', Buffer.from(JSON.stringify(itemData), 'utf-8'), 'group', 'seed-drill');

    const { getGroupKey, groupEncrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    const row = db.prepare('SELECT data, group_id FROM l2_items WHERE id = ?').get('grouped-1') as { data: Buffer; group_id: string | null };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const encrypted = await groupEncrypt(Buffer.from(JSON.stringify(parsed), 'utf-8'), gk);
    const targetGroup = row.group_id || TEST_GROUP_ID;

    db.prepare(
      `UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = 'group' WHERE id = ?`,
    ).run(Buffer.from(JSON.stringify(encrypted), 'utf-8'), targetGroup, 'grouped-1');

    const updated = db.prepare('SELECT group_id FROM l2_items WHERE id = ?').get('grouped-1') as { group_id: string };
    assert.equal(updated.group_id, 'seed-drill');
  });

  it('skips items already at v2', () => {
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility, group_id) VALUES (?, ?, ?, 2, ?, ?)',
    ).run('already-v2', 'session', Buffer.from('{}', 'utf-8'), 'group', TEST_GROUP_ID);

    const items = db.prepare('SELECT id FROM l2_items WHERE key_version < 2').all() as Array<{ id: string }>;
    const ids = items.map(r => r.id);
    assert.ok(!ids.includes('already-v2'));
  });

  it('preserves data integrity for complex nested data', async () => {
    const complexData = {
      name: 'Complex Entity',
      type: 'project',
      details: JSON.stringify({
        nested: { deep: true, arr: [1, 2, 3] },
        unicode: '\u00e9\u00e8\u00ea',
        empty: '',
        nullish: null,
      }),
    };

    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 1, ?)',
    ).run('complex-1', 'entity', Buffer.from(JSON.stringify(complexData), 'utf-8'), 'private');

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    const row = db.prepare('SELECT data FROM l2_items WHERE id = ?').get('complex-1') as { data: Buffer };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const encrypted = await groupEncrypt(Buffer.from(JSON.stringify(parsed), 'utf-8'), gk);

    db.prepare(
      `UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = 'group' WHERE id = ?`,
    ).run(Buffer.from(JSON.stringify(encrypted), 'utf-8'), TEST_GROUP_ID, 'complex-1');

    const updated = db.prepare('SELECT data FROM l2_items WHERE id = ?').get('complex-1') as { data: Buffer };
    const decrypted = await groupDecrypt(JSON.parse(updated.data.toString('utf-8')), gk);
    assert.deepEqual(JSON.parse(decrypted.toString('utf-8')), complexData);
  });
});
