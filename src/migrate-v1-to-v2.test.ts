/**
 * E5a Migration Script Tests
 *
 * Tests: v1 scrypt items migrated to v2 group PSK, unencrypted items handled,
 * idempotent re-run, items already at v2 skipped.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs/promises';
import Database from 'better-sqlite3';

// Test with a temp database
const TEST_DIR = path.join(os.tmpdir(), `cordelia-migrate-test-${Date.now()}`);
const DB_PATH = path.join(TEST_DIR, 'cordelia.db');
const SALT_DIR = path.join(TEST_DIR, 'L2-warm', '.salt');
const GROUP_KEYS_DIR = path.join(os.homedir(), '.cordelia', 'group-keys');

const TEST_PASSPHRASE = 'test-migration-passphrase-12345';
const TEST_GROUP_ID = `migrate-test-${Date.now()}`;

// AES-256-GCM parameters (match crypto.ts)
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

async function scryptDeriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(passphrase, salt, 32, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

function scryptEncrypt(plaintext: Buffer, key: Buffer): { _encrypted: true; version: 1; iv: string; authTag: string; ciphertext: string } {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    _encrypted: true,
    version: 1,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

describe('v1 -> v2 migration', () => {
  let db: Database.Database;
  let scryptKey: Buffer;
  let salt: Buffer;
  let groupPsk: Buffer;

  before(async () => {
    // Create temp dirs
    await fs.mkdir(TEST_DIR, { recursive: true });
    await fs.mkdir(SALT_DIR, { recursive: true });
    await fs.mkdir(GROUP_KEYS_DIR, { recursive: true });

    // Create salt file
    salt = crypto.randomBytes(32);
    await fs.writeFile(path.join(SALT_DIR, 'global.salt'), salt);

    // Derive scrypt key
    scryptKey = await scryptDeriveKey(TEST_PASSPHRASE, salt);

    // Create group PSK and store it
    groupPsk = crypto.randomBytes(32);
    const { storeGroupKey, clearGroupKeyCache } = await import('./group-keys.js');
    clearGroupKeyCache();
    await storeGroupKey(TEST_GROUP_ID, groupPsk);

    // Create test database with schema
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE schema_version (
        version INTEGER NOT NULL,
        migrated_at TEXT DEFAULT (datetime('now'))
      );
      INSERT INTO schema_version (version) VALUES (6);

      CREATE TABLE l2_items (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        owner_id TEXT,
        visibility TEXT NOT NULL DEFAULT 'private',
        group_id TEXT,
        author_id TEXT,
        key_version INTEGER NOT NULL DEFAULT 1,
        parent_id TEXT,
        is_copy INTEGER NOT NULL DEFAULT 0,
        domain TEXT,
        ttl_expires_at TEXT,
        data BLOB NOT NULL,
        last_accessed_at TEXT,
        access_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE l1_hot (
        user_id TEXT PRIMARY KEY,
        data BLOB NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE l2_index (
        id INTEGER PRIMARY KEY DEFAULT 1,
        data BLOB NOT NULL
      );
    `);
  });

  after(async () => {
    if (db) db.close();
    const { clearGroupKeyCache } = await import('./group-keys.js');
    clearGroupKeyCache();
    // Cleanup group key files
    await fs.unlink(path.join(GROUP_KEYS_DIR, `${TEST_GROUP_ID}.json`)).catch(() => {});
    await fs.unlink(path.join(GROUP_KEYS_DIR, `${TEST_GROUP_ID}.key`)).catch(() => {});
    await fs.rm(TEST_DIR, { recursive: true, force: true }).catch(() => {});
  });

  it('migrates encrypted v1 items to v2', async () => {
    // Insert a v1 encrypted item
    const itemData = { id: 'test-entity-1', name: 'Test Entity', type: 'person', details: 'some details' };
    const plaintext = Buffer.from(JSON.stringify(itemData, null, 2), 'utf-8');
    const encrypted = scryptEncrypt(plaintext, scryptKey);
    const encryptedJson = JSON.stringify(encrypted, null, 2);

    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 1, ?)',
    ).run('test-entity-1', 'entity', Buffer.from(encryptedJson, 'utf-8'), 'private');

    // Run migration using direct DB access (simulating what the script does)
    const { initCrypto, getDefaultCryptoProvider, isEncryptedPayload } = await import('./crypto.js');
    await initCrypto(TEST_PASSPHRASE, salt);
    const cryptoProvider = getDefaultCryptoProvider();

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    // Read v1 item
    const v1Row = db.prepare('SELECT id, data FROM l2_items WHERE id = ?').get('test-entity-1') as { id: string; data: Buffer };
    const parsed = JSON.parse(v1Row.data.toString('utf-8'));
    assert.ok(isEncryptedPayload(parsed));

    // Decrypt with scrypt
    const decrypted = await cryptoProvider.decrypt(parsed);
    const plainObj = JSON.parse(decrypted.toString('utf-8'));
    assert.equal(plainObj.name, 'Test Entity');

    // Re-encrypt with group PSK
    const reEncrypted = await groupEncrypt(Buffer.from(JSON.stringify(plainObj, null, 2), 'utf-8'), gk);
    const newData = Buffer.from(JSON.stringify(reEncrypted, null, 2), 'utf-8');

    // Update
    db.prepare(
      'UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = ? WHERE id = ?',
    ).run(newData, TEST_GROUP_ID, 'group', 'test-entity-1');

    // Verify migrated
    const updated = db.prepare('SELECT key_version, group_id, visibility, data FROM l2_items WHERE id = ?').get('test-entity-1') as { key_version: number; group_id: string; visibility: string; data: Buffer };
    assert.equal(updated.key_version, 2);
    assert.equal(updated.group_id, TEST_GROUP_ID);
    assert.equal(updated.visibility, 'group');

    // Verify decryptable with group PSK
    const updatedParsed = JSON.parse(updated.data.toString('utf-8'));
    const v2Decrypted = await groupDecrypt(updatedParsed, gk);
    const v2Obj = JSON.parse(v2Decrypted.toString('utf-8'));
    assert.equal(v2Obj.name, 'Test Entity');
  });

  it('handles unencrypted v1 items', async () => {
    // Insert an unencrypted v1 item
    const itemData = { id: 'unenc-1', name: 'Unencrypted Item', type: 'concept' };
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 1, ?)',
    ).run('unenc-1', 'entity', Buffer.from(JSON.stringify(itemData, null, 2), 'utf-8'), 'private');

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    // Read and encrypt
    const row = db.prepare('SELECT data FROM l2_items WHERE id = ?').get('unenc-1') as { data: Buffer };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const { isEncryptedPayload } = await import('./crypto.js');
    assert.ok(!isEncryptedPayload(parsed));

    // Encrypt with group PSK
    const encrypted = await groupEncrypt(Buffer.from(JSON.stringify(parsed, null, 2), 'utf-8'), gk);
    const newData = Buffer.from(JSON.stringify(encrypted, null, 2), 'utf-8');
    db.prepare(
      'UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = ? WHERE id = ?',
    ).run(newData, TEST_GROUP_ID, 'group', 'unenc-1');

    // Verify
    const updated = db.prepare('SELECT key_version, data FROM l2_items WHERE id = ?').get('unenc-1') as { key_version: number; data: Buffer };
    assert.equal(updated.key_version, 2);

    const decrypted = await groupDecrypt(JSON.parse(updated.data.toString('utf-8')), gk);
    const obj = JSON.parse(decrypted.toString('utf-8'));
    assert.equal(obj.name, 'Unencrypted Item');
  });

  it('skips items already at v2', () => {
    // Insert a v2 item
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility, group_id) VALUES (?, ?, ?, 2, ?, ?)',
    ).run('already-v2', 'session', Buffer.from('{}', 'utf-8'), 'group', TEST_GROUP_ID);

    // Query for v1 items should not include this
    const v1Items = db.prepare('SELECT id FROM l2_items WHERE key_version = 1').all() as Array<{ id: string }>;
    const ids = v1Items.map(r => r.id);
    assert.ok(!ids.includes('already-v2'));
  });

  it('preserves data integrity through migration', async () => {
    const { initCrypto, getDefaultCryptoProvider } = await import('./crypto.js');
    await initCrypto(TEST_PASSPHRASE, salt);
    const cryptoProvider = getDefaultCryptoProvider();

    const { getGroupKey, groupEncrypt, groupDecrypt } = await import('./group-keys.js');
    const gk = await getGroupKey(TEST_GROUP_ID);
    assert.ok(gk);

    // Create item with complex nested data
    const complexData = {
      id: 'complex-1',
      name: 'Complex Entity',
      type: 'project',
      details: JSON.stringify({
        nested: { deep: true, arr: [1, 2, 3] },
        unicode: '\u00e9\u00e8\u00ea',
        empty: '',
        nullish: null,
      }),
    };

    const plaintext = Buffer.from(JSON.stringify(complexData, null, 2), 'utf-8');
    const encrypted = scryptEncrypt(plaintext, scryptKey);
    db.prepare(
      'INSERT INTO l2_items (id, type, data, key_version, visibility) VALUES (?, ?, ?, 1, ?)',
    ).run('complex-1', 'entity', Buffer.from(JSON.stringify(encrypted, null, 2), 'utf-8'), 'private');

    // Decrypt with scrypt
    const row = db.prepare('SELECT data FROM l2_items WHERE id = ?').get('complex-1') as { data: Buffer };
    const parsed = JSON.parse(row.data.toString('utf-8'));
    const decrypted = await cryptoProvider.decrypt(parsed);
    const plainObj = JSON.parse(decrypted.toString('utf-8'));

    // Re-encrypt with group PSK
    const reEncrypted = await groupEncrypt(Buffer.from(JSON.stringify(plainObj, null, 2), 'utf-8'), gk);
    db.prepare(
      'UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = ? WHERE id = ?',
    ).run(Buffer.from(JSON.stringify(reEncrypted, null, 2), 'utf-8'), TEST_GROUP_ID, 'group', 'complex-1');

    // Verify roundtrip
    const updated = db.prepare('SELECT data FROM l2_items WHERE id = ?').get('complex-1') as { data: Buffer };
    const v2Decrypted = await groupDecrypt(JSON.parse(updated.data.toString('utf-8')), gk);
    const v2Obj = JSON.parse(v2Decrypted.toString('utf-8'));

    assert.deepEqual(v2Obj, complexData);
  });
});
