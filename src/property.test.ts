/**
 * Project Cordelia - Property-Based Tests
 *
 * Uses fast-check for property-based testing.
 * Tests invariants that must hold for all inputs.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import fc from 'fast-check';
import { Aes256GcmProvider } from './crypto.js';
import { SqliteStorageProvider } from './storage-sqlite.js';
import { setStorageProvider } from './storage.js';

describe('Property: Crypto encrypt/decrypt round-trip', () => {
  let provider: Aes256GcmProvider;

  before(async () => {
    provider = new Aes256GcmProvider();
    await provider.unlock('property-test-passphrase', crypto.randomBytes(32));
  });

  it('should round-trip any Buffer', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 0, maxLength: 10000 }),
        async (arr) => {
          const plaintext = Buffer.from(arr);
          const encrypted = await provider.encrypt(plaintext);
          const decrypted = await provider.decrypt(encrypted);
          assert.deepStrictEqual(decrypted, plaintext);
        },
      ),
      { numRuns: 50 },
    );
  });

  it('should produce different ciphertexts for same plaintext (unique IVs)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 100 }),
        async (arr) => {
          const plaintext = Buffer.from(arr);
          const enc1 = await provider.encrypt(plaintext);
          const enc2 = await provider.encrypt(plaintext);
          // IVs must differ
          assert.notStrictEqual(enc1.iv, enc2.iv);
          // Ciphertexts must differ (because IVs differ)
          assert.notStrictEqual(enc1.ciphertext, enc2.ciphertext);
        },
      ),
      { numRuns: 20 },
    );
  });

  it('should not decrypt with wrong key', async () => {
    const otherProvider = new Aes256GcmProvider();
    await otherProvider.unlock('different-passphrase', crypto.randomBytes(32));

    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 100 }),
        async (arr) => {
          const plaintext = Buffer.from(arr);
          const encrypted = await provider.encrypt(plaintext);

          try {
            await otherProvider.decrypt(encrypted);
            assert.fail('Should have thrown');
          } catch (e) {
            assert.ok((e as Error).message.includes('authentication tag mismatch') || (e as Error).message.includes('fail'));
          }
        },
      ),
      { numRuns: 10 },
    );
  });
});

describe('Property: L1 storage round-trip', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-prop-l1-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should round-trip arbitrary JSON as L1 data', async () => {
    let counter = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.json(),
        async (jsonStr) => {
          const userId = `prop-user-${counter++}`;
          const data = Buffer.from(jsonStr, 'utf-8');
          await provider.writeL1(userId, data);
          const result = await provider.readL1(userId);
          assert.ok(result);
          assert.strictEqual(result.toString('utf-8'), jsonStr);
        },
      ),
      { numRuns: 30 },
    );
  });
});

describe('Property: L2 storage round-trip', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-prop-l2-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should round-trip arbitrary JSON as L2 items', async () => {
    let counter = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.json(),
        async (jsonStr) => {
          const id = `prop-item-${counter++}`;
          const data = Buffer.from(jsonStr, 'utf-8');
          await provider.writeL2Item(id, 'entity', data, { type: 'entity' });
          const result = await provider.readL2Item(id);
          assert.ok(result);
          assert.strictEqual(result.data.toString('utf-8'), jsonStr);
          assert.strictEqual(result.type, 'entity');
        },
      ),
      { numRuns: 30 },
    );
  });

  it('should compute correct checksums for arbitrary data', async () => {
    let counter = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 0, maxLength: 5000 }),
        async (arr) => {
          const id = `prop-checksum-${counter++}`;
          const data = Buffer.from(arr);
          await provider.writeL2Item(id, 'entity', data, { type: 'entity' });

          const db = provider.getDatabase();
          const row = db.prepare('SELECT checksum FROM l2_items WHERE id = ?').get(id) as { checksum: string };
          const expected = crypto.createHash('sha256').update(data).digest('hex');
          assert.strictEqual(row.checksum, expected);
        },
      ),
      { numRuns: 20 },
    );
  });
});

describe('Property: FTS search does not crash', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-prop-fts-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);

    // Seed some FTS data
    await provider.ftsUpsert('fts-1', 'Test Item', 'this is searchable content', 'tag1 tag2');
    await provider.ftsUpsert('fts-2', 'Another Item', 'more content here', 'tag3');
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should not crash on arbitrary search queries', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 0, maxLength: 200 }),
        async (query) => {
          // Should never throw, regardless of input
          const results = await provider.ftsSearch(query, 10);
          assert.ok(Array.isArray(results));
        },
      ),
      { numRuns: 50 },
    );
  });
});
