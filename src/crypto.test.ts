/**
 * Project Cordelia - Crypto Module Tests
 *
 * Run with: node --test --import tsx src/crypto.test.ts
 */

import { describe, it, before, beforeEach, afterEach as _afterEach } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'crypto';
import {
  Aes256GcmProvider,
  NullCryptoProvider,
  isEncryptedPayload,
  type EncryptedPayload,
} from './crypto.js';

describe('Aes256GcmProvider', () => {
  let provider: Aes256GcmProvider;
  const testPassphrase = 'test-passphrase-for-testing';
  const testSalt = crypto.randomBytes(32);

  beforeEach(async () => {
    provider = new Aes256GcmProvider();
    await provider.unlock(testPassphrase, testSalt);
  });

  it('should be unlocked after unlock()', () => {
    assert.strictEqual(provider.isUnlocked(), true);
  });

  it('should not be unlocked before unlock()', () => {
    const newProvider = new Aes256GcmProvider();
    assert.strictEqual(newProvider.isUnlocked(), false);
  });

  it('should encrypt and decrypt round-trip correctly', async () => {
    const plaintext = Buffer.from('Hello, World! This is sensitive data.', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(encrypted);

    assert.deepStrictEqual(decrypted, plaintext);
  });

  it('should encrypt JSON data correctly', async () => {
    const data = {
      id: 'test-123',
      name: 'Test Entity',
      tags: ['tag1', 'tag2'],
      nested: { key: 'value' },
    };
    const plaintext = Buffer.from(JSON.stringify(data, null, 2), 'utf-8');
    const encrypted = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(encrypted);
    const parsed = JSON.parse(decrypted.toString('utf-8'));

    assert.deepStrictEqual(parsed, data);
  });

  it('should produce encrypted payload with correct structure', async () => {
    const plaintext = Buffer.from('test data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    assert.strictEqual(encrypted._encrypted, true);
    assert.strictEqual(encrypted.version, 1);
    assert.strictEqual(typeof encrypted.iv, 'string');
    assert.strictEqual(typeof encrypted.authTag, 'string');
    assert.strictEqual(typeof encrypted.ciphertext, 'string');

    // IV should be 12 bytes (96 bits) base64 encoded
    const iv = Buffer.from(encrypted.iv, 'base64');
    assert.strictEqual(iv.length, 12);

    // Auth tag should be 16 bytes (128 bits) base64 encoded
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    assert.strictEqual(authTag.length, 16);
  });

  it('should generate unique IVs for each encryption', async () => {
    const plaintext = Buffer.from('same plaintext', 'utf-8');
    const encrypted1 = await provider.encrypt(plaintext);
    const encrypted2 = await provider.encrypt(plaintext);
    const encrypted3 = await provider.encrypt(plaintext);

    // IVs should all be different
    assert.notStrictEqual(encrypted1.iv, encrypted2.iv);
    assert.notStrictEqual(encrypted2.iv, encrypted3.iv);
    assert.notStrictEqual(encrypted1.iv, encrypted3.iv);

    // Ciphertexts should also be different due to different IVs
    assert.notStrictEqual(encrypted1.ciphertext, encrypted2.ciphertext);
  });

  it('should fail decryption with tampered ciphertext', async () => {
    const plaintext = Buffer.from('sensitive data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Tamper with ciphertext
    const ciphertextBytes = Buffer.from(encrypted.ciphertext, 'base64');
    ciphertextBytes[0] ^= 0xff; // Flip bits
    encrypted.ciphertext = ciphertextBytes.toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /authentication tag mismatch/
    );
  });

  it('should fail decryption with tampered auth tag', async () => {
    const plaintext = Buffer.from('sensitive data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Tamper with auth tag
    const authTagBytes = Buffer.from(encrypted.authTag, 'base64');
    authTagBytes[0] ^= 0xff;
    encrypted.authTag = authTagBytes.toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /authentication tag mismatch/
    );
  });

  it('should fail decryption with wrong IV', async () => {
    const plaintext = Buffer.from('sensitive data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Use a different IV
    encrypted.iv = crypto.randomBytes(12).toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /authentication tag mismatch/
    );
  });

  it('should fail decryption with wrong key', async () => {
    const plaintext = Buffer.from('sensitive data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Create a new provider with different passphrase
    const wrongProvider = new Aes256GcmProvider();
    await wrongProvider.unlock('wrong-passphrase', testSalt);

    await assert.rejects(
      async () => wrongProvider.decrypt(encrypted),
      /authentication tag mismatch/
    );
  });

  it('should fail encryption when not unlocked', async () => {
    const lockedProvider = new Aes256GcmProvider();
    const plaintext = Buffer.from('test', 'utf-8');

    await assert.rejects(
      async () => lockedProvider.encrypt(plaintext),
      /not unlocked/
    );
  });

  it('should fail decryption when not unlocked', async () => {
    const plaintext = Buffer.from('test', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    const lockedProvider = new Aes256GcmProvider();

    await assert.rejects(
      async () => lockedProvider.decrypt(encrypted),
      /not unlocked/
    );
  });
});

describe('NullCryptoProvider', () => {
  const provider = new NullCryptoProvider();

  it('should always be unlocked', () => {
    assert.strictEqual(provider.isUnlocked(), true);
  });

  it('should have name "none"', () => {
    assert.strictEqual(provider.name, 'none');
  });

  it('should throw on encrypt', async () => {
    const plaintext = Buffer.from('test', 'utf-8');

    await assert.rejects(
      async () => provider.encrypt(plaintext),
      /no encryption key configured/
    );
  });

  it('should throw on decrypt', async () => {
    const payload: EncryptedPayload = {
      _encrypted: true,
      version: 1,
      iv: 'AAAAAAAAAAAAAAAA',
      authTag: 'AAAAAAAAAAAAAAAAAAAAAA==',
      ciphertext: 'test',
    };

    await assert.rejects(
      async () => provider.decrypt(payload),
      /no encryption key configured/
    );
  });
});

describe('isEncryptedPayload', () => {
  it('should return true for valid encrypted payload', () => {
    const payload = {
      _encrypted: true,
      version: 1,
      iv: 'AAAAAAAAAAAAAAAA',
      authTag: 'AAAAAAAAAAAAAAAAAAAAAA==',
      ciphertext: 'encrypted-content',
    };

    assert.strictEqual(isEncryptedPayload(payload), true);
  });

  it('should return false for plaintext object', () => {
    const data = {
      id: 'test',
      name: 'Test Entity',
    };

    assert.strictEqual(isEncryptedPayload(data), false);
  });

  it('should return false for object with _encrypted: false', () => {
    const data = {
      _encrypted: false,
      version: 1,
      iv: 'test',
      authTag: 'test',
      ciphertext: 'test',
    };

    assert.strictEqual(isEncryptedPayload(data), false);
  });

  it('should return false for object missing version', () => {
    const data = {
      _encrypted: true,
      iv: 'test',
      authTag: 'test',
      ciphertext: 'test',
    };

    assert.strictEqual(isEncryptedPayload(data), false);
  });

  it('should return false for null', () => {
    assert.strictEqual(isEncryptedPayload(null), false);
  });

  it('should return false for non-object', () => {
    assert.strictEqual(isEncryptedPayload('string'), false);
    assert.strictEqual(isEncryptedPayload(123), false);
    assert.strictEqual(isEncryptedPayload(undefined), false);
  });
});

// Edge case tests (S3 expansion)
describe('Crypto edge cases', () => {
  let provider: Aes256GcmProvider;
  const testPassphrase = 'edge-case-passphrase';
  const testSalt = crypto.randomBytes(32);

  before(async () => {
    provider = new Aes256GcmProvider();
    await provider.unlock(testPassphrase, testSalt);
  });

  it('should handle empty plaintext', async () => {
    const plaintext = Buffer.alloc(0);
    const encrypted = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(encrypted);
    assert.strictEqual(decrypted.length, 0);
  });

  it('should handle plaintext with null bytes', async () => {
    const plaintext = Buffer.from([0x00, 0x00, 0x00, 0x41, 0x00, 0x42]);
    const encrypted = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(encrypted);
    assert.deepStrictEqual(decrypted, plaintext);
  });

  it('should handle large plaintext (1MB)', async () => {
    const plaintext = crypto.randomBytes(1024 * 1024);
    const encrypted = await provider.encrypt(plaintext);
    const decrypted = await provider.decrypt(encrypted);
    assert.deepStrictEqual(decrypted, plaintext);
  });

  it('should reject truncated ciphertext', async () => {
    const plaintext = Buffer.from('test data for truncation', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Truncate ciphertext
    const originalCiphertext = Buffer.from(encrypted.ciphertext, 'base64');
    encrypted.ciphertext = originalCiphertext.subarray(0, 2).toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /authentication tag mismatch/,
    );
  });

  it('should reject empty ciphertext', async () => {
    const encrypted: EncryptedPayload = {
      _encrypted: true,
      version: 1,
      iv: crypto.randomBytes(12).toString('base64'),
      authTag: crypto.randomBytes(16).toString('base64'),
      ciphertext: '',
    };

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /authentication tag mismatch/,
    );
  });

  it('should reject wrong IV length', async () => {
    const plaintext = Buffer.from('test', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Use wrong-length IV (8 bytes instead of 12)
    encrypted.iv = crypto.randomBytes(8).toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
    );
  });

  it('should reject wrong authTag length', async () => {
    const plaintext = Buffer.from('test', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    // Use wrong-length authTag (8 bytes instead of 16)
    encrypted.authTag = crypto.randomBytes(8).toString('base64');

    await assert.rejects(
      async () => provider.decrypt(encrypted),
    );
  });

  it('should reject unsupported version', async () => {
    const encrypted: EncryptedPayload = {
      _encrypted: true,
      version: 1,
      iv: crypto.randomBytes(12).toString('base64'),
      authTag: crypto.randomBytes(16).toString('base64'),
      ciphertext: Buffer.from('test').toString('base64'),
    };

    // Force version 2
    (encrypted as { version: number }).version = 2;

    await assert.rejects(
      async () => provider.decrypt(encrypted),
      /Unsupported encryption version/,
    );
  });

  it('should produce different ciphertexts for same plaintext (IV uniqueness)', async () => {
    const plaintext = Buffer.from('identical plaintext', 'utf-8');
    const results = await Promise.all(
      Array.from({ length: 10 }, () => provider.encrypt(plaintext)),
    );

    const ciphertexts = new Set(results.map((r) => r.ciphertext));
    assert.strictEqual(ciphertexts.size, 10, 'All 10 ciphertexts should be unique');
  });

  it('should not decrypt with key from different passphrase', async () => {
    const plaintext = Buffer.from('secret data', 'utf-8');
    const encrypted = await provider.encrypt(plaintext);

    const wrongProvider = new Aes256GcmProvider();
    await wrongProvider.unlock('completely-different-passphrase', testSalt);

    await assert.rejects(
      async () => wrongProvider.decrypt(encrypted),
      /authentication tag mismatch/,
    );
  });
});

describe('Key derivation consistency', () => {
  it('should derive same key from same passphrase and salt', async () => {
    const passphrase = 'consistent-passphrase';
    const salt = crypto.randomBytes(32);

    const provider1 = new Aes256GcmProvider();
    await provider1.unlock(passphrase, salt);

    const provider2 = new Aes256GcmProvider();
    await provider2.unlock(passphrase, salt);

    // Encrypt with provider1, decrypt with provider2
    const plaintext = Buffer.from('test data for consistency', 'utf-8');
    const encrypted = await provider1.encrypt(plaintext);
    const decrypted = await provider2.decrypt(encrypted);

    assert.deepStrictEqual(decrypted, plaintext);
  });

  it('should derive different keys from different salts', async () => {
    const passphrase = 'same-passphrase';
    const salt1 = crypto.randomBytes(32);
    const salt2 = crypto.randomBytes(32);

    const provider1 = new Aes256GcmProvider();
    await provider1.unlock(passphrase, salt1);

    const provider2 = new Aes256GcmProvider();
    await provider2.unlock(passphrase, salt2);

    const plaintext = Buffer.from('test data', 'utf-8');
    const encrypted = await provider1.encrypt(plaintext);

    // Should fail because different salt = different key
    await assert.rejects(
      async () => provider2.decrypt(encrypted),
      /authentication tag mismatch/
    );
  });
});
