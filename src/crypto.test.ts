/**
 * Project Cordelia - Crypto Module Tests
 *
 * Tests for NullCryptoProvider and isEncryptedPayload utility.
 * Legacy Aes256GcmProvider tests removed in E5 (scrypt encryption replaced by group PSKs).
 *
 * Run with: node --test --import tsx src/crypto.test.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  NullCryptoProvider,
  isEncryptedPayload,
  type EncryptedPayload,
} from './crypto.js';

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
      /Legacy scrypt encryption removed/
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
      /Legacy scrypt encryption removed/
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
