import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encryptL1, decryptL1 } from './group-keys.js';

describe('L1 encryption', () => {
  it('encryptL1 returns encrypted payload when personal group PSK exists', async () => {
    const plaintext = { version: 1, identity: { name: 'Test' }, updated_at: new Date().toISOString() };
    const result = await encryptL1(plaintext);

    if (result === null) {
      // No personal group PSK available -- skip (CI or fresh machine)
      console.log('  (skipped: no personal group PSK)');
      return;
    }

    assert.equal(result._encrypted, true);
    assert.equal(result.version, 1);
    assert.ok(typeof result.iv === 'string');
    assert.ok(typeof result.authTag === 'string');
    assert.ok(typeof result.ciphertext === 'string');
  });

  it('decryptL1 round-trips correctly', async () => {
    const plaintext = { version: 1, identity: { name: 'Round Trip' }, test_value: 42 };
    const encrypted = await encryptL1(plaintext);

    if (encrypted === null) {
      console.log('  (skipped: no personal group PSK)');
      return;
    }

    const decrypted = await decryptL1(encrypted);
    assert.deepEqual(decrypted, plaintext);
  });

  it('decryptL1 passes through plaintext data unchanged', async () => {
    const plaintext = { version: 1, identity: { name: 'Plaintext' } };
    const result = await decryptL1(plaintext);
    assert.deepEqual(result, plaintext);
  });

  it('decryptL1 handles partial encrypted-like objects as plaintext', async () => {
    // Has _encrypted but missing other fields -- should pass through
    const partial = { _encrypted: true, version: 1, identity: { name: 'Partial' } };
    const result = await decryptL1(partial as Record<string, unknown>);
    assert.deepEqual(result, partial);
  });
});
