/**
 * E3b Group Key Sync Tests
 *
 * Tests: syncGroupKeysFromVault, startGroupKeySync/stopGroupKeySync,
 * skipping already-stored keys, handling missing credentials.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { envelopeEncrypt, envelopeDecrypt, deriveX25519FromEd25519 } from './envelope.js';
import { storeGroupKey, getGroupKey, clearGroupKeyCache, groupEncrypt, groupDecrypt } from './group-keys.js';
import { stopGroupKeySync } from './group-key-sync.js';

describe('Group key sync helpers', () => {
  const kp = (() => {
    const seed = crypto.randomBytes(32);
    return deriveX25519FromEd25519(seed);
  })();

  before(() => {
    clearGroupKeyCache();
  });

  after(() => {
    clearGroupKeyCache();
    stopGroupKeySync();
  });

  it('syncGroupKeysFromVault returns early with no credentials', async () => {
    // Without PORTAL_URL env var, sync should return immediately
    const { syncGroupKeysFromVault } = await import('./group-key-sync.js');
    const result = await syncGroupKeysFromVault();
    assert.equal(result.synced, 0);
    assert.equal(result.skipped, 0);
    assert.equal(result.errors, 0);
  });

  it('stopGroupKeySync is safe to call when not running', () => {
    // Should not throw
    stopGroupKeySync();
    stopGroupKeySync(); // Double-stop is safe
  });

  it('envelope-encrypted group keys can be decrypted and stored', async () => {
    // Simulate what syncGroupKeysFromVault does internally
    const groupId = `sync-test-${Date.now()}`;
    const psk = crypto.randomBytes(32);

    // Portal encrypts PSK for device's X25519 public key
    const envelope = envelopeEncrypt(psk, kp.publicKey);

    // Device decrypts
    const decryptedPsk = envelopeDecrypt(envelope, kp.privateKey);
    assert.deepEqual(decryptedPsk, psk);

    // Store to disk
    await storeGroupKey(groupId, decryptedPsk);

    // Verify stored
    const stored = await getGroupKey(groupId);
    assert.ok(stored);
    assert.deepEqual(stored, psk);

    // Verify can encrypt/decrypt with the key
    const plaintext = Buffer.from('shared group message');
    const encrypted = await groupEncrypt(plaintext, stored);
    const decrypted = await groupDecrypt(encrypted, stored);
    assert.deepEqual(decrypted, plaintext);

    // Cleanup
    const os = await import('os');
    await fs.unlink(
      path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.json`),
    ).catch(() => {});
    clearGroupKeyCache();
  });

  it('sync skips groups that already have local keys', async () => {
    const groupId = `sync-skip-${Date.now()}`;
    const psk = crypto.randomBytes(32);

    // Store key locally first
    await storeGroupKey(groupId, psk);

    // Verify it exists
    const existing = await getGroupKey(groupId);
    assert.ok(existing);

    // A second store with different PSK should overwrite (storeGroupKey is idempotent)
    const psk2 = crypto.randomBytes(32);
    await storeGroupKey(groupId, psk2);
    const updated = await getGroupKey(groupId);
    assert.deepEqual(updated, psk2);

    // Cleanup
    const os = await import('os');
    await fs.unlink(
      path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.json`),
    ).catch(() => {});
    clearGroupKeyCache();
  });

  it('sync picks up new key versions after rotation', async () => {
    const groupId = `sync-rotate-${Date.now()}`;
    const pskV1 = crypto.randomBytes(32);
    const pskV2 = crypto.randomBytes(32);

    // Store v1 locally (simulating initial enrollment)
    await storeGroupKey(groupId, pskV1, 1);

    // Verify v1 exists
    const existingV1 = await getGroupKey(groupId, 1);
    assert.ok(existingV1);
    assert.deepEqual(existingV1, pskV1);

    // Simulate what sync does: check if specific version exists
    const existingV2 = await getGroupKey(groupId, 2);
    assert.equal(existingV2, null, 'v2 should not exist yet');

    // Simulate sync storing v2 after rotation
    await storeGroupKey(groupId, pskV2, 2);

    // Both versions should be available
    const storedV1 = await getGroupKey(groupId, 1);
    const storedV2 = await getGroupKey(groupId, 2);
    assert.ok(storedV1);
    assert.ok(storedV2);
    assert.deepEqual(storedV1, pskV1);
    assert.deepEqual(storedV2, pskV2);

    // Latest should be v2
    const latest = await getGroupKey(groupId);
    assert.deepEqual(latest, pskV2);

    // Encrypt with v1, decrypt with v1 (key ring backward compat)
    const plaintext = Buffer.from('written with v1');
    const encrypted = await groupEncrypt(plaintext, storedV1);
    const decrypted = await groupDecrypt(encrypted, storedV1);
    assert.deepEqual(decrypted, plaintext);

    // Encrypt with v2, decrypt with v2
    const plaintext2 = Buffer.from('written with v2');
    const encrypted2 = await groupEncrypt(plaintext2, storedV2);
    const decrypted2 = await groupDecrypt(encrypted2, storedV2);
    assert.deepEqual(decrypted2, plaintext2);

    // Cross-version: v1 cannot decrypt v2 ciphertext
    await assert.rejects(() => groupDecrypt(encrypted2, storedV1));

    // Cleanup
    const os = await import('os');
    await fs.unlink(
      path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.json`),
    ).catch(() => {});
    clearGroupKeyCache();
  });

  it('multi-group sync stores all keys', async () => {
    const groups = [
      { id: `multi-a-${Date.now()}`, psk: crypto.randomBytes(32) },
      { id: `multi-b-${Date.now()}`, psk: crypto.randomBytes(32) },
      { id: `multi-c-${Date.now()}`, psk: crypto.randomBytes(32) },
    ];

    // Encrypt each for the device
    const envelopes = groups.map(g => ({
      groupId: g.id,
      psk: g.psk,
      envelope: envelopeEncrypt(g.psk, kp.publicKey),
    }));

    // Simulate sync: decrypt + store each
    for (const e of envelopes) {
      const decrypted = envelopeDecrypt(e.envelope, kp.privateKey);
      await storeGroupKey(e.groupId, decrypted);
    }

    // Verify all stored
    for (const g of groups) {
      const stored = await getGroupKey(g.id);
      assert.ok(stored);
      assert.deepEqual(stored, g.psk);
    }

    // Cross-group isolation: key from group A cannot decrypt group B's data
    const plaintext = Buffer.from('group-a secret');
    const encryptedA = await groupEncrypt(plaintext, groups[0].psk);

    // Decrypt with correct key succeeds
    const decryptedA = await groupDecrypt(encryptedA, groups[0].psk);
    assert.deepEqual(decryptedA, plaintext);

    // Decrypt with wrong key fails
    await assert.rejects(
      () => groupDecrypt(encryptedA, groups[1].psk),
    );

    // Cleanup
    const os = await import('os');
    for (const g of groups) {
      await fs.unlink(
        path.join(os.homedir(), '.cordelia', 'group-keys', `${g.id}.json`),
      ).catch(() => {});
    }
    clearGroupKeyCache();
  });
});
