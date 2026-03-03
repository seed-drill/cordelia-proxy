/**
 * E4b Key Ring Tests
 *
 * Tests: multi-version PSK storage, getGroupKey with version param,
 * version ordering, encrypt with latest, decrypt with old version.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import {
  storeGroupKey,
  getGroupKey,
  getGroupKeyVersions,
  getGroupKeyLatestVersion,
  groupEncrypt,
  groupDecrypt,
  clearGroupKeyCache,
} from './group-keys.js';

const GROUP_KEYS_DIR = path.join(os.homedir(), '.cordelia', 'group-keys');

async function cleanupGroupKey(groupId: string) {
  await fs.unlink(path.join(GROUP_KEYS_DIR, `${groupId}.json`)).catch(() => {});
}

describe('Key ring: basic operations', () => {
  const groupId = `ring-basic-${Date.now()}`;
  const psk1 = crypto.randomBytes(32);
  const psk2 = crypto.randomBytes(32);

  before(async () => {
    clearGroupKeyCache();
  });

  after(async () => {
    clearGroupKeyCache();
    await cleanupGroupKey(groupId);
  });

  it('stores first key as version 1', async () => {
    await storeGroupKey(groupId, psk1);
    const key = await getGroupKey(groupId);
    assert.ok(key);
    assert.deepEqual(key, psk1);

    const latest = await getGroupKeyLatestVersion(groupId);
    assert.equal(latest, 1);
  });

  it('stores second key as version 2', async () => {
    await storeGroupKey(groupId, psk2);
    const key = await getGroupKey(groupId);
    assert.ok(key);
    assert.deepEqual(key, psk2); // Latest is v2

    const latest = await getGroupKeyLatestVersion(groupId);
    assert.equal(latest, 2);
  });

  it('retrieves specific version', async () => {
    const v1 = await getGroupKey(groupId, 1);
    const v2 = await getGroupKey(groupId, 2);
    assert.ok(v1);
    assert.ok(v2);
    assert.deepEqual(v1, psk1);
    assert.deepEqual(v2, psk2);
  });

  it('returns null for nonexistent version', async () => {
    const v99 = await getGroupKey(groupId, 99);
    assert.equal(v99, null);
  });

  it('lists versions in descending order', async () => {
    const versions = await getGroupKeyVersions(groupId);
    assert.deepEqual(versions, [2, 1]);
  });

  it('writes JSON key ring to disk', async () => {
    const jsonPath = path.join(GROUP_KEYS_DIR, `${groupId}.json`);
    const content = await fs.readFile(jsonPath, 'utf-8');
    const ring = JSON.parse(content);
    assert.equal(ring.latest, 2);
    assert.ok(ring.versions['1']);
    assert.ok(ring.versions['2']);
  });

});

describe('Key ring: encrypt/decrypt with rotation', () => {
  const groupId = `ring-crypt-${Date.now()}`;
  const pskV1 = crypto.randomBytes(32);
  const pskV2 = crypto.randomBytes(32);

  before(async () => {
    clearGroupKeyCache();
    await storeGroupKey(groupId, pskV1);
    await storeGroupKey(groupId, pskV2);
  });

  after(async () => {
    clearGroupKeyCache();
    await cleanupGroupKey(groupId);
  });

  it('encrypts with latest key, decrypts with same key', async () => {
    const latestKey = await getGroupKey(groupId);
    assert.ok(latestKey);
    assert.deepEqual(latestKey, pskV2);

    const plaintext = Buffer.from('encrypted with latest');
    const encrypted = await groupEncrypt(plaintext, latestKey);
    const decrypted = await groupDecrypt(encrypted, latestKey);
    assert.deepEqual(decrypted, plaintext);
  });

  it('data encrypted with v1 can be decrypted with v1 key', async () => {
    const v1Key = await getGroupKey(groupId, 1);
    assert.ok(v1Key);

    const plaintext = Buffer.from('encrypted with v1');
    const encrypted = await groupEncrypt(plaintext, v1Key);
    const decrypted = await groupDecrypt(encrypted, v1Key);
    assert.deepEqual(decrypted, plaintext);
  });

  it('data encrypted with v1 cannot be decrypted with v2 key', async () => {
    const v1Key = await getGroupKey(groupId, 1);
    const v2Key = await getGroupKey(groupId, 2);
    assert.ok(v1Key);
    assert.ok(v2Key);

    const plaintext = Buffer.from('v1 encrypted data');
    const encrypted = await groupEncrypt(plaintext, v1Key);
    await assert.rejects(() => groupDecrypt(encrypted, v2Key));
  });
});

describe('Key ring: explicit version store', () => {
  const groupId = `ring-explicit-${Date.now()}`;

  before(async () => {
    clearGroupKeyCache();
  });

  after(async () => {
    clearGroupKeyCache();
    await cleanupGroupKey(groupId);
  });

  it('stores at explicit version', async () => {
    const psk = crypto.randomBytes(32);
    await storeGroupKey(groupId, psk, 5);

    const key = await getGroupKey(groupId, 5);
    assert.ok(key);
    assert.deepEqual(key, psk);

    const latest = await getGroupKeyLatestVersion(groupId);
    assert.equal(latest, 5);
  });
});
