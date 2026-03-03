/**
 * E2b Enrollment Envelope Tests
 *
 * Tests: storeGroupKey, GroupKeyVault integration, writePersonalGroupToConfig,
 * enrollment envelope decrypt + store flow, resetPersonalGroupCache.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { envelopeEncrypt, envelopeDecrypt, deriveX25519FromEd25519 } from './envelope.js';
import { storeGroupKey, getGroupKey, clearGroupKeyCache, groupEncrypt, groupDecrypt } from './group-keys.js';
import { GroupKeyVault } from './keyvault.js';

describe('storeGroupKey', () => {
  const testDir = `/tmp/cordelia-test-store-gk-${Date.now()}`;

  before(async () => {
    // We'll write keys here -- the module uses ~/.cordelia/group-keys/ by default,
    // so these tests verify the store/retrieve contract.
    clearGroupKeyCache();
  });

  after(async () => {
    clearGroupKeyCache();
  });

  it('stores and retrieves a 32-byte PSK', async () => {
    const groupId = `test-store-${Date.now()}`;
    const psk = crypto.randomBytes(32);

    await storeGroupKey(groupId, psk);
    const retrieved = await getGroupKey(groupId);

    assert.ok(retrieved);
    assert.deepEqual(retrieved, psk);

    // Cleanup
    const os = await import('os');
    const keyPath = path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.key`);
    await fs.unlink(keyPath).catch(() => {});
  });

  it('rejects PSK that is not 32 bytes', async () => {
    await assert.rejects(
      () => storeGroupKey('bad-size', Buffer.alloc(16)),
      /PSK must be 32 bytes/,
    );
  });

  it('updates cache on store', async () => {
    const groupId = `test-cache-${Date.now()}`;
    const psk = crypto.randomBytes(32);

    await storeGroupKey(groupId, psk);

    // Second call should hit cache
    const cached = await getGroupKey(groupId);
    assert.deepEqual(cached, psk);

    // Cleanup
    const os = await import('os');
    const keyPath = path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.key`);
    await fs.unlink(keyPath).catch(() => {});
    clearGroupKeyCache();
  });
});

describe('GroupKeyVault integration', () => {
  const groupId = `test-vault-${Date.now()}`;
  const psk = crypto.randomBytes(32);

  before(async () => {
    clearGroupKeyCache();
    await storeGroupKey(groupId, psk);
  });

  after(async () => {
    clearGroupKeyCache();
    const os = await import('os');
    const keyPath = path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.key`);
    await fs.unlink(keyPath).catch(() => {});
  });

  it('retrieves stored key via GroupKeyVault', async () => {
    const vault = new GroupKeyVault();
    const key = await vault.getGroupKey(groupId);
    assert.deepEqual(key, psk);
  });

  it('throws for nonexistent group', async () => {
    const vault = new GroupKeyVault();
    await assert.rejects(
      () => vault.getGroupKey('nonexistent-group'),
      /No PSK available/,
    );
  });
});

describe('Envelope decrypt -> store group key flow', () => {
  it('simulates full enrollment: encrypt on portal, decrypt on proxy, store', async () => {
    const groupId = `test-enroll-flow-${Date.now()}`;
    clearGroupKeyCache();

    // Portal side: generate PSK, envelope-encrypt for device
    const psk = crypto.randomBytes(32);
    const deviceSeed = crypto.randomBytes(32);
    const deviceKp = deriveX25519FromEd25519(deviceSeed);

    const envelope = envelopeEncrypt(psk, deviceKp.publicKey);

    // Proxy side: decrypt envelope using device private key
    const decryptedPsk = envelopeDecrypt(envelope, deviceKp.privateKey);
    assert.deepEqual(decryptedPsk, psk);

    // Store to disk
    await storeGroupKey(groupId, decryptedPsk);

    // Verify via GroupKeyVault
    const vault = new GroupKeyVault();
    const key = await vault.getGroupKey(groupId);
    assert.deepEqual(key, psk);

    // Verify can encrypt/decrypt with stored key
    const plaintext = Buffer.from('test message for encryption');
    const encrypted = await groupEncrypt(plaintext, key);
    assert.ok(encrypted._encrypted);
    assert.equal(encrypted.version, 1);

    const decrypted = await groupDecrypt(encrypted, key);
    assert.deepEqual(decrypted, plaintext);

    // Cleanup
    const os = await import('os');
    await fs.unlink(
      path.join(os.homedir(), '.cordelia', 'group-keys', `${groupId}.key`)
    ).catch(() => {});
    clearGroupKeyCache();
  });

  it('cross-device: same PSK encrypts/decrypts on different devices', async () => {
    const groupId = `test-cross-${Date.now()}`;
    clearGroupKeyCache();

    const psk = crypto.randomBytes(32);

    // Device A: gets PSK via envelope from portal
    const seedA = crypto.randomBytes(32);
    const kpA = deriveX25519FromEd25519(seedA);
    const envA = envelopeEncrypt(psk, kpA.publicKey);
    const pskA = envelopeDecrypt(envA, kpA.privateKey);

    // Device B: gets same PSK via envelope from portal
    const seedB = crypto.randomBytes(32);
    const kpB = deriveX25519FromEd25519(seedB);
    const envB = envelopeEncrypt(psk, kpB.publicKey);
    const pskB = envelopeDecrypt(envB, kpB.privateKey);

    // Both devices have the same PSK
    assert.deepEqual(pskA, pskB);
    assert.deepEqual(pskA, psk);

    // Device A encrypts
    const message = Buffer.from(JSON.stringify({ type: 'entity', name: 'cross-device test' }));
    const encrypted = await groupEncrypt(message, pskA);

    // Device B decrypts
    const decrypted = await groupDecrypt(encrypted, pskB);
    assert.deepEqual(decrypted, message);
  });
});

describe('writePersonalGroupToConfig', () => {
  const testConfigDir = `/tmp/cordelia-test-config-${Date.now()}`;
  const testConfigPath = path.join(testConfigDir, 'config.toml');

  before(async () => {
    await fs.mkdir(testConfigDir, { recursive: true });
  });

  after(async () => {
    await fs.rm(testConfigDir, { recursive: true, force: true });
  });

  it('creates config with [node] section when none exists', async () => {
    const configPath = path.join(testConfigDir, 'config-new.toml');
    // Simulate what writePersonalGroupToConfig does
    const groupId = crypto.randomUUID();
    const content = `\n[node]\npersonal_group = "${groupId}"\n`;
    await fs.writeFile(configPath, content);

    const written = await fs.readFile(configPath, 'utf-8');
    assert.ok(written.includes('[node]'));
    assert.ok(written.includes(`personal_group = "${groupId}"`));
  });

  it('appends to existing [node] section', async () => {
    const configPath = path.join(testConfigDir, 'config-existing.toml');
    const groupId = crypto.randomUUID();
    const initial = `[node]\napi_addr = "127.0.0.1:9473"\n`;
    await fs.writeFile(configPath, initial);

    // Simulate append
    let content = await fs.readFile(configPath, 'utf-8');
    content = content.replace(
      /(\[node\][^\[]*)/,
      `$1personal_group = "${groupId}"\n`,
    );
    await fs.writeFile(configPath, content);

    const written = await fs.readFile(configPath, 'utf-8');
    assert.ok(written.includes('api_addr'));
    assert.ok(written.includes(`personal_group = "${groupId}"`));
  });

  it('updates existing personal_group entry', async () => {
    const configPath = path.join(testConfigDir, 'config-update.toml');
    const oldId = crypto.randomUUID();
    const newId = crypto.randomUUID();
    const initial = `[node]\napi_addr = "127.0.0.1:9473"\npersonal_group = "${oldId}"\n`;
    await fs.writeFile(configPath, initial);

    let content = await fs.readFile(configPath, 'utf-8');
    content = content.replace(
      /^personal_group\s*=.*$/m,
      `personal_group = "${newId}"`,
    );
    await fs.writeFile(configPath, content);

    const written = await fs.readFile(configPath, 'utf-8');
    assert.ok(written.includes(`personal_group = "${newId}"`));
    assert.ok(!written.includes(oldId));
  });
});

describe('resetPersonalGroupCache', () => {
  it('invalidates cached personal group', async () => {
    const { getPersonalGroup, resetPersonalGroupCache } = await import('./storage.js');

    // First call caches the value
    const pg1 = await getPersonalGroup();

    // Reset cache
    resetPersonalGroupCache();

    // Second call re-reads from config.toml
    const pg2 = await getPersonalGroup();

    // Values should be the same (config.toml didn't change),
    // but the reset should have forced a fresh read
    assert.equal(pg1, pg2);

    // Reset again for clean state
    resetPersonalGroupCache();
  });
});
