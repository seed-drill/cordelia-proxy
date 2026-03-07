import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

// Override GROUP_KEYS_DIR before importing (use temp dir)
const tmpDir = path.join(os.tmpdir(), `cordelia-creds-test-${Date.now()}`);
const groupKeysDir = path.join(tmpDir, 'group-keys');

// We need to test loadCredentialsBundle with a temp dir.
// Since GROUP_KEYS_DIR is hardcoded, we test storeGroupKey + getGroupKey directly
// and test the bundle parsing logic.

import { storeGroupKey, getGroupKey, clearGroupKeyCache, type CredentialsBundle } from './group-keys.js';

before(async () => {
  await fs.mkdir(groupKeysDir, { recursive: true });
});

after(async () => {
  clearGroupKeyCache();
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe('Credentials bundle format', () => {
  it('CredentialsBundle interface matches expected shape', () => {
    const bundle: CredentialsBundle = {
      entity_id: 'agent-testbot',
      bearer_token: 'ct_abc123',
      groups: [
        { group_id: 'group-1', name: 'Test Group', psk: crypto.randomBytes(32).toString('hex') },
      ],
    };
    assert.equal(bundle.entity_id, 'agent-testbot');
    assert.equal(bundle.groups.length, 1);
    assert.equal(bundle.groups[0].psk.length, 64); // 32 bytes hex
  });

  it('storeGroupKey writes and getGroupKey reads back correctly', async () => {
    const groupId = `test-${Date.now()}`;
    const psk = crypto.randomBytes(32);
    await storeGroupKey(groupId, psk, 1);

    clearGroupKeyCache();
    const loaded = await getGroupKey(groupId, 1);
    assert.ok(loaded);
    assert.equal(loaded.toString('hex'), psk.toString('hex'));
  });

  it('rejects PSK with wrong length', async () => {
    const shortPsk = crypto.randomBytes(16);
    await assert.rejects(
      () => storeGroupKey('bad-group', shortPsk, 1),
      /PSK must be 32 bytes/,
    );
  });
});

describe('CORDELIA_CREDENTIALS env var parsing', () => {
  it('loadCredentialsBundle returns null when no env vars set', async () => {
    // Save and clear env
    const saved = {
      file: process.env.CORDELIA_CREDENTIALS_FILE,
      inline: process.env.CORDELIA_CREDENTIALS,
    };
    delete process.env.CORDELIA_CREDENTIALS_FILE;
    delete process.env.CORDELIA_CREDENTIALS;

    const { loadCredentialsBundle } = await import('./group-keys.js');
    const result = await loadCredentialsBundle();
    assert.equal(result, null);

    // Restore
    if (saved.file) process.env.CORDELIA_CREDENTIALS_FILE = saved.file;
    if (saved.inline) process.env.CORDELIA_CREDENTIALS = saved.inline;
  });
});
