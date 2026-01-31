/**
 * Project Cordelia - KeyVault Tests
 *
 * Minimal tests for the R2 SharedKeyVault stub.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SharedKeyVault } from './keyvault.js';

describe('SharedKeyVault (R2 stub)', () => {
  it('should return a buffer from getGroupKey', async () => {
    const vault = new SharedKeyVault();
    const key = await vault.getGroupKey('test-group');
    assert.ok(Buffer.isBuffer(key));
    assert.strictEqual(key.length, 32);
  });

  it('should return consistent key across calls', async () => {
    const vault = new SharedKeyVault();
    const key1 = await vault.getGroupKey('group-a');
    const key2 = await vault.getGroupKey('group-b');
    assert.deepStrictEqual(key1, key2, 'R2 stub returns same key for all groups');
  });

  it('should return newVersion 1 from rotateGroupKey', async () => {
    const vault = new SharedKeyVault();
    const result = await vault.rotateGroupKey('test-group');
    assert.strictEqual(result.newVersion, 1);
  });

  it('should return count 0 from reencryptItems', async () => {
    const vault = new SharedKeyVault();
    const result = await vault.reencryptItems('test-group', 1);
    assert.strictEqual(result.count, 0);
  });

  it('should accept a custom master key', async () => {
    const customKey = Buffer.alloc(32, 0xAB);
    const vault = new SharedKeyVault(customKey);
    const key = await vault.getGroupKey('any');
    assert.deepStrictEqual(key, customKey);
  });
});
