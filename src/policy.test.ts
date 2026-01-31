/**
 * Project Cordelia - Policy Engine Tests
 *
 * Tests for InlinePolicyEngine: unauthenticated, owner/non-owner,
 * member/non-member, viewer restrictions, EMCON blocks.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageProvider } from './storage-sqlite.js';
import { InlinePolicyEngine, resolveContextBinding, isGroupVisibleInContext } from './policy.js';

describe('InlinePolicyEngine', () => {
  let provider: SqliteStorageProvider;
  let engine: InlinePolicyEngine;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-policy-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    engine = new InlinePolicyEngine(provider);

    // Set up test data: group + members
    await provider.writeL1('alice', Buffer.from('{}'));
    await provider.writeL1('bob', Buffer.from('{}'));
    await provider.writeL1('charlie', Buffer.from('{}'));
    await provider.writeL1('dave', Buffer.from('{}'));

    await provider.createGroup('test-group', 'Test Group', '{}', '{}');
    await provider.addMember('test-group', 'alice', 'owner');
    await provider.addMember('test-group', 'bob', 'member');
    await provider.addMember('test-group', 'charlie', 'viewer');
    await provider.addMember('test-group', 'dave', 'member');

    // Set dave to EMCON posture
    await provider.updateMemberPosture('test-group', 'dave', 'emcon');
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should deny unauthenticated requests (no entity_id)', async () => {
    const result = await engine.evaluate({
      entity_id: '',
      action: 'read',
      resource_type: 'entity',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'unauthenticated');
  });

  it('should allow owner access to private memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'alice',
      action: 'read',
      resource_type: 'entity',
      owner_id: 'alice',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should deny non-owner access to private memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'bob',
      action: 'read',
      resource_type: 'entity',
      owner_id: 'alice',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'not_owner');
  });

  it('should allow member read on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'bob',
      action: 'read',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should deny non-member access to group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'nobody',
      action: 'read',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'not_member');
  });

  it('should deny viewer write on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'charlie',
      action: 'write',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'viewer_read_only');
  });

  it('should deny viewer delete on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'charlie',
      action: 'delete',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'viewer_read_only');
  });

  it('should deny viewer share on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'charlie',
      action: 'share',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'viewer_read_only');
  });

  it('should allow viewer read on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'charlie',
      action: 'read',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should deny EMCON entity write on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'dave',
      action: 'write',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'emcon');
  });

  it('should deny EMCON entity share on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'dave',
      action: 'share',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, false);
    assert.strictEqual(result.reason, 'emcon');
  });

  it('should allow EMCON entity read on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'dave',
      action: 'read',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should allow owner write on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'alice',
      action: 'write',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should allow member write on group memory', async () => {
    const result = await engine.evaluate({
      entity_id: 'bob',
      action: 'write',
      resource_type: 'entity',
      group_id: 'test-group',
    });
    assert.strictEqual(result.allowed, true);
  });

  it('should allow new private item creation (no owner_id)', async () => {
    const result = await engine.evaluate({
      entity_id: 'alice',
      action: 'write',
      resource_type: 'entity',
    });
    assert.strictEqual(result.allowed, true);
  });
});

describe('Context Binding', () => {
  const bindings: Record<string, string> = {
    '/Users/russell/seed-drill': 'seed-drill',
    '/Users/russell/seed-drill/cordelia': 'cordelia-dev',
    '/Users/russell/personal': 'family',
  };

  describe('resolveContextBinding', () => {
    it('should return undefined when no cwd', () => {
      assert.strictEqual(resolveContextBinding(undefined, bindings), undefined);
    });

    it('should return undefined when no bindings', () => {
      assert.strictEqual(resolveContextBinding('/some/path', undefined), undefined);
    });

    it('should match exact directory', () => {
      assert.strictEqual(resolveContextBinding('/Users/russell/personal', bindings), 'family');
    });

    it('should match subdirectory to parent binding', () => {
      assert.strictEqual(resolveContextBinding('/Users/russell/seed-drill/docs', bindings), 'seed-drill');
    });

    it('should prefer most specific (longest) match', () => {
      assert.strictEqual(resolveContextBinding('/Users/russell/seed-drill/cordelia/src', bindings), 'cordelia-dev');
    });

    it('should return undefined for unbound directory', () => {
      assert.strictEqual(resolveContextBinding('/Users/russell/other', bindings), undefined);
    });
  });

  describe('isGroupVisibleInContext', () => {
    it('should allow all groups when no bindings', () => {
      assert.strictEqual(isGroupVisibleInContext('any-group', '/any/path', undefined), true);
      assert.strictEqual(isGroupVisibleInContext('any-group', '/any/path', {}), true);
    });

    it('should deny all groups when no cwd but bindings exist', () => {
      assert.strictEqual(isGroupVisibleInContext('seed-drill', undefined, bindings), false);
    });

    it('should allow bound group in matching directory', () => {
      assert.strictEqual(isGroupVisibleInContext('seed-drill', '/Users/russell/seed-drill', bindings), true);
    });

    it('should deny non-bound group in directory', () => {
      assert.strictEqual(isGroupVisibleInContext('family', '/Users/russell/seed-drill', bindings), false);
    });

    it('should deny group when cwd has no binding', () => {
      assert.strictEqual(isGroupVisibleInContext('seed-drill', '/Users/russell/other', bindings), false);
    });
  });
});
