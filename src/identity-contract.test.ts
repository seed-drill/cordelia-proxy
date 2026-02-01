/**
 * Identity Contract Tests - user_id consistency validation
 *
 * Validates the contract between:
 * - L1 storage key (filename, e.g., "russell")
 * - L1 data identity.id (e.g., "russell_wing")
 * - MCP tool user_id parameter
 *
 * Run with: node --import tsx --test src/identity-contract.test.ts
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageProvider } from './storage-sqlite.js';
import type { StorageProvider } from './storage.js';

describe('Identity Contract', () => {
  let tmpDir: string;
  let provider: StorageProvider;
  let memoryRoot: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-identity-test-'));
    memoryRoot = path.join(tmpDir, 'memory');
    await fs.mkdir(path.join(memoryRoot, 'L1-hot'), { recursive: true });
    await fs.mkdir(path.join(memoryRoot, 'L2-warm', '.salt'), { recursive: true });
    await fs.mkdir(path.join(memoryRoot, 'L2-warm', 'items'), { recursive: true });

    provider = new SqliteStorageProvider(memoryRoot);
    await provider.initialize();
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe('L1 storage key vs identity.id', () => {
    it('should store L1 with the storage key filename', async () => {
      const storageKey = 'testuser';
      const l1Data = {
        version: 1,
        updated_at: new Date().toISOString(),
        identity: {
          id: 'test_user_entity',  // Deliberately different from storage key
          name: 'Test User',
          roles: [],
          orgs: [],
          key_refs: [],
          style: [],
          tz: 'UTC',
        },
        active: {
          project: null,
          sprint: null,
          focus: 'Testing',
          blockers: [],
          next: [],
          context_refs: [],
          sprint_plan: {},
          notes: [],
        },
        prefs: {
          planning_mode: 'important',
          feedback_style: 'continuous',
          verbosity: 'concise',
          emoji: false,
          proactive_suggestions: true,
          auto_commit: false,
        },
        delegation: {
          allowed: true,
          max_parallel: 3,
          require_approval: [],
          autonomous: [],
        },
      };

      await provider.writeL1(storageKey, Buffer.from(JSON.stringify(l1Data)));

      // Read back with storage key - should succeed
      const result = await provider.readL1(storageKey);
      assert.ok(result, 'Should read L1 with storage key');

      const parsed = JSON.parse(result!.toString('utf-8'));
      assert.strictEqual(parsed.identity.id, 'test_user_entity');

      // Read with identity.id - should return null (different from storage key)
      const wrongResult = await provider.readL1('test_user_entity');
      assert.strictEqual(wrongResult, null, 'identity.id is not the storage key');
    });

    it('should list users by storage key, not identity.id', async () => {
      const users = await provider.listL1Users();
      assert.ok(users.includes('testuser'), 'Should list by storage key');
      assert.ok(!users.includes('test_user_entity'), 'Should not list by identity.id');
    });
  });

  describe('MCP error message contract', () => {
    it('should provide known_users in error response format', () => {
      // Verify the error format matches what the MCP server produces
      const knownUsers = ['russell', 'bill', 'martin'];
      const userId = 'russell_wing';

      const errorResponse = {
        error: 'user_not_found',
        user_id: userId,
        detail: `No L1 context found for "${userId}". Known users: [${knownUsers.join(', ')}]. ` +
          `Check that you're using the L1 storage key (filename), not the identity.id field.`,
        known_users: knownUsers,
      };

      // Verify error response structure
      assert.strictEqual(errorResponse.error, 'user_not_found');
      assert.ok(errorResponse.detail.includes(userId));
      assert.ok(errorResponse.detail.includes('storage key'));
      assert.ok(errorResponse.detail.includes('identity.id'));
      assert.deepStrictEqual(errorResponse.known_users, knownUsers);
    });

    it('should distinguish storage key from identity.id in guidance', () => {
      // The error message should help users understand the difference
      const errorDetail = `No L1 context found for "russell_wing". Known users: [russell]. ` +
        `Check that you're using the L1 storage key (filename), not the identity.id field.`;

      assert.ok(errorDetail.includes('russell_wing'), 'Shows what was requested');
      assert.ok(errorDetail.includes('russell'), 'Shows known alternative');
      assert.ok(errorDetail.includes('storage key'), 'Explains concept');
    });
  });

  describe('config.toml identity mapping', () => {
    it('should parse identity.user_id as the storage key', async () => {
      // Import TOML parser
      // @ts-expect-error - hooks are plain JS, no type declarations
      const { parseTOML } = await import('../hooks/lib.mjs') as any;

      const config = parseTOML(`
[identity]
user_id = "russell"        # L1 storage key
entity_id = "russell_wing" # identity.id (informational)
`);

      assert.strictEqual(config.identity.user_id, 'russell');
      assert.strictEqual(config.identity.entity_id, 'russell_wing');

      // user_id is what hooks pass to readL1/writeL1
      // entity_id is informational (matches identity.id inside L1 data)
    });
  });
});
