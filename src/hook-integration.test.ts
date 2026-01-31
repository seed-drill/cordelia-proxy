/**
 * Hook Integration Tests - Config-driven identity round-trip
 *
 * Tests the hook -> config.toml -> L1 pipeline:
 * 1. Config.toml loads correctly and provides user_id
 * 2. session-start.mjs reads from config.toml when no CLI arg
 * 3. Missing config + no CLI arg produces clear error (no silent fallback)
 * 4. CLI arg overrides config.toml
 *
 * Run with: node --import tsx --test src/hook-integration.test.ts
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { execSync, execFileSync } from 'child_process';

// Path to the hooks
const HOOKS_DIR = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'hooks');

describe('Hook Integration: config.toml identity', () => {
  let tmpDir: string;
  let configDir: string;
  let configPath: string;
  let memoryRoot: string;
  let savedHome: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-hook-test-'));
    configDir = path.join(tmpDir, '.cordelia');
    configPath = path.join(configDir, 'config.toml');
    memoryRoot = path.join(tmpDir, 'memory');
    savedHome = os.homedir();

    // Create memory structure
    await fs.mkdir(path.join(memoryRoot, 'L1-hot'), { recursive: true });
    await fs.mkdir(path.join(memoryRoot, 'L2-warm', '.salt'), { recursive: true });

    // Create salt file
    const salt = Buffer.alloc(32, 'test-salt-for-hook-integration');
    await fs.writeFile(path.join(memoryRoot, 'L2-warm', '.salt', 'global.salt'), salt);
  });

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  describe('parseTOML', () => {
    it('should parse flat config with sections', async () => {
      // Import the parser directly
      // @ts-ignore - hooks are plain JS
      const { parseTOML } = await import('../hooks/lib.mjs') as any;

      const toml = `
# Comment
[identity]
user_id = "testuser"

[paths]
memory_root = "/tmp/test"

[node]
entity_id = "test_entity"
`;
      const result = parseTOML(toml);
      assert.strictEqual(result.identity.user_id, 'testuser');
      assert.strictEqual(result.paths.memory_root, '/tmp/test');
      assert.strictEqual(result.node.entity_id, 'test_entity');
    });

    it('should handle single-quoted values', async () => {
      // @ts-ignore - hooks are plain JS
      const { parseTOML } = await import('../hooks/lib.mjs') as any;

      const toml = `[identity]\nuser_id = 'testuser'`;
      const result = parseTOML(toml);
      assert.strictEqual(result.identity.user_id, 'testuser');
    });

    it('should handle unquoted values', async () => {
      // @ts-ignore - hooks are plain JS
      const { parseTOML } = await import('../hooks/lib.mjs') as any;

      const toml = `[identity]\nuser_id = testuser`;
      const result = parseTOML(toml);
      assert.strictEqual(result.identity.user_id, 'testuser');
    });

    it('should skip comments and blank lines', async () => {
      // @ts-ignore - hooks are plain JS
      const { parseTOML } = await import('../hooks/lib.mjs') as any;

      const toml = `
# This is a comment
[identity]
# Another comment
user_id = "test"

`;
      const result = parseTOML(toml);
      assert.strictEqual(result.identity.user_id, 'test');
    });
  });

  describe('getUserId resolution', () => {
    it('should prefer CLI arg over config.toml', async () => {
      // @ts-ignore - hooks are plain JS
      const { getUserId, clearConfigCache } = await import('../hooks/lib.mjs') as any;
      clearConfigCache();

      // Simulate CLI arg
      const originalArgv = process.argv;
      process.argv = ['node', 'script.mjs', 'cli-user'];

      try {
        const userId = await getUserId();
        assert.strictEqual(userId, 'cli-user');
      } finally {
        process.argv = originalArgv;
      }
    });

    it('should fail with clear error when no config and no CLI arg', async () => {
      // @ts-ignore - hooks are plain JS
      const { getUserId, clearConfigCache } = await import('../hooks/lib.mjs') as any;
      clearConfigCache();

      // No CLI arg, and config cache cleared (will try to load from real path)
      const originalArgv = process.argv;
      const originalHome = process.env.HOME;
      process.argv = ['node', 'script.mjs']; // No arg
      process.env.HOME = path.join(tmpDir, 'nonexistent'); // No config

      try {
        await assert.rejects(
          () => getUserId(),
          (err: Error) => {
            assert.ok(err.message.includes('No user_id configured'), `Expected helpful error, got: ${err.message}`);
            assert.ok(err.message.includes('config.toml'), 'Should mention config.toml');
            return true;
          }
        );
      } finally {
        process.argv = originalArgv;
        process.env.HOME = originalHome;
      }
    });
  });

  describe('getMemoryRoot resolution', () => {
    it('should prefer CORDELIA_MEMORY_ROOT env var', async () => {
      // @ts-ignore - hooks are plain JS
      const { getMemoryRoot, clearConfigCache } = await import('../hooks/lib.mjs') as any;
      clearConfigCache();

      const original = process.env.CORDELIA_MEMORY_ROOT;
      process.env.CORDELIA_MEMORY_ROOT = '/tmp/env-memory-root';

      try {
        const root = await getMemoryRoot();
        assert.strictEqual(root, '/tmp/env-memory-root');
      } finally {
        if (original) {
          process.env.CORDELIA_MEMORY_ROOT = original;
        } else {
          delete process.env.CORDELIA_MEMORY_ROOT;
        }
      }
    });

    it('should fail with clear error when no env and no config', async () => {
      // @ts-ignore - hooks are plain JS
      const { getMemoryRoot, clearConfigCache } = await import('../hooks/lib.mjs') as any;
      clearConfigCache();

      const originalEnv = process.env.CORDELIA_MEMORY_ROOT;
      const originalHome = process.env.HOME;
      delete process.env.CORDELIA_MEMORY_ROOT;
      process.env.HOME = path.join(tmpDir, 'nonexistent');

      try {
        await assert.rejects(
          () => getMemoryRoot(),
          (err: Error) => {
            assert.ok(err.message.includes('No memory root configured'), `Expected helpful error, got: ${err.message}`);
            return true;
          }
        );
      } finally {
        if (originalEnv) {
          process.env.CORDELIA_MEMORY_ROOT = originalEnv;
        }
        process.env.HOME = originalHome;
      }
    });
  });

  describe('session-start.mjs subprocess', () => {
    it('should fail with clear error when no user_id available', () => {
      // Run session-start.mjs with no CLI arg and HOME pointing to temp dir with no config
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined) env[k] = v;
      }
      env.HOME = path.join(tmpDir, 'nonexistent');
      env.CORDELIA_MEMORY_ROOT = memoryRoot;
      delete env.CORDELIA_ENCRYPTION_KEY;

      try {
        execFileSync('node', [path.join(HOOKS_DIR, 'session-start.mjs')], {
          env,
          encoding: 'utf-8',
          timeout: 10000,
        });
        assert.fail('Should have exited with non-zero');
      } catch (err: unknown) {
        const execErr = err as { status: number; stderr: string };
        assert.ok(execErr.status !== 0, 'Should exit with non-zero status');
        assert.ok(
          execErr.stderr.includes('No user_id configured'),
          `Expected helpful error in stderr, got: ${execErr.stderr}`
        );
      }
    });
  });
});
