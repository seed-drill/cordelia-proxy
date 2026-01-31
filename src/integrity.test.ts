/**
 * Project Cordelia - Integrity Module Tests
 *
 * Tests for chain hash verification, item checksums, canary,
 * and periodic integrity reports.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageProvider } from './storage-sqlite.js';
import { setStorageProvider } from './storage.js';
import {
  computeContentHash,
  computeChainHash,
  verifyChainHash,
  verifyItem,
  canaryCheck,
  periodicCheck,
} from './integrity.js';

describe('computeContentHash', () => {
  it('should produce consistent hash for same data', () => {
    const data = { version: 1, identity: { name: 'Test' } };
    const hash1 = computeContentHash(data);
    const hash2 = computeContentHash(data);
    assert.strictEqual(hash1, hash2);
  });

  it('should exclude integrity block from hash', () => {
    const data1 = {
      version: 1,
      ephemeral: { session_count: 1, integrity: { chain_hash: 'abc', previous_hash: 'def', genesis: '2026-01-01' } },
    };
    const data2 = {
      version: 1,
      ephemeral: { session_count: 1, integrity: { chain_hash: 'xyz', previous_hash: '123', genesis: '2026-01-02' } },
    };
    const hash1 = computeContentHash(data1);
    const hash2 = computeContentHash(data2);
    assert.strictEqual(hash1, hash2, 'Hashes should match when only integrity differs');
  });

  it('should differ when non-integrity data changes', () => {
    const data1 = { version: 1, ephemeral: { session_count: 1 } };
    const data2 = { version: 1, ephemeral: { session_count: 2 } };
    const hash1 = computeContentHash(data1);
    const hash2 = computeContentHash(data2);
    assert.notStrictEqual(hash1, hash2);
  });
});

describe('computeChainHash', () => {
  it('should produce consistent hash for same inputs', () => {
    const hash1 = computeChainHash('prev', 5, 'content');
    const hash2 = computeChainHash('prev', 5, 'content');
    assert.strictEqual(hash1, hash2);
  });

  it('should differ when any input changes', () => {
    const base = computeChainHash('prev', 5, 'content');
    assert.notStrictEqual(base, computeChainHash('other', 5, 'content'));
    assert.notStrictEqual(base, computeChainHash('prev', 6, 'content'));
    assert.notStrictEqual(base, computeChainHash('prev', 5, 'other'));
  });

  it('should be compatible with hooks/lib.mjs format', () => {
    // Chain hash = SHA256(previousHash + sessionCount + contentHash)
    const input = 'prevhash' + '10' + 'contenthash';
    const expected = crypto.createHash('sha256').update(input).digest('hex');
    const result = computeChainHash('prevhash', 10, 'contenthash');
    assert.strictEqual(result, expected);
  });
});

describe('verifyChainHash', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-integrity-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should pass for valid chain hash', async () => {
    // Build valid L1 data with correct chain hash
    const l1Data: Record<string, unknown> = {
      version: 1,
      updated_at: new Date().toISOString(),
      identity: { id: 'test', name: 'Test', roles: [], orgs: [], key_refs: [], style: [] },
      active: { project: null, sprint: null, focus: null, blockers: [], next: [], context_refs: [] },
      prefs: { planning_mode: 'optional', feedback_style: 'continuous', verbosity: 'concise', emoji: false, proactive_suggestions: true, auto_commit: false },
      delegation: { allowed: false, max_parallel: 1, require_approval: [], autonomous: [] },
    };

    const previousHash = 'genesis';
    const sessionCount = 1;
    const contentHashWithEphemeral = computeContentHash({
      ...l1Data,
      ephemeral: {
        session_count: sessionCount,
        current_session_start: new Date().toISOString(),
        last_session_end: null,
        last_summary: null,
        open_threads: [],
        vessel: null,
      },
    });
    const chainHash = computeChainHash(previousHash, sessionCount, contentHashWithEphemeral);

    const fullL1 = {
      ...l1Data,
      ephemeral: {
        session_count: sessionCount,
        current_session_start: new Date().toISOString(),
        last_session_end: null,
        last_summary: null,
        open_threads: [],
        vessel: null,
        integrity: {
          chain_hash: chainHash,
          previous_hash: previousHash,
          genesis: new Date().toISOString(),
        },
      },
    };

    await provider.writeL1('chain-test', Buffer.from(JSON.stringify(fullL1)));
    const result = await verifyChainHash('chain-test');
    assert.strictEqual(result.ok, true, `Expected ok but got errors: ${result.errors.join(', ')}`);
  });

  it('should fail for tampered data', async () => {
    const l1Data = {
      version: 1,
      updated_at: new Date().toISOString(),
      identity: { id: 'tamper', name: 'Original' },
      ephemeral: {
        session_count: 1,
        current_session_start: new Date().toISOString(),
        last_session_end: null,
        last_summary: null,
        open_threads: [],
        vessel: null,
        integrity: {
          chain_hash: 'deliberately-wrong-hash',
          previous_hash: 'genesis',
          genesis: new Date().toISOString(),
        },
      },
    };

    await provider.writeL1('tamper-test', Buffer.from(JSON.stringify(l1Data)));
    const result = await verifyChainHash('tamper-test');
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('mismatch'));
  });

  it('should return not found for missing user', async () => {
    const result = await verifyChainHash('nonexistent-user');
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('No L1 data'));
  });

  it('should pass for pre-S7 data without ephemeral', async () => {
    const l1Data = { version: 1, identity: { name: 'Old' } };
    await provider.writeL1('old-user', Buffer.from(JSON.stringify(l1Data)));
    const result = await verifyChainHash('old-user');
    assert.strictEqual(result.ok, true);
  });
});

describe('verifyItem', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-verify-item-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should pass for valid item with matching checksum', async () => {
    const data = Buffer.from(JSON.stringify({ id: 'valid-item', name: 'Test' }));
    await provider.writeL2Item('valid-item', 'entity', data, { type: 'entity' });
    const result = await verifyItem('valid-item');
    assert.strictEqual(result.ok, true);
  });

  it('should fail for corrupted item data', async () => {
    // Write a valid item first
    const data = Buffer.from(JSON.stringify({ id: 'corrupt-item', name: 'Original' }));
    await provider.writeL2Item('corrupt-item', 'entity', data, { type: 'entity' });

    // Corrupt the data directly in the DB (bypass checksum update)
    const db = provider.getDatabase();
    db.prepare('UPDATE l2_items SET data = ? WHERE id = ?').run(
      Buffer.from('corrupted data'),
      'corrupt-item',
    );

    const result = await verifyItem('corrupt-item');
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('mismatch'));
  });

  it('should return not found for missing item', async () => {
    const result = await verifyItem('nonexistent-item');
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('not found'));
  });
});

describe('canaryCheck', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-canary-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should pass when canary is present', () => {
    const result = canaryCheck();
    assert.strictEqual(result.ok, true);
  });

  it('should fail when canary is deleted', () => {
    const db = provider.getDatabase();
    db.prepare('DELETE FROM integrity_canary').run();

    const result = canaryCheck();
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('missing'));

    // Restore canary for subsequent tests
    provider.writeCanary(crypto.randomBytes(32).toString('hex'));
  });

  it('should fail when canary has invalid format', () => {
    provider.writeCanary('not-a-valid-hex-string!');
    const result = canaryCheck();
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors[0].includes('Invalid canary'));

    // Restore valid canary
    provider.writeCanary(crypto.randomBytes(32).toString('hex'));
  });
});

describe('periodicCheck', () => {
  let provider: SqliteStorageProvider;
  let tmpDir: string;

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-periodic-'));
    provider = new SqliteStorageProvider(tmpDir);
    await provider.initialize();
    setStorageProvider(provider);
  });

  after(async () => {
    await provider.close();
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('should produce a clean report for healthy database', async () => {
    const report = await periodicCheck([]);
    assert.strictEqual(report.ok, true);
    assert.ok(report.timestamp);
    assert.strictEqual(report.checks.database.ok, true);
    assert.strictEqual(report.checks.canary.ok, true);
    assert.strictEqual(report.checks.checksums.ok, true);
  });

  it('should detect corrupted items in periodic check', async () => {
    // Write valid item then corrupt it
    const data = Buffer.from(JSON.stringify({ id: 'periodic-test', name: 'Test' }));
    await provider.writeL2Item('periodic-test', 'entity', data, { type: 'entity' });

    const db = provider.getDatabase();
    db.prepare('UPDATE l2_items SET data = ? WHERE id = ?').run(
      Buffer.from('corrupted'),
      'periodic-test',
    );

    const report = await periodicCheck([]);
    assert.strictEqual(report.ok, false);
    assert.strictEqual(report.checks.checksums.ok, false);
    assert.ok(report.checks.checksums.failed > 0);
  });
});
