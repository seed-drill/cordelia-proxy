#!/usr/bin/env node
/**
 * Cordelia - Group Lifecycle Smoke Test
 *
 * Verifies the group sovereignty principle: group culture policy governs
 * group item lifecycle, domain policy governs private item lifecycle.
 *
 * Requires a live DB with at least one group that has ttl_default set
 * and one group without. Writes test items, verifies TTL assignment,
 * then cleans up.
 *
 * Usage: CORDELIA_MEMORY_ROOT=/path CORDELIA_ENCRYPTION_KEY=... node --import tsx src/group-lifecycle-smoke.ts
 */

import * as path from 'path';
import { initStorageProvider } from './storage.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from './crypto.js';
import { writeItem, deleteItem } from './l2.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT
  || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');

let passed = 0;
let failed = 0;
const testIds: string[] = [];

function assert(condition: boolean, label: string, detail?: string): void {
  if (condition) {
    console.log(`  PASS: ${label}`);
    passed++;
  } else {
    console.log(`  FAIL: ${label}${detail ? ' -- ' + detail : ''}`);
    failed++;
  }
}

async function main(): Promise<void> {
  console.log('Cordelia: Group Lifecycle Smoke Test');
  console.log('='.repeat(50));

  // Init crypto
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);
  if (config.enabled && passphrase) {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Crypto: initialized');
  } else {
    console.log('WARNING: no encryption key');
  }

  const provider = await initStorageProvider(MEMORY_ROOT);
  console.log(`Storage: ${provider.name}`);

  if (provider.name !== 'sqlite') {
    console.log('SKIP: requires SQLite provider');
    process.exit(0);
  }

  const sqlite = provider as SqliteStorageProvider;

  // Discover groups and their culture policies
  const groups = await sqlite.listGroups();
  console.log(`Groups: ${groups.length}`);
  if (groups.length === 0) {
    console.log('SKIP: no groups in database');
    process.exit(0);
  }

  const groupWithTtl = groups.find(g => {
    try { const c = JSON.parse(g.culture); return c.ttl_default && c.ttl_default > 0; } catch { return false; }
  });
  const groupNoTtl = groups.find(g => {
    try { const c = JSON.parse(g.culture); return !c.ttl_default; } catch { return true; }
  });

  console.log(`  Group with TTL: ${groupWithTtl?.id || 'none'}`);
  console.log(`  Group without TTL: ${groupNoTtl?.id || 'none'}`);
  console.log();

  // =========================================================================
  // 1. Group item with culture TTL -- should get culture-derived expiry
  // =========================================================================
  if (groupWithTtl) {
    const culture = JSON.parse(groupWithTtl.culture);
    const ttlSec = culture.ttl_default;
    console.log(`1. Group item with culture TTL (${groupWithTtl.id}, ttl_default=${ttlSec}s)`);

    const id = 'smoke-group-ttl-' + Date.now();
    testIds.push(id);
    const result = await writeItem('learning', {
      id,
      name: 'Smoke test: group with TTL',
      type: 'pattern',
      content: 'Verifying culture TTL applies to group items',
      tags: ['smoke-test'],
      confidence: 0.8,
    }, { entity_id: 'russell', group_id: groupWithTtl.id });

    assert('success' in result, 'write succeeded');

    const meta = await sqlite.readL2ItemMeta(id);
    assert(meta !== null, 'item persisted');
    assert(meta?.visibility === 'group', 'visibility is group');
    assert(meta?.group_id === groupWithTtl.id, `group_id is ${groupWithTtl.id}`);
    assert(meta?.domain === 'procedural', 'domain is procedural (inferred from learning/pattern)');
    assert(meta?.ttl_expires_at !== null, 'TTL is set');

    if (meta?.ttl_expires_at) {
      const ttlDate = new Date(meta.ttl_expires_at);
      const expectedMin = new Date(Date.now() + (ttlSec - 10) * 1000);
      const expectedMax = new Date(Date.now() + (ttlSec + 10) * 1000);
      assert(ttlDate >= expectedMin && ttlDate <= expectedMax,
        `TTL is ~${ttlSec}s from now (culture policy)`,
        `got ${meta.ttl_expires_at}`);
    }

    // Verify domain TTL was NOT used (interrupt = 3 days = 259200s)
    if (meta?.ttl_expires_at && ttlSec !== 259200) {
      const ttlDate = new Date(meta.ttl_expires_at);
      const threeDays = new Date(Date.now() + 259200 * 1000);
      const isNotDomainTtl = Math.abs(ttlDate.getTime() - threeDays.getTime()) > 60000;
      assert(isNotDomainTtl, 'TTL is NOT domain-derived (not 3 days)');
    }
    console.log();
  }

  // =========================================================================
  // 2. Group item without culture TTL -- should have no expiry
  // =========================================================================
  if (groupNoTtl) {
    console.log(`2. Group item without culture TTL (${groupNoTtl.id})`);

    const id = 'smoke-group-nottl-' + Date.now();
    testIds.push(id);
    const result = await writeItem('learning', {
      id,
      name: 'Smoke test: group no TTL',
      type: 'pattern',
      content: 'Verifying no TTL when culture has no ttl_default',
      tags: ['smoke-test'],
      confidence: 0.8,
    }, { entity_id: 'russell', group_id: groupNoTtl.id });

    assert('success' in result, 'write succeeded');

    const meta = await sqlite.readL2ItemMeta(id);
    assert(meta !== null, 'item persisted');
    assert(meta?.visibility === 'group', 'visibility is group');
    assert(meta?.ttl_expires_at === null, 'no TTL (culture has no ttl_default)');
    console.log();
  }

  // =========================================================================
  // 3. Private interrupt -- should get domain TTL (3 days)
  // =========================================================================
  console.log('3. Private session (domain=interrupt, TTL=3 days)');

  const intId = 'smoke-private-interrupt-' + Date.now();
  testIds.push(intId);
  const intResult = await writeItem('session', {
    id: intId,
    date: new Date().toISOString().slice(0, 10),
    focus: 'Smoke test: private interrupt',
    summary: 'Verifying domain TTL for private interrupt items',
    tags: ['smoke-test'],
  }, { entity_id: 'russell' });

  assert('success' in intResult, 'write succeeded');

  const intMeta = await sqlite.readL2ItemMeta(intId);
  assert(intMeta !== null, 'item persisted');
  assert(intMeta?.visibility === 'private', 'visibility is private');
  assert(intMeta?.domain === 'interrupt', 'domain is interrupt (inferred from session)');
  assert(intMeta?.ttl_expires_at !== null, 'TTL is set');

  if (intMeta?.ttl_expires_at) {
    const ttlDate = new Date(intMeta.ttl_expires_at);
    const threeDaysMin = new Date(Date.now() + (259200 - 10) * 1000);
    const threeDaysMax = new Date(Date.now() + (259200 + 10) * 1000);
    assert(ttlDate >= threeDaysMin && ttlDate <= threeDaysMax,
      'TTL is ~3 days from now (domain policy)',
      `got ${intMeta.ttl_expires_at}`);
  }
  console.log();

  // =========================================================================
  // 4. Private procedural -- should have no TTL
  // =========================================================================
  console.log('4. Private learning (domain=procedural, no TTL)');

  const procId = 'smoke-private-proc-' + Date.now();
  testIds.push(procId);
  const procResult = await writeItem('learning', {
    id: procId,
    name: 'Smoke test: private procedural',
    type: 'pattern',
    content: 'Verifying no TTL for private procedural items',
    tags: ['smoke-test'],
    confidence: 0.8,
  }, { entity_id: 'russell' });

  assert('success' in procResult, 'write succeeded');

  const procMeta = await sqlite.readL2ItemMeta(procId);
  assert(procMeta !== null, 'item persisted');
  assert(procMeta?.visibility === 'private', 'visibility is private');
  assert(procMeta?.domain === 'procedural', 'domain is procedural');
  assert(procMeta?.ttl_expires_at === null, 'no TTL (procedural uses cap eviction, not TTL)');
  console.log();

  // =========================================================================
  // 5. Private value -- should have no TTL (permanent)
  // =========================================================================
  console.log('5. Private learning/principle (domain=value, permanent)');

  const valId = 'smoke-private-value-' + Date.now();
  testIds.push(valId);
  const valResult = await writeItem('learning', {
    id: valId,
    name: 'Smoke test: private value',
    type: 'principle',
    content: 'Verifying no TTL for value-domain items (permanent)',
    tags: ['smoke-test'],
    confidence: 0.9,
  }, { entity_id: 'russell' });

  assert('success' in valResult, 'write succeeded');

  const valMeta = await sqlite.readL2ItemMeta(valId);
  assert(valMeta !== null, 'item persisted');
  assert(valMeta?.domain === 'value', 'domain is value (inferred from learning/principle)');
  assert(valMeta?.ttl_expires_at === null, 'no TTL (value items are permanent)');
  console.log();

  // =========================================================================
  // Cleanup
  // =========================================================================
  console.log('Cleaning up test items...');
  for (const id of testIds) {
    await deleteItem(id);
  }

  // =========================================================================
  // Summary
  // =========================================================================
  console.log('='.repeat(50));
  console.log(`Results: ${passed} passed, ${failed} failed`);

  await provider.close();
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('Fatal:', e);
  // Attempt cleanup on error
  (async () => {
    try {
      const provider = await initStorageProvider(MEMORY_ROOT);
      for (const id of testIds) await provider.deleteL2Item(id);
      await provider.close();
    } catch { /* best effort */ }
  })();
  process.exit(1);
});
