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

async function initCryptoIfEnabled(): Promise<void> {
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);
  if (config.enabled && passphrase) {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Crypto: initialized');
  } else {
    console.log('WARNING: no encryption key');
  }
}

function hasCultureTtl(g: { culture: string }): boolean {
  try { const c = JSON.parse(g.culture); return c.ttl_default && c.ttl_default > 0; } catch { return false; }
}

function lacksCtultureTtl(g: { culture: string }): boolean {
  try { const c = JSON.parse(g.culture); return !c.ttl_default; } catch { return true; }
}

function assertTtlInRange(ttlExpiresAt: string, ttlSec: number, label: string): void {
  const ttlDate = new Date(ttlExpiresAt);
  const expectedMin = new Date(Date.now() + (ttlSec - 10) * 1000);
  const expectedMax = new Date(Date.now() + (ttlSec + 10) * 1000);
  assert(ttlDate >= expectedMin && ttlDate <= expectedMax, label, `got ${ttlExpiresAt}`);
}

async function testGroupWithTtl(
  group: { id: string; culture: string },
  sqlite: SqliteStorageProvider,
): Promise<void> {
  const culture = JSON.parse(group.culture);
  const ttlSec = culture.ttl_default;
  console.log(`1. Group item with culture TTL (${group.id}, ttl_default=${ttlSec}s)`);

  const id = 'smoke-group-ttl-' + Date.now();
  testIds.push(id);
  const result = await writeItem('learning', {
    id,
    name: 'Smoke test: group with TTL',
    type: 'pattern',
    content: 'Verifying culture TTL applies to group items',
    tags: ['smoke-test'],
    confidence: 0.8,
  }, { entity_id: 'russell', group_id: group.id });

  assert('success' in result, 'write succeeded');

  const meta = await sqlite.readL2ItemMeta(id);
  assert(meta !== null, 'item persisted');
  assert(meta?.visibility === 'group', 'visibility is group');
  assert(meta?.group_id === group.id, `group_id is ${group.id}`);
  assert(meta?.domain === 'procedural', 'domain is procedural (inferred from learning/pattern)');
  assert(meta?.ttl_expires_at !== null, 'TTL is set');

  if (meta?.ttl_expires_at) {
    assertTtlInRange(meta.ttl_expires_at, ttlSec, `TTL is ~${ttlSec}s from now (culture policy)`);
  }

  if (meta?.ttl_expires_at && ttlSec !== 259200) {
    const ttlDate = new Date(meta.ttl_expires_at);
    const threeDays = new Date(Date.now() + 259200 * 1000);
    const isNotDomainTtl = Math.abs(ttlDate.getTime() - threeDays.getTime()) > 60000;
    assert(isNotDomainTtl, 'TTL is NOT domain-derived (not 3 days)');
  }
  console.log();
}

async function testGroupNoTtl(
  group: { id: string },
  sqlite: SqliteStorageProvider,
): Promise<void> {
  console.log(`2. Group item without culture TTL (${group.id})`);

  const id = 'smoke-group-nottl-' + Date.now();
  testIds.push(id);
  const result = await writeItem('learning', {
    id,
    name: 'Smoke test: group no TTL',
    type: 'pattern',
    content: 'Verifying no TTL when culture has no ttl_default',
    tags: ['smoke-test'],
    confidence: 0.8,
  }, { entity_id: 'russell', group_id: group.id });

  assert('success' in result, 'write succeeded');

  const meta = await sqlite.readL2ItemMeta(id);
  assert(meta !== null, 'item persisted');
  assert(meta?.visibility === 'group', 'visibility is group');
  assert(meta?.ttl_expires_at === null, 'no TTL (culture has no ttl_default)');
  console.log();
}

async function main(): Promise<void> {
  console.log('Cordelia: Group Lifecycle Smoke Test');
  console.log('='.repeat(50));

  await initCryptoIfEnabled();

  const provider = await initStorageProvider(MEMORY_ROOT);
  console.log(`Storage: ${provider.name}`);

  if (provider.name !== 'sqlite') {
    console.log('SKIP: requires SQLite provider');
    process.exit(0);
  }

  const sqlite = provider as SqliteStorageProvider;

  const groups = await sqlite.listGroups();
  console.log(`Groups: ${groups.length}`);
  if (groups.length === 0) {
    console.log('SKIP: no groups in database');
    process.exit(0);
  }

  const groupWithTtl = groups.find(hasCultureTtl);
  const groupNoTtl = groups.find(lacksCtultureTtl);

  console.log(`  Group with TTL: ${groupWithTtl?.id || 'none'}`);
  console.log(`  Group without TTL: ${groupNoTtl?.id || 'none'}`);
  console.log();

  if (groupWithTtl) {
    await testGroupWithTtl(groupWithTtl, sqlite);
  }

  if (groupNoTtl) {
    await testGroupNoTtl(groupNoTtl, sqlite);
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
    assertTtlInRange(intMeta.ttl_expires_at, 259200, 'TTL is ~3 days from now (domain policy)');
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

try {
  await main();
} catch (e) {
  console.error('Fatal:', e);
  // Attempt cleanup on error
  try {
    const provider = await initStorageProvider(MEMORY_ROOT);
    for (const id of testIds) await provider.deleteL2Item(id);
    await provider.close();
  } catch { /* best effort */ }
  process.exit(1);
}
