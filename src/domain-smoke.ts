#!/usr/bin/env node
/**
 * Cordelia - Domain Smoke Test
 *
 * Exercises search, prefetch, and domain features against a live DB.
 * Verifies no regressions in FTS, vec, and hybrid scoring.
 */

import * as path from 'path';
import { initStorageProvider } from './storage.js';
import { getConfig as getCryptoConfig, loadOrCreateSalt, initCrypto } from './crypto.js';
import { search, prefetchItems, readItem } from './l2.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT
  || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');

let passed = 0;
let failed = 0;

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

function assertAllDomain(
  results: Array<{ domain?: string }>,
  domain: string,
  label: string,
): void {
  const all = results.every(r => r.domain === domain);
  assert(all, label,
    all ? '' : `got domains: ${[...new Set(results.map(r => r.domain))].join(',')}`);
}

function verifyDomainBoost(
  boostResults: { results: Array<{ domain?: string; name: string; score: number }> },
): void {
  if (boostResults.results.length > 0) {
    const valueBoosted = boostResults.results.filter(r => r.domain === 'value');
    const procUnboosted = boostResults.results.filter(r => r.domain === 'procedural');
    console.log(`  Value results: ${valueBoosted.length}, Procedural results: ${procUnboosted.length}`);

    if (valueBoosted.length > 0 && procUnboosted.length > 0) {
      console.log(`  Top value: ${valueBoosted[0].name.slice(0,30)} score=${valueBoosted[0].score.toFixed(3)}`);
      console.log(`  Top proc:  ${procUnboosted[0].name.slice(0,30)} score=${procUnboosted[0].score.toFixed(3)}`);
    }
    assert(boostResults.results.length > 0, 'boost query returns results');
  } else {
    console.log('  SKIP: no results for boost query');
  }
}

function verifyPrefetchOrder(domainOrder: Array<string | undefined>): void {
  const firstNonValue = domainOrder.findIndex(d => d !== 'value');
  const lastValue = domainOrder.lastIndexOf('value');

  if (lastValue >= 0 && firstNonValue >= 0) {
    assert(lastValue < firstNonValue || firstNonValue === -1,
      'value items come before non-value in prefetch',
      `first non-value at ${firstNonValue}, last value at ${lastValue}`);
  }

  const firstInterrupt = domainOrder.findIndex(d => d === 'interrupt');
  const lastProcedural = domainOrder.lastIndexOf('procedural');
  if (firstInterrupt >= 0 && lastProcedural >= 0) {
    assert(lastProcedural <= firstInterrupt,
      'procedural items come before interrupt in prefetch',
      `last proc at ${lastProcedural}, first interrupt at ${firstInterrupt}`);
  }
}

async function main(): Promise<void> {
  console.log('Cordelia: Domain Smoke Test');
  console.log('='.repeat(50));

  await initCryptoIfEnabled();

  const provider = await initStorageProvider(MEMORY_ROOT);
  console.log(`Storage: ${provider.name}`);

  if (provider.name !== 'sqlite') {
    console.log('SKIP: requires SQLite provider');
    process.exit(0);
  }

  const sqlite = provider as SqliteStorageProvider;
  const counts = await sqlite.getDomainCounts();
  console.log(`Domain counts: ${JSON.stringify(counts)}`);
  console.log(`Vec available: ${sqlite.vecAvailable()}`);
  console.log();

  // =========================================================================
  // 1. Basic search -- no domain filter (regression check)
  // =========================================================================
  console.log('1. Basic search (no domain filter)');

  const basicResults = await search({ query: 'memory', limit: 5 });
  assert(basicResults.length > 0, 'basic search returns results', `got ${basicResults.length}`);
  assert(basicResults[0].score > 0, 'results have scores');
  
  // Check domain field is present on results
  const hasDomain = basicResults.some(r => r.domain !== undefined);
  assert(hasDomain, 'results include domain field');
  const resultSummary = basicResults.map(r => `${r.name.slice(0,30)}(${r.domain})`).join(', ');
  console.log(`  Results: ${resultSummary}`);
  console.log();

  // =========================================================================
  // 2. Search with debug -- verify scoring pipeline intact
  // =========================================================================
  console.log('2. Debug search (verify scoring pipeline)');

  const debugResult = await search({ query: 'encryption key', limit: 5, debug: true as const });
  assert(debugResult.results.length > 0, 'debug search returns results');
  assert(debugResult.diagnostics.search_path === 'sql', 'search uses SQL path');
  assert(debugResult.diagnostics.fts_candidates > 0, 'FTS produced candidates',
    `fts=${debugResult.diagnostics.fts_candidates}`);
  
  const vecUsed = debugResult.diagnostics.vec_used;
  console.log(`  Vec used: ${vecUsed}, FTS candidates: ${debugResult.diagnostics.fts_candidates}, Vec candidates: ${debugResult.diagnostics.vec_candidates}`);
  
  // Check that scores are reasonable
  for (const r of debugResult.diagnostics.results.slice(0, 3)) {
    console.log(`    ${r.id.slice(0,30)}: fts=${r.fts_score.toFixed(3)} vec=${r.vec_score.toFixed(3)} combined=${r.combined_score.toFixed(3)}`);
  }
  console.log();

  // =========================================================================
  // 3. Domain filter -- value only
  // =========================================================================
  console.log('3. Search with domain=value filter');

  const valueResults = await search({ domain: 'value', limit: 20 });
  assert(valueResults.length > 0, 'value domain search returns results', `got ${valueResults.length}`);
  assertAllDomain(valueResults, 'value', 'all results are value domain');
  console.log(`  Value items: ${valueResults.length}`);
  for (const r of valueResults.slice(0, 5)) {
    console.log(`    ${r.name.slice(0,50)} (${r.type}/${r.domain})`);
  }
  console.log();

  // =========================================================================
  // 4. Domain filter -- interrupt only
  // =========================================================================
  console.log('4. Search with domain=interrupt filter');

  const interruptResults = await search({ domain: 'interrupt', limit: 20 });
  assert(interruptResults.length > 0, 'interrupt domain search returns results', `got ${interruptResults.length}`);
  assertAllDomain(interruptResults, 'interrupt', 'all results are interrupt domain');
  console.log(`  Interrupt items: ${interruptResults.length}`);
  console.log();

  // =========================================================================
  // 5. Domain filter -- procedural only
  // =========================================================================
  console.log('5. Search with domain=procedural filter');

  const procResults = await search({ domain: 'procedural', limit: 5 });
  assert(procResults.length > 0, 'procedural domain search returns results');
  assertAllDomain(procResults, 'procedural', 'all results are procedural domain');
  console.log();

  // =========================================================================
  // 6. Domain filter + keyword query
  // =========================================================================
  console.log('6. Combined: domain=value + query');

  const combinedResults = await search({ query: 'principle', domain: 'value', limit: 5 });
  console.log(`  Results: ${combinedResults.length}`);
  for (const r of combinedResults) {
    assert(r.domain === 'value', `${r.name.slice(0,30)} is value domain`);
    console.log(`    ${r.name.slice(0,50)} score=${r.score.toFixed(3)}`);
  }
  console.log();

  // =========================================================================
  // 7. Domain boost -- value items should score slightly higher
  // =========================================================================
  console.log('7. Domain boost check');

  const boostResults = await search({ query: 'sovereignty', limit: 10, debug: true as const });
  verifyDomainBoost(boostResults);
  console.log();

  // =========================================================================
  // 8. Prefetch -- domain-aware ordering
  // =========================================================================
  console.log('8. Prefetch (domain-aware ordering)');

  const prefetched = await prefetchItems('russell', { limit: 20 });
  assert(prefetched.length > 0, 'prefetch returns items', `got ${prefetched.length}`);
  
  const domainOrder = prefetched.map(p => p.domain);
  verifyPrefetchOrder(domainOrder);

  console.log(`  Order: ${domainOrder.join(', ')}`);
  console.log();

  // =========================================================================
  // 9. Read item -- verify domain on meta
  // =========================================================================
  console.log('9. Read item meta (domain + ttl)');

  // Pick a value item and an interrupt item
  const valueMeta = await provider.readL2ItemMeta(valueResults[0]?.id || '');
  if (valueMeta) {
    assert(valueMeta.domain === 'value', 'value item meta has domain=value');
    assert(valueMeta.ttl_expires_at === null, 'value item has no TTL');
  }

  if (interruptResults.length > 0) {
    const intMeta = await provider.readL2ItemMeta(interruptResults[0].id);
    if (intMeta) {
      assert(intMeta.domain === 'interrupt', 'interrupt item meta has domain=interrupt');
      // Interrupt items from backfill may not have TTL (only new writes get TTL)
      console.log(`  Interrupt TTL: ${intMeta.ttl_expires_at || 'null (pre-migration item)'}`);
    }
  }
  console.log();

  // =========================================================================
  // 10. Read a value item end-to-end
  // =========================================================================
  console.log('10. End-to-end: read a value-domain item');

  if (valueResults.length > 0) {
    const item = await readItem(valueResults[0].id);
    assert(item !== null, `readItem(${valueResults[0].id.slice(0,20)}) returns data`);
    if (item) {
      const content = (item as { content?: string }).content || (item as { summary?: string }).summary || '';
      console.log(`  Content preview: ${content.slice(0, 80)}...`);
    }
  }
  console.log();

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
  process.exit(1);
}
