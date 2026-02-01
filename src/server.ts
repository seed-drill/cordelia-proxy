#!/usr/bin/env node
/**
 * Project Cordelia - MCP Memory Server (stdio transport)
 *
 * Provides persistent dense memory for Claude via the Model Context Protocol.
 * Tool handlers are registered via registerCordeliaTools (shared with HTTP transport).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import * as path from 'path';
import { registerCordeliaTools, setEncryptionEnabled } from './mcp-tools.js';
import {
  getConfig as getCryptoConfig,
  loadOrCreateSalt,
  initCrypto,
} from './crypto.js';
import { initStorageProvider } from './storage.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';
import { InlinePolicyEngine, setPolicyEngine } from './policy.js';
import { periodicCheck } from './integrity.js';
import { getDefaultProvider } from './embeddings.js';
import * as l2 from './l2.js';

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');

const server = new Server(
  {
    name: 'cordelia',
    version: '0.2.0',
  },
  {
    capabilities: {
      tools: {},
      resources: {},
    },
  }
);

registerCordeliaTools(server);

async function initEncryption(): Promise<void> {
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);

  if (!config.enabled || !passphrase) {
    console.error('Cordelia: Encryption disabled (no CORDELIA_ENCRYPTION_KEY)');
    return;
  }

  try {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    setEncryptionEnabled(true);
    console.error('Cordelia: Encryption enabled (AES-256-GCM)');
  } catch (error) {
    console.error('Cordelia: Failed to initialize encryption:', (error as Error).message);
  }
}

async function main(): Promise<void> {
  // Initialize storage provider
  const storageProvider = await initStorageProvider(MEMORY_ROOT);
  console.error(`Cordelia: Storage provider: ${storageProvider.name}`);

  // Initialize encryption if configured
  await initEncryption();

  // Startup health checks + index integrity
  if (storageProvider.name === 'sqlite') {
    const sqliteProvider = storageProvider as SqliteStorageProvider;
    const vecOk = sqliteProvider.vecAvailable();
    const cacheCount = sqliteProvider.embeddingCacheCount();
    const vecRows = sqliteProvider.vecCount();
    const itemCount = sqliteProvider.itemCount();
    const ftsCount = sqliteProvider.ftsCount();
    console.error(`Cordelia: sqlite-vec available: ${vecOk}`);
    console.error(`Cordelia: items: ${itemCount}, FTS: ${ftsCount}, vec: ${vecRows}, embedding cache: ${cacheCount}`);

    // Auto-backfill FTS/vec if out of sync with l2_items
    if (itemCount > 0 && (ftsCount < itemCount || (vecOk && vecRows < itemCount))) {
      console.error(`Cordelia: index gap detected (items=${itemCount}, fts=${ftsCount}, vec=${vecRows}) — running backfill`);
      try {
        const backfillResult = await l2.backfillVec();
        console.error(`Cordelia: backfill complete — fts_updated=${backfillResult.fts_updated}, vec_generated=${backfillResult.generated}, vec_cached=${backfillResult.cached}, errors=${backfillResult.errors}`);
      } catch (e) {
        console.error(`Cordelia: backfill failed: ${(e as Error).message}`);
      }
    }

    const embeddingProvider = getDefaultProvider();
    if (embeddingProvider.dimensions() > 0) {
      embeddingProvider.isAvailable().then((ok) => {
        console.error(`Cordelia: embedding provider (${embeddingProvider.name}/${embeddingProvider.modelName()}): ${ok ? 'available' : 'UNAVAILABLE'}`);
      }).catch(() => {
        console.error(`Cordelia: embedding provider (${embeddingProvider.name}): UNAVAILABLE`);
      });
    } else {
      console.error('Cordelia: embedding provider: disabled');
    }
  }

  // Start periodic integrity check (default: 30 min)
  const integrityIntervalMs = parseInt(process.env.CORDELIA_INTEGRITY_INTERVAL_MS || '1800000', 10);
  if (integrityIntervalMs > 0) {
    const integrityInterval = setInterval(async () => {
      try {
        const report = await periodicCheck();
        if (!report.ok) {
          console.error(`[Cordelia] Integrity check FAILED:`, JSON.stringify(report.checks));
        }
      } catch (e) {
        console.error(`[Cordelia] Integrity check error: ${(e as Error).message}`);
      }
    }, integrityIntervalMs);
    integrityInterval.unref();
    console.error(`Cordelia: Periodic integrity check enabled (${integrityIntervalMs / 1000}s)`);
  }

  // Start TTL sweep timer
  const ttlSweepIntervalMs = parseInt(process.env.CORDELIA_TTL_SWEEP_INTERVAL_MS || '3600000', 10);
  if (ttlSweepIntervalMs > 0) {
    const ttlSweepInterval = setInterval(async () => {
      try {
        const result = await l2.sweepExpiredItems();
        if (result.swept > 0) {
          console.error(`[Cordelia] TTL sweep: ${result.swept} items expired`);
        }
      } catch (e) {
        console.error(`[Cordelia] TTL sweep error: ${(e as Error).message}`);
      }
    }, ttlSweepIntervalMs);
    ttlSweepInterval.unref();
  }

  // Sync group items from P2P network (non-blocking on failure)
  try {
    const { getNodeBridge } = await import('./node-bridge.js');
    const bridge = getNodeBridge();
    if (await bridge.isAvailable()) {
      await bridge.syncGroups(storageProvider);
      const allGroups = await storageProvider.listGroups();
      const groupIds = allGroups.map((g) => g.id);
      const result = await bridge.syncGroupItems(groupIds, storageProvider);
      if (result.synced > 0) {
        console.error(`Cordelia: synced ${result.synced} group items from P2P network`);
      }
    }
  } catch (e) {
    console.error(`Cordelia: node bridge sync failed (non-fatal): ${(e as Error).message}`);
  }

  // Initialize policy engine
  setPolicyEngine(new InlinePolicyEngine(storageProvider));

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Cordelia MCP server running');
}

main().catch(console.error);
