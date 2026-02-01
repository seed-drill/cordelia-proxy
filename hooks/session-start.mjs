#!/usr/bin/env node
/**
 * Cordelia SessionStart Hook - Load L1 hot context with integrity verification
 *
 * Flow:
 * 1. Ensure local HTTP server sidecar is running
 * 2. Connect MCP client via SSE
 * 3. Read L1 context via memory_read_hot
 * 4. Verify integrity chain (recompute hash, compare to stored)
 * 5. Update current_session_start
 * 6. Write back via memory_write_hot
 * 7. Output context + verification status to stdout
 *
 * Usage: CORDELIA_ENCRYPTION_KEY="..." node session-start.mjs [user_id]
 */
import {
  getEncryptionKey, getMemoryRoot,
  computeContentHash, computeChainHash, getUserId,
} from './lib.mjs';
import { ensureServer } from './server-manager.mjs';
import { createMcpClient, readL1, writeL1 } from './mcp-client.mjs';
import { notify } from './recovery.mjs';

const REMOTE_URL = process.env.CORDELIA_REMOTE_URL || 'https://cordelia-seed-drill.fly.dev';

/**
 * Check remote sync status
 */
async function checkSyncStatus(userId, localData) {
  try {
    const response = await fetch(`${REMOTE_URL}/api/hot/${userId}`, {
      signal: AbortSignal.timeout(5000),
    });

    if (response.status === 404) {
      return { synced: true, reason: 'no remote (local only)' };
    }

    if (!response.ok) {
      return { synced: true, reason: `remote error: ${response.status}` };
    }

    const remoteData = await response.json();
    const localTime = new Date(localData.updated_at);
    const remoteTime = new Date(remoteData.updated_at);

    if (localTime.getTime() === remoteTime.getTime()) {
      return { synced: true };
    }

    if (remoteTime > localTime) {
      const diff = Math.round((remoteTime - localTime) / 1000 / 60);
      return {
        synced: false,
        direction: 'pull',
        remoteTime,
        localTime,
        message: `Remote is ${diff}m newer. Run sync daemon or pull manually.`
      };
    } else {
      const diff = Math.round((localTime - remoteTime) / 1000 / 60);
      return {
        synced: false,
        direction: 'push',
        remoteTime,
        localTime,
        message: `Local is ${diff}m newer. Sync daemon will push changes.`
      };
    }
  } catch (error) {
    return { synced: true, reason: `offline (${error.message})` };
  }
}

/**
 * Verify integrity chain.
 */
function verifyIntegrity(l1Data) {
  if (!l1Data.ephemeral) {
    return { valid: true, reason: 'No ephemeral data (pre-S7)' };
  }

  const { ephemeral } = l1Data;
  if (!ephemeral.integrity) {
    return { valid: false, reason: 'Missing integrity block' };
  }

  const { integrity } = ephemeral;
  const { chain_hash, previous_hash, genesis } = integrity;

  const contentHash = computeContentHash(l1Data);
  const expectedHash = computeChainHash(previous_hash, ephemeral.session_count, contentHash);

  if (expectedHash !== chain_hash) {
    return {
      valid: false,
      reason: 'Chain hash mismatch - memory may have been tampered with or corrupted',
    };
  }

  const genesisDate = new Date(genesis);
  const now = new Date();
  const ageDays = Math.floor((now - genesisDate) / (1000 * 60 * 60 * 24));

  return {
    valid: true,
    sessionAge: `Session ${ephemeral.session_count} (${ageDays} days since genesis)`,
  };
}

async function main() {
  let userId;
  try {
    userId = await getUserId();
  } catch (err) {
    console.error(`[Cordelia] ${err.message}`);
    process.exit(1);
  }

  const passphrase = await getEncryptionKey();

  if (!passphrase) {
    console.error('Warning: CORDELIA_ENCRYPTION_KEY not found in env or .mcp.json');
    process.exit(0);
  }

  let client;
  try {
    // Ensure HTTP server sidecar is running
    const memoryRoot = await getMemoryRoot();
    const { baseUrl, cold } = await ensureServer(passphrase, memoryRoot);
    if (cold) {
      console.error('[Cordelia] Started HTTP server sidecar');
    }

    // Connect MCP client
    client = await createMcpClient(baseUrl);

    // Read L1 via MCP
    const l1Data = await readL1(client, userId);

    if (!l1Data) {
      console.error(`[Cordelia] No L1 context found for user: ${userId}`);
      console.log('=== CORDELIA L1 HOT CONTEXT ===');
      console.log(`{"error": "no L1 context for ${userId}"}`);
      console.log('=== END CORDELIA CONTEXT ===');
      process.exit(0);
    }

    // Verify integrity BEFORE any modifications
    const integrity = verifyIntegrity(l1Data);

    // Only update session start time if integrity verified
    if (integrity.valid && l1Data.ephemeral) {
      const now = new Date().toISOString();
      l1Data.ephemeral.current_session_start = now;

      // Recompute chain hash after updating session start
      const contentHash = computeContentHash(l1Data);
      l1Data.ephemeral.integrity.chain_hash = computeChainHash(
        l1Data.ephemeral.integrity.previous_hash,
        l1Data.ephemeral.session_count,
        contentHash
      );

      // Write back via MCP
      const writeResult = await writeL1(client, userId, 'replace', l1Data, l1Data.updated_at);
      if (writeResult?.error) {
        console.error(`[Cordelia] Write error: ${writeResult.error}`);
      }
    }

    // Check sync status with remote
    const syncStatus = await checkSyncStatus(userId, l1Data);

    // Output status banner
    const genesisDate = l1Data.ephemeral?.integrity?.genesis
      ? new Date(l1Data.ephemeral.integrity.genesis)
      : null;
    const daysSinceGenesis = genesisDate
      ? Math.floor((new Date() - genesisDate) / (1000 * 60 * 60 * 24))
      : '?';
    const sessionNum = l1Data.ephemeral?.session_count || '?';
    const lastEnd = l1Data.ephemeral?.last_session_end
      ? new Date(l1Data.ephemeral.last_session_end).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
      : null;
    const focus = l1Data.active?.focus || 'No active focus';

    // Brief status to stderr
    if (integrity.valid) {
      const syncInfo = syncStatus.synced ? 'Synced' : `SYNC: ${syncStatus.direction}`;
      console.error(`[Cordelia] Session ${sessionNum} | Genesis +${daysSinceGenesis}d | Chain OK | ${syncInfo}`);
    } else {
      console.error(`[Cordelia] Session ${sessionNum} | CHAIN FAILED: ${integrity.reason}`);
    }

    // macOS notification
    let notifTitle, notifMsg;
    if (integrity.valid) {
      notifTitle = 'Cordelia Active';
      notifMsg = `Session ${sessionNum} | Chain verified`;
    } else {
      notifTitle = 'Cordelia: INTEGRITY FAILED';
      notifMsg = integrity.reason;
    }
    notify(notifTitle, notifMsg);

    // Full banner to stdout
    console.log('');
    console.log('================================================');
    if (integrity.valid) {
      console.log(`[CORDELIA] Session ${sessionNum} | Genesis +${daysSinceGenesis}d | Chain: VERIFIED`);
    } else {
      console.log(`[CORDELIA] Session ${sessionNum} | Genesis +${daysSinceGenesis}d | Chain: FAILED`);
      console.log(`[WARNING] ${integrity.reason}`);
    }

    // Sync status
    if (!syncStatus.synced) {
      console.log(`[SYNC] ${syncStatus.message}`);
      if (syncStatus.direction === 'pull') {
        console.log(`[SYNC] To pull: curl ${REMOTE_URL}/api/hot/${userId} > memory/L1-hot/${userId}.json`);
      }
    } else if (syncStatus.reason) {
      console.log(`[SYNC] ${syncStatus.reason}`);
    } else {
      console.log(`[SYNC] Local and remote in sync`);
    }

    if (lastEnd) {
      console.log(`[LAST] ${lastEnd}`);
    }
    console.log(`[FOCUS] ${focus}`);
    if (l1Data.ephemeral?.last_summary) {
      console.log(`[PREV] ${l1Data.ephemeral.last_summary}`);
    }
    if (l1Data.ephemeral?.open_threads?.length > 0) {
      console.log(`[THREADS] ${l1Data.ephemeral.open_threads.join(', ')}`);
    }
    console.log('================================================');
    console.log('');

    // Output full context for Claude
    console.log('=== CORDELIA L1 HOT CONTEXT ===');
    console.log(JSON.stringify(l1Data, null, 2));
    console.log('=== END CORDELIA CONTEXT ===');

  } catch (error) {
    notify('Cordelia: ERROR', error.message);
    console.error(`[Cordelia] Unexpected error: ${error.message}`);
    console.log('=== CORDELIA L1 HOT CONTEXT ===');
    console.log(`{"error": "${error.message}"}`);
    console.log('=== END CORDELIA CONTEXT ===');
    process.exit(0);
  } finally {
    if (client) {
      try { await client.close(); } catch { /* ignore */ }
    }
  }
}

main();
