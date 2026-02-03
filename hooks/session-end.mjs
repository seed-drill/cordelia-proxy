#!/usr/bin/env node
/**
 * Cordelia SessionEnd Hook - Update ephemeral memory and auto-summary
 *
 * Flow:
 * 1. Ensure local HTTP server sidecar is running
 * 2. Connect MCP client via SSE
 * 3. Read L1 via memory_read_hot
 * 4. Increment session_count
 * 5. Set last_session_end timestamp
 * 6. Generate auto-summary from L1 state (R2-015)
 * 7. Compute new chain_hash
 * 8. Write back via memory_write_hot
 *
 * Usage: CORDELIA_ENCRYPTION_KEY="..." node session-end.mjs [user_id]
 */
import * as crypto from 'crypto';
import {
  getEncryptionKey, getMemoryRoot,
  computeContentHash, computeChainHash, getUserId,
} from './lib.mjs';
import { ensureServer } from './server-manager.mjs';
import { createMcpClient, readL1, writeL1 } from './mcp-client.mjs';
import { notify } from './recovery.mjs';

/**
 * Generate a concise session summary from L1 state.
 * Format: "Session N: [focus]. [key outcomes]. [blockers if any]."
 */
function generateSummary(l1Data) {
  const parts = [];
  const sessionNum = l1Data.ephemeral?.session_count || '?';
  const focus = l1Data.active?.focus;
  const notes = l1Data.active?.notes || [];
  const blockers = l1Data.active?.blockers || [];

  if (focus) {
    parts.push(`Session ${sessionNum}: ${focus}`);
  } else {
    parts.push(`Session ${sessionNum}`);
  }

  const recentNotes = notes.slice(-5);
  if (recentNotes.length > 0) {
    const outcomes = recentNotes.map(n => {
      const firstSentence = n.split(/[.!]\s/)[0];
      return firstSentence.length > 120 ? firstSentence.slice(0, 117) + '...' : firstSentence;
    });
    parts.push(outcomes.join('. '));
  }

  if (blockers.length > 0) {
    parts.push(`Blockers: ${blockers.join(', ')}`);
  }

  let summary = parts.join('. ');
  if (summary.length > 500) {
    summary = summary.slice(0, 497) + '...';
  }

  return summary;
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
    console.error('Warning: CORDELIA_ENCRYPTION_KEY not found in env or .mcp.json - skipping session end');
    process.exit(0);
  }

  let client;
  try {
    // Ensure HTTP server sidecar is running
    const memoryRoot = await getMemoryRoot();
    const { baseUrl } = await ensureServer(passphrase, memoryRoot);

    // Connect MCP client
    client = await createMcpClient(baseUrl);

    // Read L1 via MCP
    const l1Data = await readL1(client, userId);

    if (!l1Data) {
      console.error(`[Cordelia] No L1 context for user: ${userId} - skipping session end`);
      process.exit(0);
    }

    // Update timestamp
    const now = new Date().toISOString();
    l1Data.updated_at = now;

    // Initialize or update ephemeral block
    if (!l1Data.ephemeral) {
      // Genesis - first tracked session
      const genesis = now;
      const genesisHash = crypto.createHash('sha256').update(`genesis:${genesis}`).digest('hex');

      l1Data.ephemeral = {
        session_count: 1,
        current_session_start: now,
        last_session_end: null,
        last_summary: null,
        open_threads: [],
        vessel: null,
        integrity: null,
      };

      const contentHash = computeContentHash(l1Data);
      const chainHash = computeChainHash(genesisHash, 1, contentHash);

      l1Data.ephemeral.integrity = {
        chain_hash: chainHash,
        previous_hash: genesisHash,
        genesis: genesis,
      };
    } else {
      const previousHash = l1Data.ephemeral.integrity.chain_hash;
      const newSessionCount = l1Data.ephemeral.session_count + 1;

      l1Data.ephemeral.session_count = newSessionCount;
      l1Data.ephemeral.last_session_end = now;

      // Auto-generate session summary (R2-015)
      l1Data.ephemeral.last_summary = generateSummary(l1Data);

      // Recompute chain hash after all updates
      const contentHash = computeContentHash(l1Data);
      l1Data.ephemeral.integrity.previous_hash = previousHash;
      l1Data.ephemeral.integrity.chain_hash = computeChainHash(previousHash, newSessionCount, contentHash);
    }

    // L1 size guard
    const l1Size = JSON.stringify(l1Data).length;
    if (l1Size > 50 * 1024) {
      console.error(`[Cordelia] WARNING: L1 size ${Math.round(l1Size / 1024)}KB exceeds 50KB target.`);
    }

    // Write back via MCP
    const writeResult = await writeL1(client, userId, 'replace', l1Data);
    if (writeResult?.error) {
      console.error(`[Cordelia] Write error: ${writeResult.error}`);
      process.exit(1);
    }

  } catch (error) {
    notify('Cordelia: SESSION-END ERROR', error.message);
    console.error(`[Cordelia] Session end error: ${error.message}`);
    process.exit(1);
  } finally {
    if (client) {
      try { await client.close(); } catch { /* ignore */ }
    }
  }
}

await main();
