#!/usr/bin/env node
/**
 * Cordelia SessionEnd Hook - Update ephemeral memory, auto-summary, and commit
 *
 * Flow:
 * 1. Decrypt L1 context
 * 2. Increment session_count
 * 3. Set last_session_end timestamp
 * 4. Generate auto-summary from L1 state (R2-015)
 * 5. Compute new chain_hash
 * 6. Re-encrypt and write
 * 7. Auto-commit to git
 *
 * Usage: CORDELIA_ENCRYPTION_KEY="..." node session-end.mjs [user_id]
 */
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import {
  getEncryptionKey, initCrypto, readL1, writeL1, getL1Path,
  computeContentHash, computeChainHash, CORDELIA_DIR,
} from './lib.mjs';
import { attemptRecovery, createBackup, removeBackup, notify } from './recovery.mjs';

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

  // Start with session number and focus
  if (focus) {
    parts.push(`Session ${sessionNum}: ${focus}`);
  } else {
    parts.push(`Session ${sessionNum}`);
  }

  // Add last 3-5 notes as key outcomes (take most recent)
  const recentNotes = notes.slice(-5);
  if (recentNotes.length > 0) {
    // Truncate each note to keep summary concise
    const outcomes = recentNotes.map(n => {
      // Take first sentence or first 120 chars
      const firstSentence = n.split(/[.!]\s/)[0];
      return firstSentence.length > 120 ? firstSentence.slice(0, 117) + '...' : firstSentence;
    });
    parts.push(outcomes.join('. '));
  }

  // Add blockers if any
  if (blockers.length > 0) {
    parts.push(`Blockers: ${blockers.join(', ')}`);
  }

  // Join and cap total length
  let summary = parts.join('. ');
  if (summary.length > 500) {
    summary = summary.slice(0, 497) + '...';
  }

  return summary;
}

async function gitCommit() {
  try {
    const status = execSync('git status --porcelain memory/', {
      cwd: CORDELIA_DIR,
      encoding: 'utf-8',
    });

    if (!status.trim()) {
      return;
    }

    execSync('git add memory/', { cwd: CORDELIA_DIR });
    execSync(
      `git commit -m "chore: Auto-commit memory state (session end)\n\nCo-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>" --no-verify`,
      { cwd: CORDELIA_DIR, stdio: 'ignore' }
    );
  } catch (error) {
    // Ignore commit errors - not critical
  }
}

async function main() {
  const userId = process.argv[2] || 'russell';
  const passphrase = await getEncryptionKey();

  if (!passphrase) {
    console.error('Warning: CORDELIA_ENCRYPTION_KEY not found in env or .mcp.json - skipping session end');
    process.exit(0);
  }

  try {
    const key = await initCrypto(passphrase);
    const l1Path = getL1Path(userId);

    // Create backup before any modifications
    await createBackup(l1Path);

    // Read L1 with recovery support
    let l1Data, recoveredFrom;
    try {
      const result = await readL1(userId, key, async (filePath, decryptError) => {
        console.error(`[Cordelia] Session-end decryption failed: ${decryptError.message}`);
        console.error('[Cordelia] Attempting recovery...');
        const recovery = await attemptRecovery(filePath, CORDELIA_DIR);
        if (recovery.recovered) {
          console.error(`[Cordelia] Recovered from ${recovery.source}`);
          notify('Cordelia: Session-End Recovery', `Memory restored from ${recovery.source}`);
        }
        return recovery;
      });
      l1Data = result.l1Data;
      recoveredFrom = result.recoveredFrom;
    } catch (error) {
      notify('Cordelia: SESSION-END FAILED', 'Could not decrypt or recover memory');
      console.error(`[Cordelia] Recovery failed: ${error.message}`);
      console.error('[Cordelia] Skipping session-end to preserve data');
      await removeBackup(l1Path);
      process.exit(1);
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

    // Re-encrypt and write
    await writeL1(userId, l1Data, key);

    // Success - remove backup
    await removeBackup(l1Path);

    // Auto-commit
    await gitCommit();

    if (recoveredFrom) {
      console.error(`[Cordelia] Session ended (recovered from ${recoveredFrom})`);
    }

  } catch (error) {
    // Unexpected error - try to restore backup
    const l1Path = getL1Path(userId);
    const backupPath = `${l1Path}.backup`;
    try {
      const { default: fs } = await import('fs/promises');
      const backupExists = await fs.access(backupPath).then(() => true).catch(() => false);
      if (backupExists) {
        const backupContent = await fs.readFile(backupPath, 'utf-8');
        await fs.writeFile(l1Path, backupContent);
        await removeBackup(l1Path);
        console.error(`[Cordelia] Restored from backup after error`);
      }
    } catch {
      // Backup restore also failed
    }
    notify('Cordelia: SESSION-END ERROR', error.message);
    console.error(`[Cordelia] Session end error: ${error.message}`);
    process.exit(1);
  }
}

main();
