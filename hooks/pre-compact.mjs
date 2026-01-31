#!/usr/bin/env node
/**
 * Cordelia PreCompact Hook - Flush insights before context compaction (R2-011)
 *
 * Flow:
 * 1. Read transcript_path from stdin (provided by Claude Code)
 * 2. Parse JSONL transcript, extract last N user+assistant messages
 * 3. Run lightweight novelty analysis
 * 4. Persist high-signal items to L1 (notes, blockers)
 * 5. Deduplicate against existing L1 content
 *
 * Timeout: 15s (target: <3s actual)
 * Fallback: Any failure exits 0 - never block compaction
 */
import * as fs from 'fs/promises';
import {
  getEncryptionKey, initCrypto, readL1, writeL1,
  computeContentHash, computeChainHash,
} from './lib.mjs';
import { analyzeMessages } from './novelty-lite.mjs';
import { notify } from './recovery.mjs';

const MAX_MESSAGES = 20;

/**
 * Read transcript path from stdin (Claude Code passes it as input).
 */
async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data.trim()));
    // If stdin is already ended or not piped
    setTimeout(() => resolve(data.trim()), 1000);
  });
}

/**
 * Parse JSONL transcript and extract recent user+assistant message texts.
 */
async function extractRecentMessages(transcriptPath) {
  let content;
  try {
    content = await fs.readFile(transcriptPath, 'utf-8');
  } catch (err) {
    console.error(`[Cordelia PreCompact] Cannot read transcript: ${err.message}`);
    return [];
  }

  const lines = content.split('\n').filter(Boolean);
  const messages = [];

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      // Claude Code transcript format: each line is a message object
      if (entry.role === 'user' || entry.role === 'assistant') {
        // Content can be string or array of content blocks
        let text = '';
        if (typeof entry.content === 'string') {
          text = entry.content;
        } else if (Array.isArray(entry.content)) {
          text = entry.content
            .filter(block => block.type === 'text')
            .map(block => block.text)
            .join('\n');
        }
        if (text.trim()) {
          messages.push(text);
        }
      }
    } catch {
      // Skip malformed lines
    }
  }

  // Return last N messages
  return messages.slice(-MAX_MESSAGES);
}

/**
 * Apply novelty suggestions to L1 data. Returns count of items persisted.
 */
function applyToL1(l1Data, suggestions) {
  if (!l1Data.active) l1Data.active = {};
  if (!l1Data.active.notes) l1Data.active.notes = [];
  if (!l1Data.active.blockers) l1Data.active.blockers = [];

  const existingNotes = new Set(l1Data.active.notes.map(n => n.toLowerCase()));
  const existingBlockers = new Set(l1Data.active.blockers.map(b => b.toLowerCase()));

  let persisted = 0;

  for (const item of suggestions) {
    const contentLower = item.content.toLowerCase();

    if (item.target === 'active.blockers' || item.signal === 'blocker') {
      // Check for "unblocked/resolved" - these remove blockers, don't add
      if (/unblocked|resolved/i.test(item.content)) {
        // Try to find and remove matching blocker
        const beforeLen = l1Data.active.blockers.length;
        l1Data.active.blockers = l1Data.active.blockers.filter(b =>
          !item.content.toLowerCase().includes(b.toLowerCase().slice(0, 20))
        );
        if (l1Data.active.blockers.length < beforeLen) persisted++;
        continue;
      }

      if (!existingBlockers.has(contentLower)) {
        l1Data.active.blockers.push(item.content);
        existingBlockers.add(contentLower);
        persisted++;
      }
    } else if (item.target?.startsWith('active.notes') || item.signal === 'decision' ||
               item.signal === 'insight' || item.signal === 'working_pattern' ||
               item.signal === 'meta_learning') {
      if (!existingNotes.has(contentLower)) {
        l1Data.active.notes.push(item.content);
        existingNotes.add(contentLower);
        persisted++;
      }
    }
    // Other targets (prefs, identity.key_refs) are not auto-persisted from compaction
  }

  return persisted;
}

async function main() {
  const userId = process.argv[2] || 'russell';

  try {
    // Read transcript path from stdin
    const stdinData = await readStdin();
    if (!stdinData) {
      console.error('[Cordelia PreCompact] No input on stdin, skipping');
      process.exit(0);
    }

    // Parse stdin - Claude Code sends JSON with transcript_path
    let transcriptPath;
    try {
      const input = JSON.parse(stdinData);
      transcriptPath = input.transcript_path;
    } catch {
      // Maybe it's just the path as plain text
      transcriptPath = stdinData;
    }

    if (!transcriptPath) {
      console.error('[Cordelia PreCompact] No transcript_path found in input');
      process.exit(0);
    }

    // Extract recent messages
    const messages = await extractRecentMessages(transcriptPath);
    if (messages.length === 0) {
      console.error('[Cordelia PreCompact] No messages extracted from transcript');
      process.exit(0);
    }

    // Run novelty analysis
    const { signals, suggestions } = analyzeMessages(messages, 0.7);
    if (suggestions.length === 0) {
      console.error('[Cordelia PreCompact] No novel content detected');
      process.exit(0);
    }

    // Load L1
    const passphrase = await getEncryptionKey();
    if (!passphrase) {
      console.error('[Cordelia PreCompact] No encryption key, skipping');
      process.exit(0);
    }

    const key = await initCrypto(passphrase);
    const { l1Data } = await readL1(userId, key);

    // Apply suggestions to L1
    const persisted = applyToL1(l1Data, suggestions);

    if (persisted === 0) {
      console.error('[Cordelia PreCompact] All items already in L1, no updates');
      process.exit(0);
    }

    // Update chain hash after L1 modifications
    if (l1Data.ephemeral?.integrity) {
      const contentHash = computeContentHash(l1Data);
      l1Data.ephemeral.integrity.chain_hash = computeChainHash(
        l1Data.ephemeral.integrity.previous_hash,
        l1Data.ephemeral.session_count,
        contentHash
      );
    }

    // Write back
    await writeL1(userId, l1Data, key);

    console.error(`[Cordelia PreCompact] Persisted ${persisted} items (signals: ${signals.join(', ')})`);
    // stdout message visible to Claude after compaction
    console.log(`[Cordelia] Pre-compaction flush: ${persisted} insights persisted to L1`);

  } catch (error) {
    // Never block compaction
    console.error(`[Cordelia PreCompact] Error (non-fatal): ${error.message}`);
    process.exit(0);
  }
}

main();
