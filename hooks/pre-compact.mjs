#!/usr/bin/env node
/**
 * Cordelia PreCompact Hook - Flush insights before context compaction (R2-011)
 *
 * Flow:
 * 1. Read transcript_path from stdin (provided by Claude Code)
 * 2. Parse JSONL transcript, extract last N user+assistant messages
 * 3. Run lightweight novelty analysis
 * 4. Read L1 via REST API (GET /api/hot/:userId)
 * 5. Persist high-signal items to L1 (notes, blockers)
 * 6. Deduplicate against existing L1 content
 * 7. Write back via REST API (PUT /api/hot/:userId)
 *
 * Timeout: 15s (target: <3s actual)
 * Fallback: Any failure exits 0 - never block compaction
 */
import * as fs from 'fs/promises';
import {
  getMemoryRoot,
  computeContentHash, computeChainHash, getUserId,
} from './lib.mjs';
import { ensureServer } from './server-manager.mjs';
import { analyzeMessages } from './novelty-lite.mjs';

const MAX_MESSAGES = 20;

let BASE_URL;

/**
 * Read L1 via REST API.
 */
async function readL1(userId) {
  const res = await fetch(`${BASE_URL}/api/hot/${userId}`, {
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) return null;
  const data = await res.json();
  if (data.error) return null;
  return data;
}

/**
 * Write L1 via REST API.
 */
async function writeL1(userId, data) {
  const res = await fetch(`${BASE_URL}/api/hot/${userId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(5000),
  });
  return await res.json();
}

/**
 * Read transcript path from stdin (Claude Code passes it as input).
 */
async function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data.trim()));
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
      if (entry.role === 'user' || entry.role === 'assistant') {
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

  return messages.slice(-MAX_MESSAGES);
}

function isBlockerItem(item) {
  return item.target === 'active.blockers' || item.signal === 'blocker';
}

const NOTE_SIGNALS = new Set(['decision', 'insight', 'working_pattern', 'meta_learning']);

function isNoteItem(item) {
  return item.target?.startsWith('active.notes') || NOTE_SIGNALS.has(item.signal);
}

function applyBlockerResolution(l1Data, item) {
  const beforeLen = l1Data.active.blockers.length;
  l1Data.active.blockers = l1Data.active.blockers.filter(b =>
    !item.content.toLowerCase().includes(b.toLowerCase().slice(0, 20))
  );
  return l1Data.active.blockers.length < beforeLen ? 1 : 0;
}

function addIfNew(list, existingSet, content) {
  const lower = content.toLowerCase();
  if (existingSet.has(lower)) return 0;
  list.push(content);
  existingSet.add(lower);
  return 1;
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
    if (isBlockerItem(item)) {
      if (/unblocked|resolved/i.test(item.content)) {
        persisted += applyBlockerResolution(l1Data, item);
        continue;
      }
      persisted += addIfNew(l1Data.active.blockers, existingBlockers, item.content);
    } else if (isNoteItem(item)) {
      persisted += addIfNew(l1Data.active.notes, existingNotes, item.content);
    }
  }

  return persisted;
}

async function main() {
  let userId;
  try {
    userId = await getUserId();
  } catch (err) {
    console.error(`[Cordelia PreCompact] ${err.message}`);
    process.exit(0); // Never block compaction
  }

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

    // Ensure server is running
    const memoryRoot = await getMemoryRoot();
    const { baseUrl } = await ensureServer(memoryRoot);
    BASE_URL = baseUrl;

    // Read L1 via REST API
    const l1Data = await readL1(userId);
    if (!l1Data) {
      console.error('[Cordelia PreCompact] No L1 context, skipping');
      process.exit(0);
    }

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

    // Write back via REST API
    const writeResult = await writeL1(userId, l1Data);
    if (writeResult?.error) {
      console.error(`[Cordelia PreCompact] Write error: ${writeResult.error}`);
    }

    console.error(`[Cordelia PreCompact] Persisted ${persisted} items (signals: ${signals.join(', ')})`);
    console.log(`[Cordelia] Pre-compaction flush: ${persisted} insights persisted to L1`);

  } catch (error) {
    // Never block compaction
    console.error(`[Cordelia PreCompact] Error (non-fatal): ${error.message}`);
    process.exit(0);
  }
}

await main();
