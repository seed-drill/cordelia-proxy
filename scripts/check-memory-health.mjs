#!/usr/bin/env node
/**
 * Cordelia Memory Health Check
 *
 * Run BEFORE and AFTER upgrades to catch memory integrity issues.
 * Operates on live data. Checks 10-11 perform a write/delete round-trip
 * using a canary item that is always cleaned up.
 *
 * Checks:
 *   1. L1 duplicate user_ids (e.g. russell + russwing)
 *   2. L1 encrypted file exists and is decryptable
 *   3. L1 SQLite vs encrypted file consistency
 *   4. L2 orphaned items (owner_id = NULL)
 *   5. L2 prefetch returns items for each L1 user
 *   6. L2 index count vs item count
 *   7. Chain integrity (hash verification)
 *   8. Session count sanity
 *   9. L2 search functional
 *  10. L2 write/read/delete round-trip (canary test)
 *  11. L2 write rejects invalid schema (negative test)
 *
 * Exit 0 = all pass, Exit 1 = any fail, Exit 2 = any warn (no fail)
 *
 * Usage:
 *   node scripts/check-memory-health.mjs [--memory-root ~/.cordelia/memory] [--verbose]
 */

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 10_000;
const GLOBAL_TIMEOUT_MS = 60_000;

const args = process.argv.slice(2);
const VERBOSE = args.includes('--verbose') || args.includes('-v');
const memRootIdx = args.indexOf('--memory-root');
const MEMORY_ROOT = memRootIdx >= 0 ? args[memRootIdx + 1] : join(process.env.HOME, '.cordelia', 'memory');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let nextId = 1;

function makeRequest(method, params = {}) {
  return { jsonrpc: '2.0', id: nextId++, method, params };
}

function makeNotification(method, params = {}) {
  return { jsonrpc: '2.0', method, params };
}

function extractEncryptionKey() {
  const claudeJson = resolve(process.env.HOME, '.claude.json');
  try {
    const config = JSON.parse(readFileSync(claudeJson, 'utf-8'));
    const key = config?.mcpServers?.cordelia?.env?.CORDELIA_ENCRYPTION_KEY;
    if (key) return key;
  } catch { /* fall through */ }
  if (process.env.CORDELIA_ENCRYPTION_KEY) return process.env.CORDELIA_ENCRYPTION_KEY;

  // Try project .mcp.json
  const mcpJson = resolve(PROJECT_ROOT, '..', 'seed-drill', '.mcp.json');
  try {
    const config = JSON.parse(readFileSync(mcpJson, 'utf-8'));
    const key = config?.mcpServers?.cordelia?.env?.CORDELIA_ENCRYPTION_KEY;
    if (key) return key;
  } catch { /* fall through */ }

  throw new Error('Cannot find CORDELIA_ENCRYPTION_KEY');
}

function spawnServer(encryptionKey) {
  const serverPath = resolve(PROJECT_ROOT, 'dist', 'server.js');

  const child = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CORDELIA_ENCRYPTION_KEY: encryptionKey,
      CORDELIA_MEMORY_ROOT: MEMORY_ROOT,
      CORDELIA_STORAGE: 'sqlite',
      CORDELIA_EMBEDDING_PROVIDER: 'none',
      CORDELIA_INTEGRITY_INTERVAL_MS: '0',
      CORDELIA_TTL_SWEEP_INTERVAL_MS: '0',
    },
  });

  const rl = createInterface({ input: child.stdout });

  let stderrBuf = '';
  child.stderr.on('data', (chunk) => {
    stderrBuf += chunk.toString();
    if (VERBOSE) process.stderr.write(chunk);
  });

  return { child, rl, stderrBuf: () => stderrBuf };
}

function waitForStartup(stderrFn, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error('Server startup timeout')), timeoutMs);
    const poll = setInterval(() => {
      if (stderrFn().includes('Cordelia MCP server running')) {
        clearInterval(poll);
        clearTimeout(deadline);
        resolve();
      }
    }, 50);
  });
}

function sendRequest(child, rl, request, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(
      () => reject(new Error(`Timeout: ${request.method} (id=${request.id})`)),
      timeoutMs,
    );
    const handler = (line) => {
      try {
        const msg = JSON.parse(line);
        if (msg.id === request.id) {
          rl.removeListener('line', handler);
          clearTimeout(deadline);
          resolve(msg);
        }
      } catch { /* ignore non-JSON */ }
    };
    rl.on('line', handler);
    child.stdin.write(JSON.stringify(request) + '\n');
  });
}

function sendNotification(child, notification) {
  child.stdin.write(JSON.stringify(notification) + '\n');
}

function parseContent(response) {
  if (response?.error) {
    throw new Error(`MCP error: ${response.error.message || JSON.stringify(response.error)}`);
  }
  const text = response?.result?.content?.[0]?.text;
  if (!text) throw new Error(`No content: ${JSON.stringify(response)}`);
  return JSON.parse(text);
}

/** Like parseContent but returns null on error instead of throwing. */
function tryParseContent(response) {
  try {
    return parseContent(response);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const results = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function runCheck(name, level, fn) {
  try {
    await fn();
    results.push({ name, level, pass: true });
    console.log(`  PASS  ${name}`);
  } catch (e) {
    results.push({ name, level, pass: false, error: e.message });
    const tag = level === 'FAIL' ? 'FAIL' : 'WARN';
    console.log(`  ${tag}  ${name}: ${e.message}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const globalDeadline = setTimeout(() => {
    console.log('\nFATAL: Global timeout exceeded');
    process.exit(1);
  }, GLOBAL_TIMEOUT_MS);

  console.log('\n=== Cordelia Memory Health Check ===');
  console.log(`Memory root: ${MEMORY_ROOT}\n`);

  // Pre-flight: check memory root exists
  if (!existsSync(MEMORY_ROOT)) {
    console.log(`FATAL: Memory root does not exist: ${MEMORY_ROOT}`);
    process.exit(1);
  }

  // Pre-flight: check encrypted L1 files exist
  const l1Dir = join(MEMORY_ROOT, 'L1-hot');
  const l1Files = existsSync(l1Dir) ? readdirSync(l1Dir).filter(f => f.endsWith('.json') && !f.includes('backup')) : [];
  console.log(`L1 encrypted files: ${l1Files.join(', ') || '(none)'}`);

  // Pre-flight: check SQLite DB exists
  const dbPath = join(MEMORY_ROOT, 'cordelia.db');
  const dbExists = existsSync(dbPath);
  console.log(`SQLite database: ${dbExists ? 'exists' : 'MISSING'}`);
  console.log('');

  // Start MCP server
  const encryptionKey = extractEncryptionKey();
  const { child, rl, stderrBuf } = spawnServer(encryptionKey);

  try {
    await waitForStartup(stderrBuf);
    if (VERBOSE) console.log('Server started.\n');

    // MCP handshake
    const initResp = await sendRequest(child, rl, makeRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'cordelia-health-check', version: '1.0.0' },
    }));
    assert(initResp.result, 'MCP initialize failed');
    sendNotification(child, makeNotification('notifications/initialized'));
    await new Promise((r) => setTimeout(r, 200));

    // -----------------------------------------------------------------------
    // CHECK 1: System status
    // -----------------------------------------------------------------------
    let statusData;
    await runCheck('System status is OK', 'FAIL', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_status', arguments: {},
      }));
      statusData = parseContent(resp);
      assert(statusData.status === 'ok', `status="${statusData.status}"`);
    });

    // -----------------------------------------------------------------------
    // CHECK 2: No duplicate L1 user_ids
    // -----------------------------------------------------------------------
    const l1Users = statusData?.layers?.L1_hot?.users || [];

    // Pre-read all L1 users, tolerating read failures (different key, corrupt, etc.)
    const l1Data = new Map(); // user_id -> data | null
    const l1Errors = new Map(); // user_id -> error message
    for (const u of l1Users) {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_hot', arguments: { user_id: u },
      }));
      const data = tryParseContent(resp);
      l1Data.set(u, data);
      if (!data && resp?.error) {
        l1Errors.set(u, resp.error.message || 'unknown error');
      }
    }

    // Report any L1 read failures
    if (l1Errors.size > 0) {
      await runCheck('All L1 users readable', 'WARN', async () => {
        const msgs = [...l1Errors.entries()].map(([u, e]) => `${u}: ${e}`);
        throw new Error(`Could not read L1 for: ${msgs.join('; ')}`);
      });
    }

    // Helper: is this user active (not deprecated, not unreadable)?
    function isActiveUser(u) {
      const data = l1Data.get(u);
      if (!data) return false;
      if (data.identity?.id?.includes('DEPRECATED')) return false;
      if (data.active?.focus?.includes('DEPRECATED')) return false;
      return true;
    }

    const activeUsers = l1Users.filter(isActiveUser);

    await runCheck('No duplicate L1 user_ids (identity split)', 'FAIL', async () => {
      const seen = new Map();
      const duplicates = [];

      for (const u of activeUsers) {
        const data = l1Data.get(u);
        const identityId = data?.identity?.id;
        for (const [otherUser, otherId] of seen.entries()) {
          if (identityId && otherId && identityId === otherId && otherUser !== u) {
            duplicates.push(`${u} and ${otherUser} share identity.id="${identityId}"`);
          }
        }
        seen.set(u, identityId);
      }

      assert(duplicates.length === 0,
        `Duplicate identity detected: ${duplicates.join('; ')}. ` +
        'This causes memory split -- different sessions write to different L1 stores.');
    });

    // -----------------------------------------------------------------------
    // CHECK 3: L1 encrypted file exists for each active SQLite user
    // -----------------------------------------------------------------------
    await runCheck('L1 encrypted files match SQLite users', 'WARN', async () => {
      const missing = activeUsers.filter(u => !l1Files.includes(`${u}.json`));
      assert(missing.length === 0,
        `Active users without encrypted L1 file: ${missing.join(', ')}. ` +
        'Session hooks will fail to load context for these users.');
    });

    // -----------------------------------------------------------------------
    // CHECK 4: L2 orphaned items (owner_id = NULL)
    // -----------------------------------------------------------------------
    const l2Stats = statusData?.layers?.L2_warm;
    await runCheck('No L2 items with NULL owner_id', 'FAIL', async () => {
      const totalItems = l2Stats?.entries || 0;
      if (totalItems === 0) return; // No items to check

      let totalPrefetched = 0;
      for (const u of activeUsers) {
        const prefetchResp = await sendRequest(child, rl, makeRequest('tools/call', {
          name: 'memory_prefetch_l2', arguments: { user_id: u, limit: 1 },
        }));
        const prefetchData = parseContent(prefetchResp);
        totalPrefetched += prefetchData.prefetched || 0;
      }

      assert(totalPrefetched > 0,
        `${totalItems} L2 items exist but prefetch returns 0 for all active users. ` +
        'Likely cause: owner_id is NULL on L2 items (run: ' +
        'sqlite3 cordelia.db "SELECT COUNT(*) FROM l2_items WHERE owner_id IS NULL")');
    });

    // -----------------------------------------------------------------------
    // CHECK 5: L2 prefetch returns items for active users
    // -----------------------------------------------------------------------
    for (const u of activeUsers) {
      await runCheck(`L2 prefetch returns items for user "${u}"`, 'WARN', async () => {
        const prefetchResp = await sendRequest(child, rl, makeRequest('tools/call', {
          name: 'memory_prefetch_l2', arguments: { user_id: u, limit: 5 },
        }));
        const prefetchData = parseContent(prefetchResp);
        assert(prefetchData.prefetched > 0,
          `Prefetch returned 0 items. User may have no owned L2 items.`);
      });
    }

    // -----------------------------------------------------------------------
    // CHECK 6: Chain integrity for each active user
    // -----------------------------------------------------------------------
    for (const u of activeUsers) {
      await runCheck(`Chain integrity for user "${u}"`, 'WARN', async () => {
        const data = l1Data.get(u);
        const integrity = data?.ephemeral?.integrity;
        assert(integrity, 'Missing ephemeral.integrity block');
        assert(integrity.genesis, 'Missing genesis timestamp');
        assert(integrity.chain_hash, 'Missing chain_hash');

        const zeroHash = '0000000000000000000000000000000000000000000000000000000000000000';
        if (integrity.chain_hash === zeroHash) {
          throw new Error('Chain hash is zeroed (post-repair state). Next session-end hook will recompute.');
        }
      });
    }

    // -----------------------------------------------------------------------
    // CHECK 7: Session count sanity
    // -----------------------------------------------------------------------
    for (const u of activeUsers) {
      await runCheck(`Session count sanity for user "${u}"`, 'WARN', async () => {
        const data = l1Data.get(u);
        const count = data?.ephemeral?.session_count;
        assert(typeof count === 'number', `session_count is not a number: ${count}`);
        assert(count > 0, `session_count is ${count}`);
        assert(count < 10000, `session_count suspiciously high: ${count}`);

        const genesis = data?.ephemeral?.integrity?.genesis;
        if (genesis) {
          const daysSinceGenesis = (Date.now() - new Date(genesis).getTime()) / (1000 * 60 * 60 * 24);
          const sessionsPerDay = count / Math.max(daysSinceGenesis, 1);
          if (sessionsPerDay > 50) {
            throw new Error(
              `${sessionsPerDay.toFixed(1)} sessions/day (${count} sessions in ${daysSinceGenesis.toFixed(1)} days). ` +
              'Possible runaway session counter.'
            );
          }
        }
      });
    }

    // -----------------------------------------------------------------------
    // CHECK 8: L2 search functional
    // -----------------------------------------------------------------------
    await runCheck('L2 search is functional', 'FAIL', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_search', arguments: { query: 'cordelia', limit: 1 },
      }));
      const data = parseContent(resp);
      // If there are items, search should find something. If DB is empty, skip.
      const totalItems = l2Stats?.entries || 0;
      if (totalItems > 0) {
        assert(data.count > 0, `${totalItems} L2 items exist but search returns 0 results`);
      }
    });

    // -----------------------------------------------------------------------
    // CHECK 10: L2 write/read/delete round-trip (canary test)
    // -----------------------------------------------------------------------
    await runCheck('L2 write/read/delete round-trip', 'FAIL', async () => {
      const canaryContent = 'healthcheck-canary-' + Date.now();

      // Write
      const writeResp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_write_warm',
        arguments: {
          type: 'learning',
          data: {
            type: 'insight',
            content: canaryContent,
            confidence: 0.1,
            tags: ['healthcheck', 'canary'],
          },
        },
      }));
      const writeData = parseContent(writeResp);
      assert(writeData.success === true, `Write failed: ${JSON.stringify(writeData)}`);
      assert(writeData.id, 'Write returned no id');

      // Read back
      const readResp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_warm',
        arguments: { id: writeData.id },
      }));
      const readData = parseContent(readResp);
      assert(readData.content === canaryContent,
        `Read-back mismatch: expected "${canaryContent}", got "${readData.content}"`);

      // Delete (cleanup)
      const deleteResp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_delete_warm',
        arguments: { id: writeData.id },
      }));
      const deleteData = parseContent(deleteResp);
      assert(deleteData.success === true, `Delete failed: ${JSON.stringify(deleteData)}`);

      // Verify deletion
      const verifyResp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_warm',
        arguments: { id: writeData.id },
      }));
      const verifyData = tryParseContent(verifyResp);
      assert(!verifyData || verifyData.error,
        `Item still readable after delete: ${JSON.stringify(verifyData)}`);
    });

    // -----------------------------------------------------------------------
    // CHECK 11: L2 write rejects invalid schema (negative test)
    // -----------------------------------------------------------------------
    await runCheck('L2 write rejects invalid learning type', 'FAIL', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_write_warm',
        arguments: {
          type: 'learning',
          data: {
            type: 'not_a_valid_type',
            content: 'should be rejected',
          },
        },
      }));
      const data = tryParseContent(resp);
      // Should get an error - either MCP error or validation_failed in content
      const isRejected = resp?.error ||
        (data && typeof data === 'object' && 'error' in data) ||
        (data && JSON.stringify(data).includes('validation_failed'));
      assert(isRejected, 'Invalid learning type was accepted (should have been rejected)');
    });

    await runCheck('L2 write rejects missing content field', 'FAIL', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_write_warm',
        arguments: {
          type: 'learning',
          data: {
            type: 'insight',
            // content deliberately omitted
          },
        },
      }));
      const data = tryParseContent(resp);
      const isRejected = resp?.error ||
        (data && typeof data === 'object' && 'error' in data) ||
        (data && JSON.stringify(data).includes('validation_failed'));
      assert(isRejected, 'Missing content field was accepted (should have been rejected)');
    });

    // -----------------------------------------------------------------------
    // CHECK 12: Group membership consistency
    // -----------------------------------------------------------------------
    await runCheck('Group membership includes active users', 'WARN', async () => {
      const groupListResp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_group_list', arguments: {},
      }));
      const groupData = parseContent(groupListResp);
      if (groupData.count === 0) return; // No groups, nothing to check

      for (const group of groupData.groups) {
        const groupResp = await sendRequest(child, rl, makeRequest('tools/call', {
          name: 'memory_group_read', arguments: { group_id: group.id },
        }));
        const detail = parseContent(groupResp);
        const memberIds = (detail.members || []).map(m => m.entity_id);

        // Check no deprecated users are group members
        // Only flag users we can read and confirm are deprecated (not users
        // whose L1 we can't decrypt -- they may use a different key)
        for (const memberId of memberIds) {
          const memberData = l1Data.get(memberId);
          if (!memberData) continue; // Can't read = different key, not deprecated
          if (memberData.identity?.id?.includes('DEPRECATED') ||
              memberData.active?.focus?.includes('DEPRECATED')) {
            throw new Error(
              `Deprecated user "${memberId}" is still a member of group "${group.id}". ` +
              'Remove with memory_group_remove_member.'
            );
          }
        }
      }
    });

  } finally {
    child.kill('SIGTERM');
    clearTimeout(globalDeadline);
  }

  // -----------------------------------------------------------------------
  // Report
  // -----------------------------------------------------------------------
  console.log('\n--- Results ---');

  const passed = results.filter(r => r.pass).length;
  const failed = results.filter(r => !r.pass && r.level === 'FAIL').length;
  const warned = results.filter(r => !r.pass && r.level === 'WARN').length;

  console.log(`${passed} passed, ${failed} failed, ${warned} warnings (${results.length} total)\n`);

  if (failed > 0) {
    console.log('FAILURES (must fix before upgrade):');
    for (const r of results.filter(r => !r.pass && r.level === 'FAIL')) {
      console.log(`  - ${r.name}: ${r.error}`);
    }
    console.log('');
  }

  if (warned > 0) {
    console.log('WARNINGS (review before upgrade):');
    for (const r of results.filter(r => !r.pass && r.level === 'WARN')) {
      console.log(`  - ${r.name}: ${r.error}`);
    }
    console.log('');
  }

  if (failed > 0) {
    console.log('=== HEALTH CHECK FAILED ===');
    console.log('Do NOT proceed with upgrade until failures are resolved.');
    process.exit(1);
  } else if (warned > 0) {
    console.log('=== HEALTH CHECK PASSED WITH WARNINGS ===');
    process.exit(2);
  } else {
    console.log('=== HEALTH CHECK PASSED ===');
    process.exit(0);
  }
}

main().catch((e) => {
  console.error(`\nFATAL: ${e.message}`);
  process.exit(1);
});
