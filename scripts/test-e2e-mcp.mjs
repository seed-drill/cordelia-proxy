#!/usr/bin/env node
/**
 * Cordelia MCP E2E Test Suite
 *
 * Spawns the MCP server via stdio, runs JSON-RPC 2.0 tool calls,
 * validates a full memory round-trip (L1 + L2).
 *
 * Zero dependencies -- plain Node.js ESM.
 *
 * Exit 0 = all pass, Exit 1 = any fail.
 */

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 10_000;
const GLOBAL_TIMEOUT_MS = 60_000;

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

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

function extractEncryptionKey() {
  // install.sh writes the key into ~/.claude.json under mcpServers.cordelia.env
  const claudeJson = resolve(process.env.HOME, '.claude.json');
  try {
    const config = JSON.parse(readFileSync(claudeJson, 'utf-8'));
    const key = config?.mcpServers?.cordelia?.env?.CORDELIA_ENCRYPTION_KEY;
    if (key) return key;
  } catch {
    // fall through
  }
  // Fallback: env var already set (e.g. in CI)
  if (process.env.CORDELIA_ENCRYPTION_KEY) return process.env.CORDELIA_ENCRYPTION_KEY;
  throw new Error('Cannot find CORDELIA_ENCRYPTION_KEY in ~/.claude.json or environment');
}

function spawnServer(encryptionKey) {
  const serverPath = resolve(PROJECT_ROOT, 'dist', 'server.js');
  const memoryRoot = resolve(PROJECT_ROOT, 'memory');

  const child = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CORDELIA_ENCRYPTION_KEY: encryptionKey,
      CORDELIA_MEMORY_ROOT: memoryRoot,
      CORDELIA_EMBEDDING_PROVIDER: 'none',
      CORDELIA_INTEGRITY_INTERVAL_MS: '0',
      CORDELIA_TTL_SWEEP_INTERVAL_MS: '0',
    },
  });

  const rl = createInterface({ input: child.stdout });

  // Collect stderr for startup detection
  let stderrBuf = '';
  child.stderr.on('data', (chunk) => {
    stderrBuf += chunk.toString();
    // Mirror to our stderr for debug visibility
    process.stderr.write(chunk);
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

// ---------------------------------------------------------------------------
// JSON-RPC transport
// ---------------------------------------------------------------------------

function sendRequest(child, rl, request, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`Timeout waiting for response to ${request.method} (id=${request.id})`)), timeoutMs);

    const handler = (line) => {
      try {
        const msg = JSON.parse(line);
        if (msg.id === request.id) {
          rl.removeListener('line', handler);
          clearTimeout(deadline);
          resolve(msg);
        }
      } catch {
        // ignore non-JSON lines
      }
    };

    rl.on('line', handler);
    child.stdin.write(JSON.stringify(request) + '\n');
  });
}

function sendNotification(child, notification) {
  child.stdin.write(JSON.stringify(notification) + '\n');
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const results = [];

function assert(condition, message) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

async function runTest(name, fn) {
  try {
    await fn();
    results.push({ name, pass: true });
    console.log(`  PASS  ${name}`);
  } catch (e) {
    results.push({ name, pass: false, error: e.message });
    console.log(`  FAIL  ${name}: ${e.message}`);
  }
}

function parseContent(response) {
  // MCP tool call responses come as { result: { content: [{ type, text }] } }
  const text = response?.result?.content?.[0]?.text;
  if (!text) throw new Error(`No content in response: ${JSON.stringify(response)}`);
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const globalDeadline = setTimeout(() => {
    console.log('\nFATAL: Global timeout exceeded');
    process.exit(1);
  }, GLOBAL_TIMEOUT_MS);

  console.log('\n=== Cordelia MCP E2E Test Suite ===\n');

  // 1. Start server
  const encryptionKey = extractEncryptionKey();
  const { child, rl, stderrBuf } = spawnServer(encryptionKey);

  try {
    await waitForStartup(stderrBuf);
    console.log('Server started.\n');

    // 2. MCP handshake
    const initResp = await sendRequest(child, rl, makeRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'cordelia-e2e-test', version: '1.0.0' },
    }));
    assert(initResp.result, 'initialize should return result');
    assert(initResp.result.serverInfo?.name === 'cordelia', `serverInfo.name should be "cordelia", got "${initResp.result.serverInfo?.name}"`);
    console.log('Handshake complete.\n');

    sendNotification(child, makeNotification('notifications/initialized'));

    // Small delay to let server process the notification
    await new Promise((r) => setTimeout(r, 200));

    // 3. Run tests
    // -----------------------------------------------------------------------

    // Test 1: memory_status
    await runTest('memory_status returns ok with testuser', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_status',
        arguments: {},
      }));
      const data = parseContent(resp);
      assert(data.status === 'ok', `status should be "ok", got "${data.status}"`);
      assert(data.layers?.L1_hot?.users?.includes('testuser'), `testuser not in users: ${JSON.stringify(data.layers?.L1_hot?.users)}`);
    });

    // Test 2: memory_read_hot
    await runTest('memory_read_hot returns L1 context', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_hot',
        arguments: { user_id: 'testuser' },
      }));
      const data = parseContent(resp);
      assert(data.identity, 'L1 context should have identity block');
      assert(data.identity.id === 'testuser', `identity.id should be "testuser", got "${data.identity.id}"`);
    });

    // Test 3: memory_write_hot (patch)
    await runTest('memory_write_hot patches active.focus', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_write_hot',
        arguments: {
          user_id: 'testuser',
          operation: 'patch',
          data: { active: { focus: 'E2E MCP test in progress' } },
        },
      }));
      const data = parseContent(resp);
      assert(data.success === true, `write should succeed, got: ${JSON.stringify(data)}`);
      assert(data.updated_at, 'write should return updated_at');
    });

    // Test 4: memory_read_hot (verify patch)
    await runTest('memory_read_hot reflects patched focus', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_hot',
        arguments: { user_id: 'testuser' },
      }));
      const data = parseContent(resp);
      assert(data.active?.focus === 'E2E MCP test in progress', `focus should be patched, got "${data.active?.focus}"`);
    });

    // Test 5: memory_write_warm (create L2 entity)
    let warmItemId;
    await runTest('memory_write_warm creates L2 concept entity', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_write_warm',
        arguments: {
          type: 'entity',
          data: {
            type: 'concept',
            name: 'E2E Test Concept',
            summary: 'Entity created by MCP E2E test suite for round-trip validation.',
            tags: ['e2e', 'test'],
          },
        },
      }));
      const data = parseContent(resp);
      assert(data.id, `write_warm should return id, got: ${JSON.stringify(data)}`);
      warmItemId = data.id;
    });

    // Test 6: memory_search
    await runTest('memory_search finds E2E entity', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_search',
        arguments: { query: 'E2E Test' },
      }));
      const data = parseContent(resp);
      assert(data.count > 0, `search should find at least 1 result, got ${data.count}`);
      const match = data.results.find((r) => r.id === warmItemId);
      assert(match, `search results should include item ${warmItemId}`);
    });

    // Test 7: memory_read_warm
    await runTest('memory_read_warm returns entity with correct fields', async () => {
      const resp = await sendRequest(child, rl, makeRequest('tools/call', {
        name: 'memory_read_warm',
        arguments: { id: warmItemId },
      }));
      const data = parseContent(resp);
      assert(data.name === 'E2E Test Concept', `name should be "E2E Test Concept", got "${data.name}"`);
      assert(data.type === 'concept', `type should be "concept", got "${data.type}"`);
      assert(data.tags?.includes('e2e'), `tags should include "e2e", got ${JSON.stringify(data.tags)}`);
    });

  } finally {
    child.kill('SIGTERM');
    clearTimeout(globalDeadline);
  }

  // 4. Report
  console.log('\n--- Results ---');
  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  console.log(`${passed}/${results.length} passed, ${failed} failed\n`);

  if (failed > 0) {
    console.log('Failed tests:');
    for (const r of results.filter((r) => !r.pass)) {
      console.log(`  - ${r.name}: ${r.error}`);
    }
    console.log('');
  }

  console.log(failed === 0 ? '=== ALL MCP E2E TESTS PASSED ===' : '=== MCP E2E TESTS FAILED ===');
  process.exit(failed > 0 ? 1 : 0);
}

try {
  await main();
} catch (e) {
  console.error(`\nFATAL: ${e.message}`);
  process.exit(1);
}
