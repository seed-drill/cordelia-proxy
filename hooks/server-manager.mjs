#!/usr/bin/env node
/**
 * Cordelia Server Manager - Ensure local HTTP server is running
 *
 * The HTTP server runs as a persistent sidecar across Claude Code sessions.
 * Hooks call ensureServer() which health-checks or spawns the sidecar.
 *
 * The local Cordelia node (managed by launchd) MUST be running. The proxy
 * always uses CORDELIA_STORAGE=node. There is no sqlite fallback -- all
 * writes flow through the P2P node for replication.
 *
 * PID file: ~/.cordelia/http-server.pid
 * Log file: ~/.cordelia/http-server.log
 */
import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

const CORDELIA_HOME = path.join(os.homedir(), '.cordelia');
const PID_FILE = path.join(CORDELIA_HOME, 'http-server.pid');
const LOG_FILE = path.join(CORDELIA_HOME, 'http-server.log');
const DEFAULT_PORT = 3847;
const HEALTH_TIMEOUT_MS = 3000;
const STARTUP_POLL_MS = 200;
const STARTUP_MAX_WAIT_MS = 5000;
const NODE_WAIT_MS = 10000;
const NODE_POLL_MS = 500;

/**
 * Get the base URL for the local HTTP server.
 */
export function getBaseUrl(port) {
  return `http://127.0.0.1:${port || DEFAULT_PORT}`;
}

/**
 * Check if the server is healthy.
 */
async function healthCheck(baseUrl) {
  try {
    const response = await fetch(`${baseUrl}/api/health`, {
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
    });
    if (!response.ok) return false;
    const data = await response.json();
    return data.ok === true;
  } catch {
    return false;
  }
}

/**
 * Read PID file and check if process is still alive.
 */
async function getRunningPid() {
  try {
    const pid = parseInt(await fs.readFile(PID_FILE, 'utf-8'), 10);
    if (isNaN(pid)) return null;
    // Check if process is alive (signal 0 = existence check)
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

/**
 * Read node URL from config.toml and token from node-token file.
 */
async function readNodeConfig() {
  const configPath = path.join(CORDELIA_HOME, 'config.toml');
  const configContent = await fs.readFile(configPath, 'utf-8');
  const addrMatch = configContent.match(/api_addr\s*=\s*"([^"]+)"/);
  const transportMatch = configContent.match(/api_transport\s*=\s*"([^"]+)"/);
  if (!addrMatch) {
    throw new Error('No api_addr in ~/.cordelia/config.toml');
  }

  const proto = transportMatch?.[1] === 'https' ? 'https' : 'http';
  const nodeUrl = `${proto}://${addrMatch[1]}`;

  const tokenPath = path.join(CORDELIA_HOME, 'node-token');
  const nodeToken = (await fs.readFile(tokenPath, 'utf-8')).trim();
  if (!nodeToken) {
    throw new Error('Empty ~/.cordelia/node-token');
  }

  return { nodeUrl, nodeToken };
}

/**
 * Wait for the local Cordelia node to respond. The node is managed by launchd
 * and auto-restarts, so a brief wait covers cold-boot and restart scenarios.
 */
async function waitForNode(nodeUrl, nodeToken) {
  const start = Date.now();
  while (Date.now() - start < NODE_WAIT_MS) {
    try {
      const resp = await fetch(`${nodeUrl}/api/v1/status`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${nodeToken}` },
        signal: AbortSignal.timeout(2000),
      });
      if (resp.ok) return true;
    } catch {
      // Node not ready yet
    }
    await new Promise(r => setTimeout(r, NODE_POLL_MS));
  }
  return false;
}

/**
 * Spawn the HTTP server as a detached background process.
 * Requires the local Cordelia node to be running.
 */
async function spawnServer(memoryRoot) {
  await fs.mkdir(CORDELIA_HOME, { recursive: true });

  // Find the http-server.js in the cordelia-proxy dist directory
  const serverScript = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    '..', 'dist', 'http-server.js'
  );

  // Read node config (fails if config.toml or node-token missing)
  const { nodeUrl, nodeToken } = await readNodeConfig();

  // Wait for the node to be reachable (launchd may still be starting it)
  const nodeReady = await waitForNode(nodeUrl, nodeToken);
  if (!nodeReady) {
    throw new Error(
      `Cordelia node not responding at ${nodeUrl} after ${NODE_WAIT_MS / 1000}s. ` +
      'Check: launchctl list | grep cordelia'
    );
  }

  const logFd = await fs.open(LOG_FILE, 'a');

  const env = {
    ...process.env,
    CORDELIA_HTTP_PORT: String(DEFAULT_PORT),
    CORDELIA_MEMORY_ROOT: memoryRoot,
    CORDELIA_STORAGE: 'node',
    CORDELIA_NODE_URL: nodeUrl,
    CORDELIA_CORE_API: nodeUrl,
    CORDELIA_NODE_TOKEN: nodeToken,
  };

  const logMsg = `[${new Date().toISOString()}] Starting proxy: storage=node (${nodeUrl})\n`;
  await fs.appendFile(LOG_FILE, logMsg);

  const child = spawn('node', [serverScript, '--local'], {
    detached: true,
    stdio: ['ignore', logFd.fd, logFd.fd],
    env,
  });

  // Write PID file
  await fs.writeFile(PID_FILE, String(child.pid));

  // Detach so parent can exit
  child.unref();
  await logFd.close();

  return child.pid;
}

/**
 * Ensure the local HTTP server is running. Returns { baseUrl, pid }.
 *
 * 1. Health check existing server
 * 2. If not healthy, check PID file for stale process
 * 3. If no server, spawn one and poll until healthy
 *
 * Precondition: local Cordelia node must be running (launchd service).
 */
export async function ensureServer(memoryRoot) {
  const port = DEFAULT_PORT;
  const baseUrl = getBaseUrl(port);

  // Fast path: server already running and healthy
  if (await healthCheck(baseUrl)) {
    const pid = await getRunningPid();
    return { baseUrl, pid, cold: false };
  }

  // Server not responding. Check for stale PID and clean up.
  const stalePid = await getRunningPid();
  if (stalePid) {
    try { process.kill(stalePid, 'SIGTERM'); } catch { /* already dead */ }
    try { await fs.unlink(PID_FILE); } catch { /* ignore */ }
  }

  // Spawn new server (requires node to be running)
  const pid = await spawnServer(memoryRoot);

  // Poll for readiness
  const start = Date.now();
  while (Date.now() - start < STARTUP_MAX_WAIT_MS) {
    if (await healthCheck(baseUrl)) {
      return { baseUrl, pid, cold: true };
    }
    await new Promise(r => setTimeout(r, STARTUP_POLL_MS));
  }

  throw new Error(`HTTP server failed to start within ${STARTUP_MAX_WAIT_MS}ms (pid: ${pid})`);
}
