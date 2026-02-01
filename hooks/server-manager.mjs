#!/usr/bin/env node
/**
 * Cordelia Server Manager - Ensure local HTTP server is running
 *
 * The HTTP server runs as a persistent sidecar across Claude Code sessions.
 * Hooks call ensureServer() which health-checks or spawns the sidecar.
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
 * Spawn the HTTP server as a detached background process.
 */
async function spawnServer(passphrase, memoryRoot) {
  await fs.mkdir(CORDELIA_HOME, { recursive: true });

  // Find the http-server.js in the cordelia-proxy dist directory
  const serverScript = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    '..', 'dist', 'http-server.js'
  );

  const logFd = await fs.open(LOG_FILE, 'a');

  const env = {
    ...process.env,
    CORDELIA_HTTP_PORT: String(DEFAULT_PORT),
    CORDELIA_MEMORY_ROOT: memoryRoot,
  };
  if (passphrase) {
    env.CORDELIA_ENCRYPTION_KEY = passphrase;
  }

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
 */
export async function ensureServer(passphrase, memoryRoot) {
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

  // Spawn new server
  const pid = await spawnServer(passphrase, memoryRoot);

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
