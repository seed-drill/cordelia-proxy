#!/usr/bin/env node
/**
 * Cordelia Hooks - Shared Library
 *
 * Common utilities for all Cordelia hooks.
 * L1 read/write is via REST API (GET/PUT /api/hot/:userId).
 * Encryption is handled transparently by the storage provider.
 * This module retains: config, user ID, memory root, chain hashing.
 */
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as os from 'os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- Constants ---

export const CORDELIA_DIR = path.resolve(__dirname, '..');

// --- Content & Chain Hashing ---

/**
 * Compute content hash of L1 data (excluding integrity block).
 */
export function computeContentHash(l1Data) {
  const dataWithoutIntegrity = { ...l1Data };
  if (dataWithoutIntegrity.ephemeral) {
    dataWithoutIntegrity.ephemeral = { ...dataWithoutIntegrity.ephemeral };
    delete dataWithoutIntegrity.ephemeral.integrity;
  }
  const content = JSON.stringify(dataWithoutIntegrity);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Compute chain hash: SHA256(previous_hash + session_count + content_hash)
 */
export function computeChainHash(previousHash, sessionCount, contentHash) {
  const input = `${previousHash}${sessionCount}${contentHash}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}

// --- Config (config.toml) ---

function getConfigPath() {
  return path.join(os.homedir(), '.cordelia', 'config.toml');
}

/**
 * Extract the value from a raw TOML value string, handling quotes and inline comments.
 */
function extractTOMLValue(raw) {
  const dqMatch = raw.match(/^"([^"]*)"/);
  if (dqMatch) return dqMatch[1];

  const sqMatch = raw.match(/^'([^']*)'/);
  if (sqMatch) return sqMatch[1];

  const commentIdx = raw.indexOf('#');
  if (commentIdx > 0) return raw.slice(0, commentIdx).trim();

  return raw;
}

/**
 * Assign a key-value pair into the result, respecting current section scope.
 */
function assignTOMLEntry(result, currentSection, key, value) {
  if (currentSection) {
    result[currentSection][key] = value;
  } else {
    result[key] = value;
  }
}

/**
 * Minimal TOML parser for flat key-value pairs with [section] headers.
 * Handles: strings (quoted and unquoted), sections, comments, blank lines.
 * Does NOT handle: arrays, inline tables, multiline strings, nested tables.
 */
export function parseTOML(text) {
  const result = {};
  let currentSection = null;

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();

    if (!line || line.startsWith('#')) continue;

    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      if (!result[currentSection]) result[currentSection] = {};
      continue;
    }

    const kvMatch = line.match(/^([^=]+?)\s*=\s*(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      const value = extractTOMLValue(kvMatch[2].trim());
      assignTOMLEntry(result, currentSection, key, value);
    }
  }

  return result;
}

/**
 * Load config from ~/.cordelia/config.toml.
 * Returns parsed config object or null if file doesn't exist.
 */
let _configCache = null;
export async function loadConfig() {
  if (_configCache !== undefined && _configCache !== null) return _configCache;

  try {
    const content = await fs.readFile(getConfigPath(), 'utf-8');
    _configCache = parseTOML(content);
    return _configCache;
  } catch (err) {
    if (err.code === 'ENOENT') {
      _configCache = null;
      return null;
    }
    throw err;
  }
}

/**
 * Clear cached config (for testing).
 */
export function clearConfigCache() {
  _configCache = null;
}

/**
 * Get user_id from (in order): CLI arg, config.toml, or throw.
 * No silent fallback.
 */
export async function getUserId() {
  // 1. CLI arg (highest priority)
  if (process.argv[2]) return process.argv[2];

  // 2. config.toml
  const config = await loadConfig();
  if (config?.identity?.user_id) return config.identity.user_id;

  // 3. Fail with clear error
  throw new Error(
    'No user_id configured. Either:\n' +
    '  1. Pass user_id as CLI argument: ./session-start.mjs <user_id>\n' +
    '  2. Set identity.user_id in ~/.cordelia/config.toml\n' +
    '  3. Run install.sh to generate config'
  );
}

/**
 * Get memory root from (in order): env var, config.toml, or throw.
 * No silent fallback.
 */
export async function getMemoryRoot() {
  // 1. Environment variable (highest priority)
  if (process.env.CORDELIA_MEMORY_ROOT) return process.env.CORDELIA_MEMORY_ROOT;

  // 2. config.toml
  const config = await loadConfig();
  if (config?.paths?.memory_root) {
    // Expand ~ to homedir
    const raw = config.paths.memory_root;
    return raw.startsWith('~') ? path.join(os.homedir(), raw.slice(1)) : raw;
  }

  // 3. Fail with clear error
  throw new Error(
    'No memory root configured. Either:\n' +
    '  1. Set CORDELIA_MEMORY_ROOT environment variable\n' +
    '  2. Set paths.memory_root in ~/.cordelia/config.toml\n' +
    '  3. Run install.sh to generate config'
  );
}
