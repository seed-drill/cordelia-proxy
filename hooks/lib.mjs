#!/usr/bin/env node
/**
 * Cordelia Hooks - Shared Library
 *
 * Common utilities for all Cordelia hooks: crypto, L1 read/write, chain hashing.
 * Extracted from session-start.mjs and session-end.mjs to eliminate duplication.
 */
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as os from 'os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- Constants ---

export const CORDELIA_DIR = path.resolve(__dirname, '..');
function getConfigPath() {
  return path.join(os.homedir(), '.cordelia', 'config.toml');
}
const KEY_LENGTH = 32;
const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// --- Encryption Key ---

/**
 * Get encryption key from environment, .mcp.json, or ~/.claude.json
 */
export async function getEncryptionKey() {
  if (process.env.CORDELIA_ENCRYPTION_KEY) {
    return process.env.CORDELIA_ENCRYPTION_KEY;
  }

  // Try project .mcp.json
  const projectMcpPath = path.join(CORDELIA_DIR, '..', 'seed-drill', '.mcp.json');
  try {
    const content = await fs.readFile(projectMcpPath, 'utf-8');
    const mcp = JSON.parse(content);
    const key = mcp.mcpServers?.cordelia?.env?.CORDELIA_ENCRYPTION_KEY;
    if (key) return key;
  } catch {
    // Fall through
  }

  // Fallback to global MCP config (~/.claude.json)
  const globalMcpPath = path.join(os.homedir(), '.claude.json');
  try {
    const content = await fs.readFile(globalMcpPath, 'utf-8');
    const mcp = JSON.parse(content);
    return mcp.mcpServers?.cordelia?.env?.CORDELIA_ENCRYPTION_KEY || null;
  } catch {
    return null;
  }
}

// --- Crypto Primitives ---

export async function deriveKey(passphrase, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(passphrase, salt, KEY_LENGTH, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export function isEncryptedPayload(obj) {
  return obj && obj._encrypted === true && obj.version === 1 &&
         typeof obj.iv === 'string' && typeof obj.authTag === 'string' &&
         typeof obj.ciphertext === 'string';
}

export async function decrypt(key, payload) {
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf-8'));
}

export async function encrypt(key, data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const plaintext = Buffer.from(JSON.stringify(data, null, 2), 'utf-8');

  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    _encrypted: true,
    version: 1,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    updated_at: new Date().toISOString(),
  };
}

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

// --- L1 Read/Write ---

/**
 * Load salt for key derivation.
 */
export async function loadSalt() {
  const memRoot = await getMemoryRoot();
  const saltPath = path.join(memRoot, 'L2-warm', '.salt', 'global.salt');
  return fs.readFile(saltPath);
}

/**
 * Read and decrypt L1 data. Returns { l1Data, recoveredFrom } or throws.
 * If decryption fails, attempts recovery via the provided recoveryFn.
 */
export async function readL1(userId, key, recoveryFn) {
  const l1Path = await getL1Path(userId);
  let content = await fs.readFile(l1Path, 'utf-8');
  let parsed = JSON.parse(content);

  if (isEncryptedPayload(parsed)) {
    try {
      return { l1Data: await decrypt(key, parsed), recoveredFrom: null };
    } catch (decryptError) {
      if (!recoveryFn) throw decryptError;

      const recovery = await recoveryFn(l1Path, decryptError);
      if (!recovery.recovered) {
        throw new Error(`Decryption and recovery failed: ${recovery.error}`);
      }

      // Re-read after recovery
      content = await fs.readFile(l1Path, 'utf-8');
      parsed = JSON.parse(content);
      return { l1Data: await decrypt(key, parsed), recoveredFrom: recovery.source };
    }
  }

  return { l1Data: parsed, recoveredFrom: null };
}

/**
 * Encrypt and write L1 data to disk.
 */
export async function writeL1(userId, l1Data, key) {
  const l1Path = await getL1Path(userId);
  const encrypted = await encrypt(key, l1Data);
  await fs.writeFile(l1Path, JSON.stringify(encrypted, null, 2));
}

/**
 * Get the file path for a user's L1 data.
 */
export async function getL1Path(userId) {
  const memRoot = await getMemoryRoot();
  return path.join(memRoot, 'L1-hot', `${userId}.json`);
}

/**
 * Initialize encryption: load salt and derive key from passphrase.
 */
export async function initCrypto(passphrase) {
  const salt = await loadSalt();
  const key = await deriveKey(passphrase, salt);
  return key;
}

// --- Config (config.toml) ---

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

    // Skip blank lines and comments
    if (!line || line.startsWith('#')) continue;

    // Section header
    const sectionMatch = line.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      if (!result[currentSection]) result[currentSection] = {};
      continue;
    }

    // Key = value
    const kvMatch = line.match(/^([^=]+?)\s*=\s*(.+)$/);
    if (kvMatch) {
      const key = kvMatch[1].trim();
      let value = kvMatch[2].trim();

      // Handle quoted strings (extract content between quotes, ignore inline comments)
      const dqMatch = value.match(/^"([^"]*)"/)
      const sqMatch = value.match(/^'([^']*)'/)
      if (dqMatch) {
        value = dqMatch[1];
      } else if (sqMatch) {
        value = sqMatch[1];
      } else {
        // Unquoted: strip inline comments
        const commentIdx = value.indexOf('#');
        if (commentIdx > 0) {
          value = value.slice(0, commentIdx).trim();
        }
      }

      if (currentSection) {
        result[currentSection][key] = value;
      } else {
        result[key] = value;
      }
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
