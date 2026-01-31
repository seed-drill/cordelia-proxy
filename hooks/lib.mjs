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
export const MEMORY_ROOT = path.join(CORDELIA_DIR, 'memory');
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
  const saltPath = path.join(MEMORY_ROOT, 'L2-warm', '.salt', 'global.salt');
  return fs.readFile(saltPath);
}

/**
 * Read and decrypt L1 data. Returns { l1Data, recoveredFrom } or throws.
 * If decryption fails, attempts recovery via the provided recoveryFn.
 */
export async function readL1(userId, key, recoveryFn) {
  const l1Path = getL1Path(userId);
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
  const l1Path = getL1Path(userId);
  const encrypted = await encrypt(key, l1Data);
  await fs.writeFile(l1Path, JSON.stringify(encrypted, null, 2));
}

/**
 * Get the file path for a user's L1 data.
 */
export function getL1Path(userId) {
  return path.join(MEMORY_ROOT, 'L1-hot', `${userId}.json`);
}

/**
 * Initialize encryption: load salt and derive key from passphrase.
 */
export async function initCrypto(passphrase) {
  const salt = await loadSalt();
  const key = await deriveKey(passphrase, salt);
  return key;
}
