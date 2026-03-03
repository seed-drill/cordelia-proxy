/**
 * Project Cordelia - Group Key Provider (E4b: Key Ring)
 *
 * Per-group pre-shared keys (PSKs) with multi-version key ring support.
 * AES-256-GCM encryption/decryption using raw 32-byte keys
 * (no scrypt derivation needed -- PSK is already high-entropy random).
 *
 * Storage format:
 * - Key ring: ~/.cordelia/group-keys/{group_id}.json
 *   { "versions": { "1": "<hex>" }, "latest": 1 }
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

const GROUP_KEYS_DIR = path.join(os.homedir(), '.cordelia', 'group-keys');

// AES-256-GCM parameters (same as crypto.ts)
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export interface KeyRing {
  versions: Record<string, string>; // version number -> hex-encoded 32-byte PSK
  latest: number;
}

// Cache loaded key rings in memory
const ringCache = new Map<string, KeyRing>();

/**
 * Load key ring from disk (JSON format only).
 */
async function loadKeyRing(groupId: string): Promise<KeyRing | null> {
  if (ringCache.has(groupId)) return ringCache.get(groupId)!;

  const jsonPath = path.join(GROUP_KEYS_DIR, `${groupId}.json`);

  try {
    const content = await fs.readFile(jsonPath, 'utf-8');
    const ring = JSON.parse(content) as KeyRing;
    ringCache.set(groupId, ring);
    return ring;
  } catch {
    return null; // No key for this group
  }
}

/**
 * Get a group PSK. Returns latest version by default, or specific version if provided.
 */
export async function getGroupKey(groupId: string, version?: number): Promise<Buffer | null> {
  const ring = await loadKeyRing(groupId);
  if (!ring) return null;

  const targetVersion = version ?? ring.latest;
  const hex = ring.versions[String(targetVersion)];
  if (!hex) return null;

  return Buffer.from(hex, 'hex');
}

/**
 * Get all versions in a key ring. Returns version numbers in descending order.
 */
export async function getGroupKeyVersions(groupId: string): Promise<number[]> {
  const ring = await loadKeyRing(groupId);
  if (!ring) return [];
  return Object.keys(ring.versions).map(Number).sort((a, b) => b - a);
}

/**
 * Get the latest version number for a group key ring.
 */
export async function getGroupKeyLatestVersion(groupId: string): Promise<number | null> {
  const ring = await loadKeyRing(groupId);
  return ring?.latest ?? null;
}

export async function groupEncrypt(
  plaintext: Buffer,
  key: Buffer,
): Promise<{ _encrypted: true; version: 1; iv: string; authTag: string; ciphertext: string }> {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
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
  };
}

export async function groupDecrypt(
  payload: { iv: string; authTag: string; ciphertext: string },
  key: Buffer,
): Promise<Buffer> {
  const iv = Buffer.from(payload.iv, 'base64');
  const authTag = Buffer.from(payload.authTag, 'base64');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Store a group PSK to disk (key ring format) and update cache.
 * Creates ~/.cordelia/group-keys/ directory if needed.
 * Adds as next version or overwrites existing version.
 */
export async function storeGroupKey(groupId: string, psk: Buffer, version?: number): Promise<void> {
  if (psk.length !== 32) {
    throw new Error(`PSK must be 32 bytes, got ${psk.length}`);
  }

  await fs.mkdir(GROUP_KEYS_DIR, { recursive: true });

  // Load existing ring or create new
  let ring = await loadKeyRing(groupId);
  if (!ring) {
    ring = { versions: {}, latest: 0 };
  }

  const targetVersion = version ?? ring.latest + 1;
  ring.versions[String(targetVersion)] = psk.toString('hex');
  if (targetVersion > ring.latest) {
    ring.latest = targetVersion;
  }

  // Write JSON key ring
  const jsonPath = path.join(GROUP_KEYS_DIR, `${groupId}.json`);
  await fs.writeFile(jsonPath, JSON.stringify(ring, null, 2), { mode: 0o600 });

  ringCache.set(groupId, ring);
}

/**
 * Clear the key cache (for testing).
 */
export function clearGroupKeyCache(): void {
  ringCache.clear();
}
