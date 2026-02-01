/**
 * Project Cordelia - Group Key Provider
 *
 * Reads per-group pre-shared keys (PSKs) from filesystem.
 * AES-256-GCM encryption/decryption using raw 32-byte keys
 * (no scrypt derivation needed -- PSK is already high-entropy random).
 *
 * Key files: ~/.cordelia/group-keys/{group_id}.key (raw 32 bytes)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

const GROUP_KEYS_DIR = path.join(os.homedir(), '.cordelia', 'group-keys');

// AES-256-GCM parameters (same as crypto.ts)
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// Cache loaded keys in memory
const keyCache = new Map<string, Buffer>();

export async function getGroupKey(groupId: string): Promise<Buffer | null> {
  if (keyCache.has(groupId)) return keyCache.get(groupId)!;

  const keyPath = path.join(GROUP_KEYS_DIR, `${groupId}.key`);
  try {
    const raw = await fs.readFile(keyPath);
    if (raw.length !== 32) {
      console.error(`Cordelia: group key for ${groupId} is ${raw.length} bytes, expected 32`);
      return null;
    }
    keyCache.set(groupId, raw);
    return raw;
  } catch {
    return null; // No key for this group
  }
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
 * Clear the key cache (for testing).
 */
export function clearGroupKeyCache(): void {
  keyCache.clear();
}
