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

/**
 * Credentials bundle format (downloaded from portal agent account).
 */
export interface CredentialsBundle {
  entity_id: string;
  bearer_token: string;
  node_url?: string;
  groups: Array<{
    group_id: string;
    name?: string;
    psk: string; // hex-encoded 32-byte PSK
  }>;
}

/**
 * Load a credentials bundle from file or env var.
 * Writes PSKs to ~/.cordelia/group-keys/ directory.
 * Also sets CORDELIA_NODE_TOKEN if bearer_token is present and env is unset.
 *
 * Sources checked in order:
 * 1. CORDELIA_CREDENTIALS_FILE env var (path to JSON file)
 * 2. CORDELIA_CREDENTIALS env var (inline JSON)
 *
 * Returns the parsed bundle, or null if no credentials source found.
 */
export async function loadCredentialsBundle(): Promise<CredentialsBundle | null> {
  let raw: string | undefined;

  const credFile = process.env.CORDELIA_CREDENTIALS_FILE;
  if (credFile) {
    try {
      raw = await fs.readFile(credFile, 'utf-8');
    } catch (err) {
      console.error(`Cordelia: failed to read credentials file ${credFile}: ${(err as Error).message}`);
      return null;
    }
  }

  if (!raw) {
    raw = process.env.CORDELIA_CREDENTIALS;
  }

  if (!raw) return null;

  let bundle: CredentialsBundle;
  try {
    bundle = JSON.parse(raw) as CredentialsBundle;
  } catch (err) {
    console.error(`Cordelia: failed to parse credentials bundle: ${(err as Error).message}`);
    return null;
  }

  if (!bundle.entity_id || !bundle.groups || !Array.isArray(bundle.groups)) {
    console.error('Cordelia: invalid credentials bundle (missing entity_id or groups)');
    return null;
  }

  // Write PSKs to group-keys directory
  let loaded = 0;
  for (const group of bundle.groups) {
    if (!group.group_id || !group.psk) continue;
    const psk = Buffer.from(group.psk, 'hex');
    if (psk.length !== 32) {
      console.error(`Cordelia: skipping group ${group.group_id} -- PSK must be 32 bytes, got ${psk.length}`);
      continue;
    }
    await storeGroupKey(group.group_id, psk, 1);
    loaded++;
  }

  // Set node token from bundle if not already set
  if (bundle.bearer_token && !process.env.CORDELIA_NODE_TOKEN) {
    process.env.CORDELIA_NODE_TOKEN = bundle.bearer_token;
  }

  // Set API key for proxy bearer auth if not already set
  if (bundle.bearer_token && !process.env.CORDELIA_API_KEY) {
    process.env.CORDELIA_API_KEY = bundle.bearer_token;
  }

  console.error(`Cordelia: loaded ${loaded} group key(s) from credentials bundle for ${bundle.entity_id}`);
  return bundle;
}

/**
 * Encrypt L1 hot context using the personal group PSK.
 * Returns the encrypted payload as a JSON object, or null if no PSK is available
 * (in which case the caller should store plaintext -- graceful degradation).
 */
export async function encryptL1(plaintext: Record<string, unknown>): Promise<Record<string, unknown> | null> {
  const { getPersonalGroup } = await import('./storage.js');
  const personalGroupId = await getPersonalGroup();
  if (!personalGroupId) {
    console.error('Cordelia: no personal group configured, storing L1 unencrypted');
    return null;
  }

  const key = await getGroupKey(personalGroupId);
  if (!key) {
    console.error(`Cordelia: no PSK for personal group ${personalGroupId}, storing L1 unencrypted`);
    return null;
  }

  const buf = Buffer.from(JSON.stringify(plaintext), 'utf-8');
  return await groupEncrypt(buf, key);
}

/**
 * Decrypt L1 hot context if it is an encrypted payload.
 * Returns plaintext JSON object. If the input is not encrypted, returns it as-is
 * (transparent migration: old plaintext data still works).
 */
export async function decryptL1(data: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (data._encrypted !== true || typeof data.iv !== 'string' || typeof data.ciphertext !== 'string') {
    return data; // Not encrypted -- return as-is (migration compat)
  }

  const { getPersonalGroup } = await import('./storage.js');
  const personalGroupId = await getPersonalGroup();
  if (!personalGroupId) {
    throw new Error('Cannot decrypt L1: no personal group configured');
  }

  // Use key ring version from payload (same as L2 decryptPayload) to support key rotation
  const ringVersion = typeof data.version === 'number' ? data.version : undefined;
  const key = await getGroupKey(personalGroupId, ringVersion);
  if (!key) {
    throw new Error(`Cannot decrypt L1: no PSK for personal group ${personalGroupId}`);
  }

  const decrypted = await groupDecrypt(data as { iv: string; authTag: string; ciphertext: string }, key);
  return JSON.parse(decrypted.toString('utf-8'));
}
