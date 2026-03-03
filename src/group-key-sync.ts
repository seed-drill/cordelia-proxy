/**
 * Project Cordelia - Group Key Sync (E3b)
 *
 * Periodically fetches envelope-encrypted group keys from the portal vault,
 * decrypts using local X25519 private key, and stores to disk.
 *
 * Sync flow:
 * 1. Read entity-id and portal-token from ~/.cordelia/
 * 2. GET /api/vault/group-keys/{entityId} from portal (bearer auth)
 * 3. For each group key not already stored locally:
 *    a. Decrypt envelope using local X25519 private key
 *    b. Store PSK to ~/.cordelia/group-keys/{groupId}.key
 * 4. Repeat on interval (default 5 minutes)
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { getLocalX25519Keypair, envelopeDecrypt } from './envelope.js';
import { storeGroupKey, getGroupKey } from './group-keys.js';
import type { EnvelopeCiphertext } from './envelope.js';

const CORDELIA_HOME = process.env.CORDELIA_HOME || path.join(os.homedir(), '.cordelia');
const SYNC_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

let syncTimer: ReturnType<typeof setInterval> | null = null;

interface VaultGroupKeyResponse {
  entity_id: string;
  group_keys: Array<{
    group_id: string;
    key_version: number;
    ephemeral_public_key: string;
    iv: string;
    auth_tag: string;
    encrypted_psk: string;
  }>;
}

/**
 * Read stored portal credentials from disk.
 */
async function readPortalCredentials(): Promise<{
  portalUrl: string;
  portalToken: string;
  entityId: string;
} | null> {
  try {
    const portalUrl = process.env.PORTAL_URL;
    if (!portalUrl) return null;

    const portalToken = (await fs.readFile(
      path.join(CORDELIA_HOME, 'portal-token'), 'utf-8',
    )).trim();

    const entityId = (await fs.readFile(
      path.join(CORDELIA_HOME, 'entity-id'), 'utf-8',
    )).trim();

    if (!portalToken || !entityId) return null;
    return { portalUrl, portalToken, entityId };
  } catch {
    return null;
  }
}

/**
 * Fetch all envelope-encrypted group keys from portal vault.
 */
async function fetchGroupKeysFromPortal(
  portalUrl: string,
  portalToken: string,
  entityId: string,
): Promise<VaultGroupKeyResponse | null> {
  try {
    const url = `${portalUrl}/api/vault/group-keys/${encodeURIComponent(entityId)}`;
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${portalToken}`,
        Accept: 'application/json',
      },
    });

    if (!resp.ok) {
      if (resp.status !== 401 && resp.status !== 403) {
        console.error(`Cordelia group-key-sync: portal returned ${resp.status}`);
      }
      return null;
    }

    return await resp.json() as VaultGroupKeyResponse;
  } catch (err) {
    console.error('Cordelia group-key-sync: fetch error:', (err as Error).message);
    return null;
  }
}

/**
 * Sync group keys from portal vault to local disk.
 * Decrypts envelope-encrypted PSKs using local X25519 private key.
 * Only stores keys that aren't already present locally.
 *
 * Returns { synced: number, skipped: number, errors: number }.
 */
export async function syncGroupKeysFromVault(): Promise<{
  synced: number;
  skipped: number;
  errors: number;
}> {
  const result = { synced: 0, skipped: 0, errors: 0 };

  const creds = await readPortalCredentials();
  if (!creds) {
    return result; // Not enrolled or no portal URL
  }

  const data = await fetchGroupKeysFromPortal(
    creds.portalUrl, creds.portalToken, creds.entityId,
  );
  if (!data || !data.group_keys.length) {
    return result;
  }

  let keypair: { publicKey: Buffer; privateKey: Buffer } | null = null;
  try {
    keypair = await getLocalX25519Keypair();
  } catch (err) {
    console.error('Cordelia group-key-sync: cannot load X25519 keypair:', (err as Error).message);
    return result;
  }

  for (const gk of data.group_keys) {
    // Skip if already stored locally
    const existing = await getGroupKey(gk.group_id);
    if (existing) {
      result.skipped++;
      continue;
    }

    try {
      const envelope: EnvelopeCiphertext = {
        ephemeralPublicKey: gk.ephemeral_public_key,
        iv: gk.iv,
        authTag: gk.auth_tag,
        ciphertext: gk.encrypted_psk,
      };

      const psk = envelopeDecrypt(envelope, keypair.privateKey);
      await storeGroupKey(gk.group_id, psk);
      result.synced++;
    } catch (err) {
      console.error(`Cordelia group-key-sync: failed to decrypt key for group ${gk.group_id}:`, (err as Error).message);
      result.errors++;
    }
  }

  // Zero private key after use
  keypair.privateKey.fill(0);

  if (result.synced > 0) {
    console.log(`Cordelia group-key-sync: synced ${result.synced} new group key(s)`);
  }

  return result;
}

/**
 * Start periodic group key sync.
 * First sync runs immediately, then repeats on interval.
 */
export function startGroupKeySync(): void {
  if (syncTimer) return; // Already running

  // Initial sync (fire-and-forget)
  syncGroupKeysFromVault().catch(err => {
    console.error('Cordelia group-key-sync: initial sync error:', (err as Error).message);
  });

  // Periodic sync
  syncTimer = setInterval(() => {
    syncGroupKeysFromVault().catch(err => {
      console.error('Cordelia group-key-sync: periodic sync error:', (err as Error).message);
    });
  }, SYNC_INTERVAL_MS);

  // Don't block process exit
  if (syncTimer.unref) syncTimer.unref();
}

/**
 * Stop periodic group key sync.
 */
export function stopGroupKeySync(): void {
  if (syncTimer) {
    clearInterval(syncTimer);
    syncTimer = null;
  }
}
