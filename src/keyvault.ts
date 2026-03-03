/**
 * Project Cordelia - KeyVault Interface + GroupKeyVault
 *
 * Per-group PSK management. Each group has its own 32-byte AES-256 key
 * stored at ~/.cordelia/group-keys/{groupId}.json (key ring format).
 *
 * GroupKeyVault delegates to group-keys.ts for filesystem I/O and
 * calls the portal rotation endpoint for key lifecycle operations.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { getGroupKey, clearGroupKeyCache } from './group-keys.js';
import { syncGroupKeysFromVault } from './group-key-sync.js';

const CORDELIA_HOME = process.env.CORDELIA_HOME || path.join(os.homedir(), '.cordelia');

export interface KeyVault {
  getGroupKey(groupId: string, version?: number): Promise<Buffer>;
  rotateGroupKey(groupId: string, passphrase: string): Promise<{ newVersion: number; membersDistributed: number }>;
  reencryptItems(groupId: string, fromVersion: number): Promise<{ count: number }>;
}

/**
 * Read portal credentials from disk (same path as group-key-sync.ts).
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
 * Real per-group key vault backed by filesystem PSKs.
 * Rotation delegates to the portal's rotate-group-key endpoint.
 */
export class GroupKeyVault implements KeyVault {
  async getGroupKey(groupId: string, version?: number): Promise<Buffer> {
    const key = await getGroupKey(groupId, version);
    if (!key) {
      throw new Error(`No PSK available for group ${groupId}`);
    }
    return key;
  }

  async rotateGroupKey(groupId: string, passphrase: string): Promise<{ newVersion: number; membersDistributed: number }> {
    const creds = await readPortalCredentials();
    if (!creds) {
      throw new Error('Cannot rotate: no portal credentials (PORTAL_URL not set or portal-token missing)');
    }

    const resp = await fetch(
      `${creds.portalUrl}/api/vault/rotate-group-key/${encodeURIComponent(groupId)}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${creds.portalToken}`,
        },
        body: JSON.stringify({ passphrase }),
      },
    );

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({})) as Record<string, unknown>;
      throw new Error(`Rotation failed (HTTP ${resp.status}): ${body.error || 'unknown error'}`);
    }

    const result = await resp.json() as { new_key_version: number; members_distributed: number };

    // Sync new key version from vault to local disk
    clearGroupKeyCache();
    await syncGroupKeysFromVault();

    return { newVersion: result.new_key_version, membersDistributed: result.members_distributed };
  }

  async reencryptItems(_groupId: string, _fromVersion: number): Promise<{ count: number }> {
    // Deferred: re-encryption on rotation is a future "nuclear departure policy" (spec Section 11)
    return { count: 0 };
  }
}

// Singleton
let activeVault: KeyVault | null = null;

export function getKeyVault(): KeyVault {
  if (!activeVault) {
    activeVault = new GroupKeyVault();
  }
  return activeVault;
}

export function setKeyVault(vault: KeyVault): void {
  activeVault = vault;
}
