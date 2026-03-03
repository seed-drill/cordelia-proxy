/**
 * Project Cordelia - KeyVault Interface + GroupKeyVault
 *
 * Per-group PSK management. Each group has its own 32-byte AES-256 key
 * stored at ~/.cordelia/group-keys/{groupId}.key.
 *
 * GroupKeyVault delegates to group-keys.ts for filesystem I/O.
 * Rotation and re-encryption are stubs until E4 (key lifecycle sprint).
 */

import { getGroupKey } from './group-keys.js';

export interface KeyVault {
  getGroupKey(groupId: string, version?: number): Promise<Buffer>;
  rotateGroupKey(groupId: string): Promise<{ newVersion: number }>;
  reencryptItems(groupId: string, fromVersion: number): Promise<{ count: number }>;
}

/**
 * Real per-group key vault backed by filesystem PSKs.
 * Each group's key lives at ~/.cordelia/group-keys/{groupId}.key (32 raw bytes).
 */
export class GroupKeyVault implements KeyVault {
  async getGroupKey(groupId: string, _version?: number): Promise<Buffer> {
    const key = await getGroupKey(groupId);
    if (!key) {
      throw new Error(`No PSK available for group ${groupId}`);
    }
    return key;
  }

  async rotateGroupKey(_groupId: string): Promise<{ newVersion: number }> {
    // Stub until E4 -- single version per group for now
    return { newVersion: 1 };
  }

  async reencryptItems(_groupId: string, _fromVersion: number): Promise<{ count: number }> {
    // Stub until E4 -- nothing to re-encrypt yet
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
