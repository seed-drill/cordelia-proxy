/**
 * Project Cordelia - KeyVault Interface + R2 Stub
 *
 * Interface designed for R3 envelope encryption (Signal pattern).
 * R2 stub: shared key, no real envelope. key_version always 1.
 *
 * R3 target: per-group keys, member key escrow, rotation with re-encryption.
 */

export interface KeyVault {
  getGroupKey(groupId: string, version?: number): Promise<Buffer>;
  rotateGroupKey(groupId: string): Promise<{ newVersion: number }>;
  reencryptItems(groupId: string, fromVersion: number): Promise<{ count: number }>;
}

/**
 * R2 degenerate stub. Single shared key, no rotation, no re-encryption.
 * Satisfies the interface contract so R3 can swap in a real implementation.
 */
export class SharedKeyVault implements KeyVault {
  private readonly masterKey: Buffer;

  constructor(masterKey?: Buffer) {
    // Use provided key or a deterministic dummy for R2
    this.masterKey = masterKey || Buffer.alloc(32, 0x01);
  }

  async getGroupKey(_groupId: string, _version?: number): Promise<Buffer> {
    return this.masterKey;
  }

  async rotateGroupKey(_groupId: string): Promise<{ newVersion: number }> {
    // No-op in R2 -- single key, no rotation
    return { newVersion: 1 };
  }

  async reencryptItems(_groupId: string, _fromVersion: number): Promise<{ count: number }> {
    // No-op in R2 -- nothing to re-encrypt
    return { count: 0 };
  }
}

// Singleton
let activeVault: KeyVault | null = null;

export function getKeyVault(): KeyVault {
  if (!activeVault) {
    activeVault = new SharedKeyVault();
  }
  return activeVault;
}

export function setKeyVault(vault: KeyVault): void {
  activeVault = vault;
}
