/**
 * Project Cordelia - Encryption Types & Utilities
 *
 * All at-rest encryption uses per-group PSKs via group-keys.ts
 * (AES-256-GCM with raw 32-byte keys).
 *
 * This module provides shared types (EncryptedPayload, CryptoProvider),
 * the payload detection helper, and the NullCryptoProvider.
 *
 * Legacy scrypt encryption removed in E5 migration.
 */

export interface EncryptedPayload {
  _encrypted: true;
  version: 1;
  iv: string; // Base64, 12 bytes
  authTag: string; // Base64, 16 bytes
  ciphertext: string; // Base64
}

export interface CryptoProvider {
  name: string;
  isUnlocked(): boolean;
  unlock(passphrase: string, salt: Buffer): Promise<void>;
  encrypt(plaintext: Buffer): Promise<EncryptedPayload>;
  decrypt(payload: EncryptedPayload): Promise<Buffer>;
}

/**
 * Null provider - no legacy scrypt encryption.
 * All encryption now uses per-group PSKs via group-keys.ts.
 */
export class NullCryptoProvider implements CryptoProvider {
  name = 'none';

  isUnlocked(): boolean {
    return true;
  }

  async unlock(_passphrase: string, _salt: Buffer): Promise<void> {
    // No-op
  }

  async encrypt(_plaintext: Buffer): Promise<EncryptedPayload> {
    throw new Error('Legacy scrypt encryption removed (E5). Use group PSKs via group-keys.ts');
  }

  async decrypt(_payload: EncryptedPayload): Promise<Buffer> {
    throw new Error('Legacy scrypt encryption removed (E5). Run migrate:v2 to convert v1 items');
  }
}

/**
 * Check if a parsed JSON object is an encrypted payload.
 */
export function isEncryptedPayload(obj: unknown): obj is EncryptedPayload {
  if (typeof obj !== 'object' || obj === null) {
    return false;
  }
  const p = obj as Record<string, unknown>;
  return p._encrypted === true && p.version === 1 && typeof p.iv === 'string' && typeof p.authTag === 'string' && typeof p.ciphertext === 'string';
}

// Singleton instance
let defaultProvider: CryptoProvider | null = null;

/**
 * Get the default crypto provider.
 * Always returns NullCryptoProvider (legacy scrypt removed in E5).
 */
export function getDefaultCryptoProvider(): CryptoProvider {
  if (!defaultProvider) {
    defaultProvider = new NullCryptoProvider();
  }
  return defaultProvider;
}

/**
 * Reset to null provider (for testing).
 */
export function resetCryptoProvider(): void {
  defaultProvider = null;
}
