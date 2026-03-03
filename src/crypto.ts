/**
 * Project Cordelia - Encryption Types & Utilities
 *
 * After E5 migration, all at-rest encryption uses per-group PSKs
 * via group-keys.ts (AES-256-GCM with raw 32-byte keys).
 *
 * This module retains shared types (EncryptedPayload, CryptoProvider),
 * the payload detection helper, and legacy scrypt functions needed
 * only by migration scripts (migrate-v1-to-v2.ts, migrate.ts).
 */

import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'node:child_process';

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
    return true; // Always "unlocked" since no encryption
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
 * Load or create salt for a user.
 */
export async function loadOrCreateSalt(saltDir: string, userId: string): Promise<Buffer> {
  const saltPath = path.join(saltDir, `${userId}.salt`);

  try {
    const salt = await fs.readFile(saltPath);
    return salt;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // Generate new salt
      const salt = crypto.randomBytes(32);
      await fs.mkdir(saltDir, { recursive: true });
      await fs.writeFile(saltPath, salt);
      return salt;
    }
    throw error;
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

// =============================================================================
// Legacy scrypt functions -- MIGRATION ONLY
// Used by migrate-v1-to-v2.ts and migrate.ts to decrypt v1 items.
// Not used by any runtime code path (server, l2, mcp-tools).
// =============================================================================

const KEY_LENGTH = 32;
const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export interface CryptoConfig {
  enabled: boolean;
  saltDir: string;
}

/** @deprecated Migration only. */
export function getConfig(memoryRoot: string): CryptoConfig {
  const hasKey = !!process.env.CORDELIA_ENCRYPTION_KEY;
  const explicitEnabled = process.env.CORDELIA_ENCRYPTION_ENABLED;
  return {
    enabled: explicitEnabled !== undefined ? explicitEnabled === 'true' : hasKey,
    saltDir: path.join(memoryRoot, 'L2-warm', '.salt'),
  };
}

async function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(passphrase, salt, KEY_LENGTH, { N: 16384, r: 8, p: 1 }, (err, dk) => {
      if (err) reject(err); else resolve(dk);
    });
  });
}

/** @deprecated Migration only. */
export class Aes256GcmProvider implements CryptoProvider {
  name = 'aes-256-gcm';
  private key: Buffer | null = null;

  isUnlocked(): boolean { return this.key !== null; }

  async unlock(passphrase: string, salt: Buffer): Promise<void> {
    this.key = await deriveKey(passphrase, salt);
  }

  async encrypt(plaintext: Buffer): Promise<EncryptedPayload> {
    if (!this.key) throw new Error('Crypto provider not unlocked');
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, this.key, iv, { authTagLength: AUTH_TAG_LENGTH });
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      _encrypted: true, version: 1,
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: encrypted.toString('base64'),
    };
  }

  async decrypt(payload: EncryptedPayload): Promise<Buffer> {
    if (!this.key) throw new Error('Crypto provider not unlocked');
    if (payload.version !== 1) throw new Error(`Unsupported encryption version: ${payload.version}`);
    const iv = Buffer.from(payload.iv, 'base64');
    const authTag = Buffer.from(payload.authTag, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext, 'base64');
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, this.key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);
    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new Error('Decryption failed: authentication tag mismatch');
    }
  }
}

/** @deprecated Migration only. */
export async function resolveEncryptionKey(): Promise<string | null> {
  if (process.env.CORDELIA_ENCRYPTION_KEY) return process.env.CORDELIA_ENCRYPTION_KEY;
  const keychainCmds: Record<string, string> = {
    darwin: 'security find-generic-password -a cordelia -s cordelia-encryption-key -w',
    linux: 'secret-tool lookup service cordelia type encryption-key',
  };
  const cmd = keychainCmds[os.platform()];
  if (cmd) {
    try {
      const key = execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
      if (key) return key;
    } catch { /* not found */ }
  }
  try {
    const key = (await fs.readFile(path.join(os.homedir(), '.cordelia', 'key'), 'utf-8')).trim();
    if (key) return key;
  } catch { /* not found */ }
  return null;
}

/** @deprecated Migration only. */
export async function initCrypto(passphrase: string, salt: Buffer): Promise<CryptoProvider> {
  const provider = new Aes256GcmProvider();
  await provider.unlock(passphrase, salt);
  defaultProvider = provider;
  return provider;
}
