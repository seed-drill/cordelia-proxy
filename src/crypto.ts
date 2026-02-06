/**
 * Project Cordelia - Encryption Module
 *
 * Provides at-rest encryption for L2 items using AES-256-GCM with
 * scrypt key derivation.
 *
 * Configuration via environment:
 *   CORDELIA_ENCRYPTION_KEY: Passphrase for encryption (required for encryption)
 *   CORDELIA_ENCRYPTION_ENABLED: Explicit enable/disable (default: true if key provided)
 *
 * Threat model:
 *   - Target: Curious/determined attackers (not state-level)
 *   - Protection: Data at rest on disk
 *   - Accept: Passphrase in memory during runtime
 */

import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'node:child_process';

// Key derivation parameters
const KEY_LENGTH = 32; // 256 bits for AES-256

// AES-256-GCM parameters
const AES_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits

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

export interface CryptoConfig {
  enabled: boolean;
  saltDir: string;
}

/**
 * Get configuration from environment.
 */
export function getConfig(memoryRoot: string): CryptoConfig {
  const hasKey = !!process.env.CORDELIA_ENCRYPTION_KEY;
  const explicitEnabled = process.env.CORDELIA_ENCRYPTION_ENABLED;

  return {
    enabled: explicitEnabled !== undefined ? explicitEnabled === 'true' : hasKey,
    saltDir: path.join(memoryRoot, 'L2-warm', '.salt'),
  };
}

/**
 * Key derivation using Node's built-in scrypt.
 *
 * scrypt parameters chosen for balance of security and performance:
 * - N=2^14 (16384) - memory/CPU cost (~16MB memory)
 * - r=8 - block size
 * - p=1 - parallelization
 *
 * This provides strong protection against brute-force while keeping
 * derivation time reasonable (~100ms on modern hardware).
 */
async function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      passphrase,
      salt,
      KEY_LENGTH,
      { N: 16384, r: 8, p: 1 },
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      }
    );
  });
}

/**
 * AES-256-GCM encryption provider with scrypt key derivation.
 */
export class Aes256GcmProvider implements CryptoProvider {
  name = 'aes-256-gcm';
  private key: Buffer | null = null;

  isUnlocked(): boolean {
    return this.key !== null;
  }

  async unlock(passphrase: string, salt: Buffer): Promise<void> {
    this.key = await deriveKey(passphrase, salt);
  }

  async encrypt(plaintext: Buffer): Promise<EncryptedPayload> {
    if (!this.key) {
      throw new Error('Crypto provider not unlocked');
    }

    // Generate random IV for each encryption
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(AES_ALGORITHM, this.key, iv, {
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

  async decrypt(payload: EncryptedPayload): Promise<Buffer> {
    if (!this.key) {
      throw new Error('Crypto provider not unlocked');
    }

    if (payload.version !== 1) {
      throw new Error(`Unsupported encryption version: ${payload.version}`);
    }

    const iv = Buffer.from(payload.iv, 'base64');
    const authTag = Buffer.from(payload.authTag, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext, 'base64');

    const decipher = crypto.createDecipheriv(AES_ALGORITHM, this.key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decrypted;
    } catch {
      // Authentication failed - tampered or wrong key
      throw new Error('Decryption failed: authentication tag mismatch');
    }
  }
}

/**
 * Null provider - encryption disabled.
 * Used when no encryption key is configured.
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
    throw new Error('Encryption not available: no encryption key configured');
  }

  async decrypt(_payload: EncryptedPayload): Promise<Buffer> {
    throw new Error('Decryption not available: no encryption key configured');
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

/**
 * Resolve encryption key using 3-tier priority chain:
 *   1. Env var       -- CORDELIA_ENCRYPTION_KEY
 *   2. Keychain      -- macOS Keychain / Linux secret-tool (GNOME Keyring)
 *   3. File          -- ~/.cordelia/key (0600 permissions)
 *
 * Returns key string or null. Never throws.
 */
export async function resolveEncryptionKey(): Promise<string | null> {
  // 1. Environment variable
  if (process.env.CORDELIA_ENCRYPTION_KEY) {
    return process.env.CORDELIA_ENCRYPTION_KEY;
  }

  // 2. Platform keychain
  const keychainCmds: Record<string, string> = {
    darwin: 'security find-generic-password -a cordelia -s cordelia-encryption-key -w',
    linux: 'secret-tool lookup service cordelia type encryption-key',
  };
  const cmd = keychainCmds[os.platform()];
  if (cmd) {
    try {
      const key = execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
      if (key) return key;
    } catch {
      // Keychain entry not found -- fall through
    }
  }

  // 3. File at ~/.cordelia/key
  try {
    const key = (await fs.readFile(path.join(os.homedir(), '.cordelia', 'key'), 'utf-8')).trim();
    if (key) return key;
  } catch {
    // File not found -- fall through
  }

  return null;
}

// Singleton instance
let defaultProvider: CryptoProvider | null = null;

/**
 * Get the default crypto provider.
 * Returns NullCryptoProvider if not initialized.
 */
export function getDefaultCryptoProvider(): CryptoProvider {
  if (!defaultProvider) {
    defaultProvider = new NullCryptoProvider();
  }
  return defaultProvider;
}

/**
 * Initialize the crypto provider with passphrase and salt.
 * Call this at server startup.
 */
export async function initCrypto(passphrase: string, salt: Buffer): Promise<CryptoProvider> {
  const provider = new Aes256GcmProvider();
  await provider.unlock(passphrase, salt);
  defaultProvider = provider;
  return provider;
}

/**
 * Reset to null provider (for testing).
 */
export function resetCryptoProvider(): void {
  defaultProvider = null;
}
