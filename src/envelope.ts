/**
 * Project Cordelia - ECIES Envelope Encryption (E1b)
 *
 * X25519 ECDH + HKDF-SHA256 + AES-256-GCM envelope for group PSK distribution.
 * Cross-implementation compatible with cordelia-core (Rust).
 */

import { sha512 } from '@noble/hashes/sha2.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

const HKDF_INFO = new TextEncoder().encode('cordelia-key-wrap-v1');
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export interface EnvelopeCiphertext {
  ephemeralPublicKey: string; // base64, 32 bytes
  iv: string; // base64, 12 bytes
  authTag: string; // base64, 16 bytes
  ciphertext: string; // base64
}

/**
 * Extract the 32-byte Ed25519 seed from a ring-generated PKCS#8 DER file.
 * Scans for the pattern 04 20 (OCTET STRING, length 32).
 */
export function extractEd25519Seed(pkcs8Der: Buffer): Buffer {
  for (let i = 0; i < pkcs8Der.length - 33; i++) {
    if (pkcs8Der[i] === 0x04 && pkcs8Der[i + 1] === 0x20) {
      return pkcs8Der.subarray(i + 2, i + 34);
    }
  }
  throw new Error('Could not extract Ed25519 seed from PKCS#8 DER');
}

/**
 * Derive X25519 keypair from an Ed25519 seed.
 * Algorithm: SHA-512(seed) -> first 32 bytes -> RFC 7748 clamping -> scalarMultBase.
 */
export function deriveX25519FromEd25519(seed: Buffer): {
  publicKey: Buffer;
  privateKey: Buffer;
} {
  const hash = sha512(seed);
  const scalar = new Uint8Array(hash.slice(0, 32));

  // RFC 7748 clamping
  scalar[0] &= 0xf8;
  scalar[31] &= 0x7f;
  scalar[31] |= 0x40;

  const privateKey = Buffer.from(scalar);
  const publicKey = Buffer.from(x25519.scalarMultBase(scalar));

  // Zero the intermediate
  scalar.fill(0);

  return { publicKey, privateKey };
}

/**
 * ECIES envelope encrypt: ephemeral X25519 + ECDH + HKDF-SHA256 + AES-256-GCM.
 * Fresh ephemeral keypair per call (security invariant).
 */
export function envelopeEncrypt(
  plaintext: Buffer,
  recipientX25519Pub: Buffer,
): EnvelopeCiphertext {
  // Generate ephemeral X25519 keypair
  const ephemeralPrivate = crypto.randomBytes(32);
  // Clamp
  ephemeralPrivate[0] &= 0xf8;
  ephemeralPrivate[31] &= 0x7f;
  ephemeralPrivate[31] |= 0x40;

  const ephemeralPublic = Buffer.from(x25519.scalarMultBase(ephemeralPrivate));

  // ECDH
  const sharedSecret = Buffer.from(
    x25519.scalarMult(ephemeralPrivate, recipientX25519Pub),
  );

  // Zero ephemeral private key
  ephemeralPrivate.fill(0);

  // HKDF-SHA256 (salt = 32 zero bytes per RFC 5869 when empty)
  const salt = new Uint8Array(32);
  const wrappingKey = hkdf(sha256, sharedSecret, salt, HKDF_INFO, 32);

  // Zero shared secret
  sharedSecret.fill(0);

  // AES-256-GCM
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(wrappingKey),
    iv,
    { authTagLength: AUTH_TAG_LENGTH },
  );
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ephemeralPublicKey: ephemeralPublic.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

/**
 * ECIES envelope decrypt: ECDH + HKDF-SHA256 + AES-256-GCM.
 */
export function envelopeDecrypt(
  envelope: EnvelopeCiphertext,
  recipientX25519Priv: Buffer,
): Buffer {
  const ephemeralPublic = Buffer.from(envelope.ephemeralPublicKey, 'base64');
  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  // ECDH
  const sharedSecret = Buffer.from(
    x25519.scalarMult(recipientX25519Priv, ephemeralPublic),
  );

  // HKDF-SHA256
  const salt = new Uint8Array(32);
  const wrappingKey = hkdf(sha256, sharedSecret, salt, HKDF_INFO, 32);

  // Zero shared secret
  sharedSecret.fill(0);

  // AES-256-GCM decrypt
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(wrappingKey),
    iv,
    { authTagLength: AUTH_TAG_LENGTH },
  );
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Load local X25519 keypair from ~/.cordelia/node.key (PKCS#8 DER).
 */
export async function getLocalX25519Keypair(): Promise<{
  publicKey: Buffer;
  privateKey: Buffer;
}> {
  const keyPath = path.join(os.homedir(), '.cordelia', 'node.key');
  const pkcs8Der = await fs.readFile(keyPath);
  const seed = extractEd25519Seed(pkcs8Der);
  return deriveX25519FromEd25519(seed);
}
