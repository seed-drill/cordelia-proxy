/**
 * Project Cordelia - OAuth Token Utilities
 *
 * Token generation, hashing, and verification for OAuth 2.0 flows.
 */

import * as crypto from 'crypto';

// Token expiry defaults (in seconds)
export const DEFAULT_ACCESS_TOKEN_EXPIRY = 3600; // 1 hour
export const DEFAULT_REFRESH_TOKEN_EXPIRY = 30 * 24 * 3600; // 30 days
export const DEFAULT_AUTHORIZATION_CODE_EXPIRY = 600; // 10 minutes
export const DEFAULT_CLIENT_SECRET_EXPIRY = 30 * 24 * 3600; // 30 days

/**
 * Generate a cryptographically secure random token.
 * @param bytes Number of random bytes (default: 32)
 * @returns Base64url-encoded token
 */
export function generateToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Generate an access token.
 * Format: at_<random>
 */
export function generateAccessToken(): string {
  return `at_${generateToken(32)}`;
}

/**
 * Generate a refresh token.
 * Format: rt_<random>
 */
export function generateRefreshToken(): string {
  return `rt_${generateToken(48)}`;
}

/**
 * Generate an authorization code.
 * Format: ac_<random>
 */
export function generateAuthorizationCode(): string {
  return `ac_${generateToken(32)}`;
}

/**
 * Generate a client ID.
 * Uses UUID v4 format.
 */
export function generateClientId(): string {
  return crypto.randomUUID();
}

/**
 * Generate a client secret.
 * Format: cs_<random>
 */
export function generateClientSecret(): string {
  return `cs_${generateToken(32)}`;
}

/**
 * Hash a token for storage.
 * Uses SHA-256 to create a fixed-length hash.
 * @param token The raw token
 * @returns Hex-encoded SHA-256 hash
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Verify a PKCE code verifier against a code challenge.
 * Only S256 method is supported.
 * @param verifier The code_verifier from the client
 * @param challenge The code_challenge stored during authorization
 * @param method The challenge method (must be 'S256')
 * @returns true if verification passes
 */
export function verifyPKCE(verifier: string, challenge: string, method = 'S256'): boolean {
  if (method !== 'S256') {
    throw new Error('Only S256 PKCE method is supported');
  }

  // S256: BASE64URL(SHA256(code_verifier))
  const computed = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');

  return computed === challenge;
}

/**
 * Generate a PKCE code verifier and challenge pair (for testing).
 * @returns Object with verifier and challenge
 */
export function generatePKCE(): { verifier: string; challenge: string } {
  // Code verifier: 43-128 characters from unreserved URI characters
  const verifier = generateToken(32);

  // Code challenge: BASE64URL(SHA256(verifier))
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');

  return { verifier, challenge };
}

/**
 * Check if a token has expired.
 * @param expiresAt Expiration timestamp (epoch seconds)
 * @returns true if expired
 */
export function isExpired(expiresAt: number | null): boolean {
  if (expiresAt === null) {
    return false; // null means never expires
  }
  const now = Math.floor(Date.now() / 1000);
  return now >= expiresAt;
}

/**
 * Calculate expiration timestamp.
 * @param expirySeconds Seconds until expiration
 * @returns Epoch timestamp (seconds)
 */
export function calculateExpiry(expirySeconds: number): number {
  return Math.floor(Date.now() / 1000) + expirySeconds;
}

/**
 * Parse scope string into array.
 * @param scope Space-separated scope string
 * @returns Array of scopes
 */
export function parseScopes(scope: string | null | undefined): string[] {
  if (!scope) return [];
  return scope.split(/\s+/).filter(Boolean);
}

/**
 * Join scopes array into string.
 * @param scopes Array of scopes
 * @returns Space-separated scope string
 */
export function joinScopes(scopes: string[]): string {
  return scopes.join(' ');
}

/**
 * Check if requested scopes are a subset of allowed scopes.
 * @param requested Requested scopes
 * @param allowed Allowed scopes
 * @returns true if all requested scopes are allowed
 */
export function validateScopes(requested: string[], allowed: string[]): boolean {
  const allowedSet = new Set(allowed);
  return requested.every(scope => allowedSet.has(scope));
}

/**
 * Cordelia-specific scopes.
 */
export const CORDELIA_SCOPES = {
  MEMORY_READ: 'memory_read',
  MEMORY_WRITE: 'memory_write',
  MEMORY_SEARCH: 'memory_search',
  MCP: 'mcp', // Full MCP access
} as const;

/**
 * Default scopes for MCP clients.
 */
export const DEFAULT_MCP_SCOPES = [
  CORDELIA_SCOPES.MEMORY_READ,
  CORDELIA_SCOPES.MEMORY_WRITE,
  CORDELIA_SCOPES.MEMORY_SEARCH,
  CORDELIA_SCOPES.MCP,
];

/**
 * All supported scopes.
 */
export const SUPPORTED_SCOPES = Object.values(CORDELIA_SCOPES);
