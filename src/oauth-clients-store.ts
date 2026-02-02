/**
 * Project Cordelia - OAuth Registered Clients Store
 *
 * Implements OAuthRegisteredClientsStore interface from MCP SDK.
 * Stores OAuth clients in SQLite with hashed secrets.
 */

import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { SqliteStorageProvider, OAuthClientRow } from './storage-sqlite.js';
import {
  generateClientId,
  generateClientSecret,
  hashToken,
  calculateExpiry,
  DEFAULT_CLIENT_SECRET_EXPIRY,
} from './oauth-tokens.js';

export interface CordeliaOAuthClientsStoreOptions {
  storage: SqliteStorageProvider;
  clientSecretExpirySeconds?: number;
}

/**
 * Cordelia OAuth Clients Store backed by SQLite.
 */
export class CordeliaOAuthClientsStore implements OAuthRegisteredClientsStore {
  private storage: SqliteStorageProvider;
  private clientSecretExpirySeconds: number;

  constructor(options: CordeliaOAuthClientsStoreOptions) {
    this.storage = options.storage;
    this.clientSecretExpirySeconds = options.clientSecretExpirySeconds ?? DEFAULT_CLIENT_SECRET_EXPIRY;
  }

  /**
   * Get a registered OAuth client by ID.
   * Returns the client info without the secret (secret is hashed in DB).
   */
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const row = await this.storage.getOAuthClient(clientId);
    if (!row) {
      return undefined;
    }
    return this.rowToClientInfo(row);
  }

  /**
   * Register a new OAuth client.
   * Generates client_id and client_secret, stores hashed secret.
   * Returns full client info including the plaintext secret (only time it's available).
   */
  async registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>
  ): Promise<OAuthClientInformationFull> {
    const clientId = generateClientId();
    const clientSecret = generateClientSecret();
    const clientSecretHash = hashToken(clientSecret);
    const clientIdIssuedAt = Math.floor(Date.now() / 1000);

    // Calculate secret expiry (null for public clients)
    let clientSecretExpiresAt: number | null = null;
    if (client.token_endpoint_auth_method !== 'none') {
      clientSecretExpiresAt = calculateExpiry(this.clientSecretExpirySeconds);
    }

    // Build the row for storage
    const row: Omit<OAuthClientRow, 'created_at' | 'updated_at'> = {
      client_id: clientId,
      client_secret_hash: clientSecretHash,
      client_id_issued_at: clientIdIssuedAt,
      client_secret_expires_at: clientSecretExpiresAt,
      redirect_uris: JSON.stringify(client.redirect_uris.map(u => u.toString())),
      token_endpoint_auth_method: client.token_endpoint_auth_method ?? 'client_secret_post',
      grant_types: JSON.stringify(client.grant_types ?? ['authorization_code', 'refresh_token']),
      response_types: JSON.stringify(client.response_types ?? ['code']),
      client_name: client.client_name ?? null,
      client_uri: client.client_uri?.toString() ?? null,
      logo_uri: client.logo_uri?.toString() ?? null,
      scope: client.scope ?? null,
      contacts: client.contacts ? JSON.stringify(client.contacts) : null,
      software_id: client.software_id ?? null,
      software_version: client.software_version ?? null,
      owner_user_id: null, // Will be set by caller if needed
    };

    await this.storage.createOAuthClient(row);

    // Return full client info with plaintext secret
    return {
      client_id: clientId,
      client_secret: clientSecret, // Only time the plaintext is returned
      client_id_issued_at: clientIdIssuedAt,
      client_secret_expires_at: clientSecretExpiresAt ?? undefined,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      grant_types: client.grant_types,
      response_types: client.response_types,
      client_name: client.client_name,
      client_uri: client.client_uri,
      logo_uri: client.logo_uri,
      scope: client.scope,
      contacts: client.contacts,
      software_id: client.software_id,
      software_version: client.software_version,
    };
  }

  /**
   * Verify a client secret against the stored hash.
   * @param clientId The client ID
   * @param clientSecret The plaintext secret to verify
   * @returns true if secret matches
   */
  async verifyClientSecret(clientId: string, clientSecret: string): Promise<boolean> {
    const row = await this.storage.getOAuthClient(clientId);
    if (!row || !row.client_secret_hash) {
      return false;
    }

    const providedHash = hashToken(clientSecret);
    return providedHash === row.client_secret_hash;
  }

  /**
   * Convert a database row to OAuthClientInformationFull.
   * Note: client_secret is not included (it's only stored as a hash).
   */
  private rowToClientInfo(row: OAuthClientRow): OAuthClientInformationFull {
    // Note: logo_uri and client_uri are stored as strings but SDK expects URL objects
    const result: OAuthClientInformationFull = {
      client_id: row.client_id,
      // client_secret is intentionally omitted (only hash is stored)
      client_id_issued_at: row.client_id_issued_at,
      client_secret_expires_at: row.client_secret_expires_at ?? undefined,
      redirect_uris: JSON.parse(row.redirect_uris).map((u: string) => new URL(u)),
      token_endpoint_auth_method: row.token_endpoint_auth_method,
      grant_types: JSON.parse(row.grant_types),
      response_types: JSON.parse(row.response_types),
      client_name: row.client_name ?? undefined,
      scope: row.scope ?? undefined,
      contacts: row.contacts ? JSON.parse(row.contacts) : undefined,
      software_id: row.software_id ?? undefined,
      software_version: row.software_version ?? undefined,
    };

    // Add optional URL fields if present
    if (row.client_uri) {
      (result as Record<string, unknown>).client_uri = new URL(row.client_uri);
    }
    if (row.logo_uri) {
      (result as Record<string, unknown>).logo_uri = new URL(row.logo_uri);
    }

    return result;
  }

  /**
   * Delete a client (for cleanup/revocation).
   */
  async deleteClient(clientId: string): Promise<boolean> {
    return this.storage.deleteOAuthClient(clientId);
  }

  /**
   * Check if a client secret has expired.
   */
  isClientSecretExpired(client: OAuthClientInformationFull): boolean {
    if (!client.client_secret_expires_at) {
      return false; // No expiry = never expires
    }
    const now = Math.floor(Date.now() / 1000);
    return now >= client.client_secret_expires_at;
  }
}
