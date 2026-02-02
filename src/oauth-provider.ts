/**
 * Project Cordelia - OAuth Server Provider
 *
 * Implements OAuthServerProvider interface from MCP SDK.
 * Handles the complete OAuth 2.0 authorization flow.
 */

import type { Response } from 'express';
import type { OAuthServerProvider, AuthorizationParams, OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';
import { CordeliaOAuthClientsStore } from './oauth-clients-store.js';
import {
  generateAccessToken,
  generateRefreshToken,
  generateAuthorizationCode,
  hashToken,
  verifyPKCE,
  isExpired,
  calculateExpiry,
  parseScopes,
  joinScopes,
  DEFAULT_ACCESS_TOKEN_EXPIRY,
  DEFAULT_REFRESH_TOKEN_EXPIRY,
  DEFAULT_AUTHORIZATION_CODE_EXPIRY,
  SUPPORTED_SCOPES,
} from './oauth-tokens.js';

export interface CordeliaOAuthProviderOptions {
  storage: SqliteStorageProvider;
  baseUrl: string;
  accessTokenExpirySeconds?: number;
  refreshTokenExpirySeconds?: number;
  authorizationCodeExpirySeconds?: number;
}

// Pending authorization requests stored in memory
interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
  createdAt: number;
}

/**
 * Cordelia OAuth Server Provider.
 * Implements the full OAuth 2.0 authorization code flow with PKCE.
 */
export class CordeliaOAuthProvider implements OAuthServerProvider, OAuthTokenVerifier {
  private storage: SqliteStorageProvider;
  private _clientsStore: CordeliaOAuthClientsStore;
  private baseUrl: string;
  private accessTokenExpirySeconds: number;
  private refreshTokenExpirySeconds: number;
  private authorizationCodeExpirySeconds: number;

  // Store pending authorizations keyed by state
  private pendingAuthorizations = new Map<string, PendingAuthorization>();

  constructor(options: CordeliaOAuthProviderOptions) {
    this.storage = options.storage;
    this._clientsStore = new CordeliaOAuthClientsStore({ storage: options.storage });
    this.baseUrl = options.baseUrl;
    this.accessTokenExpirySeconds = options.accessTokenExpirySeconds ?? DEFAULT_ACCESS_TOKEN_EXPIRY;
    this.refreshTokenExpirySeconds = options.refreshTokenExpirySeconds ?? DEFAULT_REFRESH_TOKEN_EXPIRY;
    this.authorizationCodeExpirySeconds = options.authorizationCodeExpirySeconds ?? DEFAULT_AUTHORIZATION_CODE_EXPIRY;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /**
   * Begin the authorization flow.
   * Redirects to a consent page where the user can approve or deny.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    // Generate a state if not provided
    const state = params.state || generateAuthorizationCode().slice(0, 16);

    // Store the pending authorization
    this.pendingAuthorizations.set(state, {
      clientId: client.client_id,
      params,
      createdAt: Date.now(),
    });

    // Clean up old pending authorizations (older than 10 minutes)
    this.cleanupPendingAuthorizations();

    // Build the consent page URL
    const consentUrl = new URL('/oauth/consent', this.baseUrl);
    consentUrl.searchParams.set('client_id', client.client_id);
    consentUrl.searchParams.set('client_name', client.client_name || client.client_id);
    consentUrl.searchParams.set('redirect_uri', params.redirectUri);
    consentUrl.searchParams.set('state', state);
    consentUrl.searchParams.set('scope', params.scopes?.join(' ') || '');
    consentUrl.searchParams.set('code_challenge', params.codeChallenge);
    if (params.resource) {
      consentUrl.searchParams.set('resource', params.resource.toString());
    }

    // Redirect to consent page
    res.redirect(consentUrl.toString());
  }

  /**
   * Complete the authorization after user consent.
   * Called by the consent endpoint after the user approves.
   * @returns The authorization code to redirect with
   */
  async completeAuthorization(
    state: string,
    userId: string,
    approved: boolean
  ): Promise<{ code?: string; error?: string; redirectUri: string; state?: string }> {
    const pending = this.pendingAuthorizations.get(state);
    if (!pending) {
      return { error: 'invalid_request', redirectUri: '', state };
    }

    this.pendingAuthorizations.delete(state);

    const redirectUri = pending.params.redirectUri;

    if (!approved) {
      return { error: 'access_denied', redirectUri, state: pending.params.state };
    }

    // Generate authorization code
    const code = generateAuthorizationCode();
    const codeHash = hashToken(code);

    // Store the authorization code
    await this.storage.storeAuthorizationCode(codeHash, {
      client_id: pending.clientId,
      user_id: userId,
      redirect_uri: redirectUri,
      scope: pending.params.scopes?.join(' ') || null,
      code_challenge: pending.params.codeChallenge,
      code_challenge_method: 'S256',
      expires_at: calculateExpiry(this.authorizationCodeExpirySeconds),
      resource: pending.params.resource?.toString() || null,
    });

    return { code, redirectUri, state: pending.params.state };
  }

  /**
   * Get the code challenge for an authorization code.
   */
  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const codeHash = hashToken(authorizationCode);
    const codeData = await this.storage.getAuthorizationCode(codeHash);

    if (!codeData) {
      return '';
    }

    return codeData.code_challenge;
  }

  /**
   * Exchange an authorization code for tokens.
   */
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    const codeHash = hashToken(authorizationCode);
    const codeData = await this.storage.getAuthorizationCode(codeHash);

    if (!codeData) {
      throw new Error('Invalid authorization code');
    }

    // Verify the code hasn't expired
    if (isExpired(codeData.expires_at)) {
      await this.storage.deleteAuthorizationCode(codeHash);
      throw new Error('Authorization code expired');
    }

    // Verify client ID matches
    if (codeData.client_id !== client.client_id) {
      throw new Error('Client ID mismatch');
    }

    // Verify redirect URI matches
    if (redirectUri && codeData.redirect_uri !== redirectUri) {
      throw new Error('Redirect URI mismatch');
    }

    // Verify PKCE code verifier
    if (codeVerifier) {
      if (!verifyPKCE(codeVerifier, codeData.code_challenge, codeData.code_challenge_method)) {
        throw new Error('Invalid code verifier');
      }
    }

    // Consume the authorization code (delete it)
    await this.storage.deleteAuthorizationCode(codeHash);

    // Generate tokens
    const accessToken = generateAccessToken();
    const refreshToken = generateRefreshToken();
    const accessTokenExpiresAt = calculateExpiry(this.accessTokenExpirySeconds);
    const refreshTokenExpiresAt = calculateExpiry(this.refreshTokenExpirySeconds);

    // Store access token
    await this.storage.storeAccessToken(hashToken(accessToken), {
      client_id: client.client_id,
      user_id: codeData.user_id,
      scope: codeData.scope,
      expires_at: accessTokenExpiresAt,
      resource: resource?.toString() || codeData.resource,
    });

    // Store refresh token
    await this.storage.storeRefreshToken(hashToken(refreshToken), {
      client_id: client.client_id,
      user_id: codeData.user_id,
      scope: codeData.scope,
      expires_at: refreshTokenExpiresAt,
      resource: resource?.toString() || codeData.resource,
      revoked_at: null,
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenExpirySeconds,
      scope: codeData.scope || undefined,
      refresh_token: refreshToken,
    };
  }

  /**
   * Exchange a refresh token for a new access token.
   */
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    const tokenHash = hashToken(refreshToken);
    const tokenData = await this.storage.getRefreshToken(tokenHash);

    if (!tokenData) {
      throw new Error('Invalid refresh token');
    }

    // Check if revoked
    if (tokenData.revoked_at) {
      throw new Error('Refresh token has been revoked');
    }

    // Check if expired
    if (tokenData.expires_at && isExpired(tokenData.expires_at)) {
      throw new Error('Refresh token expired');
    }

    // Verify client ID matches
    if (tokenData.client_id !== client.client_id) {
      throw new Error('Client ID mismatch');
    }

    // Validate requested scopes (must be subset of original)
    let finalScope = tokenData.scope;
    if (scopes && scopes.length > 0) {
      const originalScopes = parseScopes(tokenData.scope);
      const requestedScopes = new Set(scopes);
      const originalSet = new Set(originalScopes);

      // All requested scopes must be in original
      for (const s of requestedScopes) {
        if (!originalSet.has(s)) {
          throw new Error(`Scope '${s}' was not in original grant`);
        }
      }

      finalScope = joinScopes(scopes);
    }

    // Generate new access token
    const accessToken = generateAccessToken();
    const accessTokenExpiresAt = calculateExpiry(this.accessTokenExpirySeconds);

    // Store new access token
    await this.storage.storeAccessToken(hashToken(accessToken), {
      client_id: client.client_id,
      user_id: tokenData.user_id,
      scope: finalScope,
      expires_at: accessTokenExpiresAt,
      resource: resource?.toString() || tokenData.resource,
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenExpirySeconds,
      scope: finalScope || undefined,
      // Don't issue new refresh token by default (can be configured)
    };
  }

  /**
   * Verify an access token and return auth info.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const tokenHash = hashToken(token);
    const tokenData = await this.storage.getAccessToken(tokenHash);

    if (!tokenData) {
      throw new Error('Invalid access token');
    }

    // Check expiration
    if (isExpired(tokenData.expires_at)) {
      // Clean up expired token
      await this.storage.deleteAccessToken(tokenHash);
      throw new Error('Access token expired');
    }

    return {
      token,
      clientId: tokenData.client_id,
      scopes: parseScopes(tokenData.scope),
      expiresAt: tokenData.expires_at,
      resource: tokenData.resource ? new URL(tokenData.resource) : undefined,
      extra: {
        userId: tokenData.user_id,
      },
    };
  }

  /**
   * Revoke an access or refresh token.
   */
  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    const tokenHash = hashToken(request.token);

    // Try to revoke as access token
    const accessToken = await this.storage.getAccessToken(tokenHash);
    if (accessToken) {
      // Verify client owns this token
      if (accessToken.client_id === client.client_id) {
        await this.storage.deleteAccessToken(tokenHash);
      }
      return;
    }

    // Try to revoke as refresh token
    const refreshToken = await this.storage.getRefreshToken(tokenHash);
    if (refreshToken) {
      // Verify client owns this token
      if (refreshToken.client_id === client.client_id) {
        await this.storage.revokeRefreshToken(tokenHash);
      }
      return;
    }

    // Token not found - per RFC 7009, this is not an error
  }

  /**
   * Get supported scopes for metadata.
   */
  getSupportedScopes(): string[] {
    return SUPPORTED_SCOPES;
  }

  /**
   * Clean up expired authorization codes and tokens.
   */
  async cleanup(): Promise<{ codes: number; accessTokens: number }> {
    const codes = await this.storage.cleanupExpiredAuthorizationCodes();
    const accessTokens = await this.storage.cleanupExpiredAccessTokens();
    return { codes, accessTokens };
  }

  /**
   * Clean up old pending authorizations.
   */
  private cleanupPendingAuthorizations(): void {
    const tenMinutesAgo = Date.now() - 10 * 60 * 1000;
    for (const [state, pending] of this.pendingAuthorizations) {
      if (pending.createdAt < tenMinutesAgo) {
        this.pendingAuthorizations.delete(state);
      }
    }
  }

  /**
   * Check if a user ID is valid (exists in L1).
   */
  async isValidUser(userId: string): Promise<boolean> {
    const data = await this.storage.readL1(userId);
    return data !== null;
  }

  /**
   * Revoke all tokens for a user.
   */
  async revokeAllUserTokens(userId: string): Promise<{ accessTokens: number; refreshTokens: number }> {
    return this.storage.revokeAllUserTokens(userId);
  }
}
