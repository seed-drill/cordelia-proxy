#!/usr/bin/env node
/**
 * Project Cordelia - HTTP API Server
 *
 * Provides REST API access to Cordelia memory for the identity dashboard.
 * Runs on port 3847 (default).
 *
 * GitHub OAuth Configuration:
 *   GITHUB_CLIENT_ID: OAuth App client ID
 *   GITHUB_CLIENT_SECRET: OAuth App client secret
 *   CORDELIA_SESSION_SECRET: Secret for signing session cookies
 *   CORDELIA_BASE_URL: Base URL for OAuth callbacks (auto-detected on Fly.io)
 *
 * Honeycomb Monitoring:
 *   HONEYCOMB_API_KEY: Your Honeycomb API key
 */

// Initialize telemetry before other imports
import { initTelemetry, Sentry } from './instrumentation.js';
initTelemetry();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './swagger.js';
import * as crypto from 'crypto';
import * as path from 'path';
import { L1HotContextSchema, type L1HotContext } from './schema.js';
import * as l2 from './l2.js';
import {
  getConfig as getCryptoConfig,
  loadOrCreateSalt,
  initCrypto,
  getDefaultCryptoProvider,
  isEncryptedPayload,
  type EncryptedPayload,
} from './crypto.js';
import { initStorageProvider, getStorageProvider } from './storage.js';
import { Server as McpServer } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { CordeliaOAuthProvider } from './oauth-provider.js';
import { SqliteStorageProvider } from './storage-sqlite.js';

const PORT = parseInt(process.env.CORDELIA_HTTP_PORT || '3847', 10);
const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');
const DASHBOARD_ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'dashboard');

// GitHub OAuth config (optional)
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const SESSION_SECRET = process.env.CORDELIA_SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Local username/password auth (optional, format: "user1:pass1,user2:pass2")
const LOCAL_USERS_RAW = process.env.CORDELIA_LOCAL_USERS || '';
const LOCAL_USERS = new Map<string, string>();
if (LOCAL_USERS_RAW) {
  for (const pair of LOCAL_USERS_RAW.split(',')) {
    const [username, password] = pair.split(':');
    if (username && password) {
      LOCAL_USERS.set(username.trim(), password.trim());
    }
  }
}

// API key for CLI uploads (optional, set via CORDELIA_API_KEY)
const _API_KEY = process.env.CORDELIA_API_KEY;

// Core node API (optional, for P2P network status)
const CORDELIA_CORE_API = process.env.CORDELIA_CORE_API;

// Determine base URL for OAuth callback
// Priority: CORDELIA_BASE_URL > Fly.io detection > localhost
function getBaseUrl(): string {
  if (process.env.CORDELIA_BASE_URL) {
    return process.env.CORDELIA_BASE_URL;
  }
  if (process.env.FLY_APP_NAME) {
    return `https://${process.env.FLY_APP_NAME}.fly.dev`;
  }
  return `http://localhost:${PORT}`;
}

const BASE_URL = getBaseUrl();
const CALLBACK_URL = `${BASE_URL}/auth/github/callback`;

// Session type supports both GitHub OAuth and local auth
interface Session {
  auth_type: 'github' | 'local';
  username: string;           // github_login or local username
  github_id?: string;         // only for GitHub auth
  cordelia_user: string | null;
  expires: number;
}

// Simple in-memory session store (for production, use Redis or similar)
const sessions = new Map<string, Session>();

// OAuth provider (initialized on server start)
let oauthProvider: CordeliaOAuthProvider | null = null;

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser(SESSION_SECRET));

/**
 * Load hot context for a user, handling decryption if needed.
 */
async function loadHotContext(userId: string): Promise<L1HotContext | null> {
  try {
    const storage = getStorageProvider();
    const buffer = await storage.readL1(userId);

    if (!buffer) {
      return null;
    }

    let parsed = JSON.parse(buffer.toString('utf-8'));

    if (isEncryptedPayload(parsed)) {
      const cryptoProvider = getDefaultCryptoProvider();
      if (!cryptoProvider.isUnlocked()) {
        throw new Error('Cannot read encrypted L1 context: encryption not configured');
      }
      const decrypted = await cryptoProvider.decrypt(parsed as EncryptedPayload);
      parsed = JSON.parse(decrypted.toString('utf-8'));
    }

    return L1HotContextSchema.parse(parsed);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

/**
 * List available users from L1-hot directory.
 */
async function listUsers(): Promise<string[]> {
  try {
    const storage = getStorageProvider();
    return await storage.listL1Users();
  } catch {
    return [];
  }
}

/**
 * Find Cordelia user by GitHub login/ID.
 */
async function findUserByGitHub(githubLogin: string): Promise<string | null> {
  const users = await listUsers();

  for (const userId of users) {
    try {
      const context = await loadHotContext(userId);
      if (context?.identity.github_id === githubLogin) {
        return userId;
      }
    } catch {
      // Skip users we can't load
    }
  }

  return null;
}

/**
 * Get session from cookie.
 */
function getSession(req: Request): Session | null {
  const sessionId = req.signedCookies?.cordelia_session;
  if (!sessionId) return null;

  const session = sessions.get(sessionId);
  if (!session) return null;

  if (Date.now() > session.expires) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

/**
 * @deprecated Use OAuth 2.0 authentication instead.
 * Validate legacy API key from Authorization header and return the user ID.
 * Accepts: "Authorization: Bearer ck_xxx" or "X-API-Key: ck_xxx"
 *
 * This function is kept for backward compatibility during migration.
 * It will be removed in a future version.
 */
async function validateApiKey(req: Request): Promise<string | null> {
  // Check Authorization header first (Bearer token)
  const authHeader = req.headers.authorization;
  let apiKey: string | undefined;

  if (authHeader?.startsWith('Bearer ')) {
    apiKey = authHeader.slice(7);
  } else {
    // Fall back to X-API-Key header
    apiKey = req.headers['x-api-key'] as string | undefined;
  }

  // Only validate legacy API keys (ck_ prefix)
  if (!apiKey || !apiKey.startsWith('ck_')) {
    return null;
  }

  console.warn('DEPRECATED: Legacy API key authentication used. Please migrate to OAuth 2.0.');

  // Search all users for matching API key
  const users = await listUsers();
  for (const userId of users) {
    try {
      const context = await loadHotContext(userId);
      if (context?.identity?.api_key === apiKey) {
        return userId;
      }
    } catch {
      // Skip users we can't load
    }
  }

  return null;
}

/**
 * Create a new session for GitHub auth.
 */
function createGitHubSession(githubId: string, githubLogin: string, cordeliaUser: string | null): string {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  sessions.set(sessionId, {
    auth_type: 'github',
    username: githubLogin,
    github_id: githubId,
    cordelia_user: cordeliaUser,
    expires,
  });

  return sessionId;
}

/**
 * Create a new session for local auth.
 */
function createLocalSession(username: string, cordeliaUser: string | null): string {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  sessions.set(sessionId, {
    auth_type: 'local',
    username,
    cordelia_user: cordeliaUser,
    expires,
  });

  return sessionId;
}

// =============================================================================
// Authentication Routes
// =============================================================================

/**
 * GET /auth/status - Check if user is authenticated
 */
app.get('/auth/status', (req: Request, res: Response) => {
  const session = getSession(req);

  if (!session) {
    res.json({
      authenticated: false,
      github_enabled: !!GITHUB_CLIENT_ID,
      local_enabled: LOCAL_USERS.size > 0,
    });
    return;
  }

  res.json({
    authenticated: true,
    auth_type: session.auth_type,
    username: session.username,
    github_login: session.auth_type === 'github' ? session.username : undefined,
    cordelia_user: session.cordelia_user,
    github_enabled: !!GITHUB_CLIENT_ID,
    local_enabled: LOCAL_USERS.size > 0,
  });
});

/**
 * POST /auth/login - Username/password login
 */
app.post('/auth/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: 'Username and password required' });
    return;
  }

  if (LOCAL_USERS.size === 0) {
    res.status(403).json({ error: 'Local authentication not configured' });
    return;
  }

  const storedPassword = LOCAL_USERS.get(username);
  if (!storedPassword || storedPassword !== password) {
    res.status(401).json({ error: 'Invalid username or password' });
    return;
  }

  // Find matching Cordelia user
  const cordeliaUser = await findUserByGitHub(username); // Reuse the same lookup logic

  const sessionId = createLocalSession(username, cordeliaUser);

  res.cookie('cordelia_session', sessionId, {
    httpOnly: true,
    secure: BASE_URL.startsWith('https'),
    signed: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax',
  });

  res.json({
    success: true,
    username,
    cordelia_user: cordeliaUser,
  });
});

/**
 * GET /auth/github - Initiate GitHub OAuth
 */
app.get('/auth/github', (_req: Request, res: Response) => {
  if (!GITHUB_CLIENT_ID) {
    res.status(500).json({ error: 'GitHub OAuth not configured. Set GITHUB_CLIENT_ID.' });
    return;
  }

  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    scope: 'read:user',
    state,
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

/**
 * GET /auth/github/callback - Handle GitHub OAuth callback
 */
app.get('/auth/github/callback', async (req: Request, res: Response) => {
  const code = req.query.code as string;

  if (!code) {
    res.status(400).send('Missing authorization code');
    return;
  }

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
    res.status(500).send('GitHub OAuth not configured');
    return;
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: CALLBACK_URL,
      }),
    });

    const tokenData = await tokenResponse.json() as { access_token?: string; error?: string };

    if (tokenData.error || !tokenData.access_token) {
      res.status(400).send(`OAuth error: ${tokenData.error || 'No access token'}`);
      return;
    }

    // Get user info from GitHub
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: 'application/vnd.github.v3+json',
      },
    });

    const userData = await userResponse.json() as { id: number; login: string };

    // Find matching Cordelia user
    const cordeliaUser = await findUserByGitHub(userData.login);

    // Create session
    const sessionId = createGitHubSession(String(userData.id), userData.login, cordeliaUser);

    // Set cookie and redirect to dashboard
    res.cookie('cordelia_session', sessionId, {
      signed: true,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'lax',
    });

    res.redirect('/');
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.status(500).send('Authentication failed');
  }
});

/**
 * POST /auth/logout - Log out
 */
app.post('/auth/logout', (req: Request, res: Response) => {
  const sessionId = req.signedCookies?.cordelia_session;
  if (sessionId) {
    sessions.delete(sessionId);
  }
  res.clearCookie('cordelia_session');
  res.json({ success: true });
});

// =============================================================================
// OAuth 2.0 Consent Endpoints
// =============================================================================

/**
 * GET /oauth/consent - Serve the consent page
 * Redirected here by the OAuth authorize flow
 */
app.get('/oauth/consent', (_req: Request, res: Response) => {
  res.sendFile(path.join(DASHBOARD_ROOT, 'consent.html'));
});

/**
 * POST /oauth/consent - Process user consent decision
 * Called from the consent.html page after user approves/denies
 */
app.post('/oauth/consent', async (req: Request, res: Response) => {
  const session = getSession(req);

  if (!session || !session.cordelia_user) {
    res.status(401).json({ error: 'Must be logged in to authorize applications' });
    return;
  }

  if (!oauthProvider) {
    res.status(503).json({ error: 'OAuth not initialized' });
    return;
  }

  const { approved, client_id, state, redirect_uri } = req.body;

  if (!state) {
    res.status(400).json({ error: 'Missing state parameter' });
    return;
  }

  try {
    const result = await oauthProvider.completeAuthorization(
      state,
      session.cordelia_user,
      approved === true
    );

    if (result.error) {
      // Build error redirect URL
      const redirectUrl = new URL(result.redirectUri || redirect_uri);
      redirectUrl.searchParams.set('error', result.error);
      if (result.state) {
        redirectUrl.searchParams.set('state', result.state);
      }
      res.json({ redirect_url: redirectUrl.toString() });
      return;
    }

    // Build success redirect URL
    const redirectUrl = new URL(result.redirectUri!);
    redirectUrl.searchParams.set('code', result.code!);
    if (result.state) {
      redirectUrl.searchParams.set('state', result.state);
    }
    res.json({ redirect_url: redirectUrl.toString() });
  } catch (error) {
    console.error('OAuth consent error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

// =============================================================================
// API Routes
// =============================================================================

/**
 * GET /api/status - System status
 */
app.get('/api/status', async (_req: Request, res: Response) => {
  try {
    const users = await listUsers();
    const l2Index = await l2.loadIndex();
    const cryptoProvider = getDefaultCryptoProvider();

    res.json({
      status: 'ok',
      version: '0.4.0',
      server: 'http',
      port: PORT,
      auth: {
        github_configured: !!GITHUB_CLIENT_ID,
      },
      layers: {
        L1_hot: { users },
        L2_warm: {
          status: 'active',
          entries: l2Index.entries.length,
          entities: l2Index.entries.filter((e) => e.type === 'entity').length,
          sessions: l2Index.entries.filter((e) => e.type === 'session').length,
          learnings: l2Index.entries.filter((e) => e.type === 'learning').length,
        },
        L3_cold: { status: 'not_implemented' },
      },
      encryption: {
        provider: cryptoProvider.name,
        unlocked: cryptoProvider.isUnlocked(),
      },
    });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/core/status - Core node status (proxied from core node)
 */
app.get('/api/core/status', async (_req: Request, res: Response) => {
  if (!CORDELIA_CORE_API) {
    res.json({
      connected: false,
      error: 'Core API not configured',
      core_api: null,
    });
    return;
  }

  try {
    // Read the bearer token from core's config directory
    const fs = await import('fs/promises');
    let bearerToken = '';
    try {
      bearerToken = (await fs.readFile('/home/cordelia/.cordelia/node-token', 'utf-8')).trim();
    } catch {
      // Token file may not exist yet
    }

    const response = await fetch(`${CORDELIA_CORE_API}/api/v1/status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
    });

    if (!response.ok) {
      throw new Error(`Core API returned ${response.status}`);
    }

    const data = await response.json() as {
      node_id: string;
      entity_id: string;
      uptime_secs: number;
      peers_warm: number;
      peers_hot: number;
      groups: string[];
    };

    res.json({
      connected: true,
      core_api: CORDELIA_CORE_API,
      node_id: data.node_id,
      entity_id: data.entity_id,
      uptime_secs: data.uptime_secs,
      peers: {
        warm: data.peers_warm,
        hot: data.peers_hot,
        total: data.peers_warm + data.peers_hot,
      },
      groups: data.groups,
    });
  } catch (error) {
    const err = error as Error & { cause?: Error };
    console.error('Core status API error:', err.message, err.cause?.message || '');
    res.json({
      connected: false,
      error: err.cause?.message || err.message,
      core_api: CORDELIA_CORE_API,
    });
  }
});

/**
 * GET /api/peers - P2P network peer status (proxied from core node)
 * @deprecated Use /api/core/status instead
 */
app.get('/api/peers', async (_req: Request, res: Response) => {
  if (!CORDELIA_CORE_API) {
    res.json({ error: 'Core API not configured', warm: 0, hot: 0, total: 0 });
    return;
  }

  try {
    // Read the bearer token from core's config directory
    const fs = await import('fs/promises');
    let bearerToken = '';
    try {
      bearerToken = (await fs.readFile('/home/cordelia/.cordelia/node-token', 'utf-8')).trim();
    } catch {
      // Token file may not exist yet
    }

    const response = await fetch(`${CORDELIA_CORE_API}/api/v1/peers`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
    });

    if (!response.ok) {
      throw new Error(`Core API returned ${response.status}`);
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    const err = error as Error & { cause?: Error };
    console.error('Peers API error:', err.message, err.cause?.message || '');
    res.json({
      error: err.cause?.message || err.message,
      core_api: CORDELIA_CORE_API,
      warm: 0,
      hot: 0,
      total: 0
    });
  }
});

/**
 * GET /api/users - List available users
 */
app.get('/api/users', async (_req: Request, res: Response) => {
  try {
    const users = await listUsers();
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/hot/:userId - L1 hot context (decrypted)
 */
app.get('/api/hot/:userId', async (req: Request, res: Response) => {
  try {
    const userId = req.params.userId as string;
    const context = await loadHotContext(userId);

    if (!context) {
      res.status(404).json({ error: 'not_found', user_id: userId });
      return;
    }

    res.json(context);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * PUT /api/hot/:userId - Upload/update L1 hot context
 * Auth: session cookie OR X-API-Key header (per-user API key)
 */
app.put('/api/hot/:userId', async (req: Request, res: Response) => {
  try {
    const session = getSession(req);
    const userId = req.params.userId as string;
    const apiKey = req.headers['x-api-key'] as string | undefined;

    let isAuthorized = false;

    // Check per-user API key auth first
    if (apiKey) {
      const existingContext = await loadHotContext(userId);
      if (existingContext?.identity?.api_key && existingContext.identity.api_key === apiKey) {
        isAuthorized = true;
      }
    }

    // Fall back to session auth
    if (!isAuthorized) {
      if (!session) {
        res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in or provide valid X-API-Key' });
        return;
      }

      // Must be the owner (github_login matches userId or cordelia_user matches)
      if (session.username !== userId && session.cordelia_user !== userId) {
        res.status(403).json({ error: 'forbidden', detail: 'Can only update your own profile' });
        return;
      }
      isAuthorized = true;
    }

    // Validate the incoming context
    const validated = L1HotContextSchema.parse(req.body);

    // Encrypt if crypto is enabled
    const cryptoProvider = getDefaultCryptoProvider();
    let fileContent: string;

    if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
      const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
      const encrypted = await cryptoProvider.encrypt(plaintext);
      fileContent = JSON.stringify(encrypted, null, 2);
    } else {
      fileContent = JSON.stringify(validated, null, 2);
    }

    const storage = getStorageProvider();
    await storage.writeL1(userId, Buffer.from(fileContent, 'utf-8'));

    res.json({ success: true, user_id: userId });
  } catch (error) {
    console.error('Hot context upload error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/l2/index - L2 index
 */
app.get('/api/l2/index', async (_req: Request, res: Response) => {
  try {
    const index = await l2.loadIndex();
    const entries = index.entries.map(({ embedding: _embedding, ...rest }) => rest);
    res.json({ ...index, entries });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/l2/item/:id - L2 item (decrypted)
 */
app.get('/api/l2/item/:id', async (req: Request, res: Response) => {
  try {
    const id = req.params.id as string;
    const item = await l2.readItem(id);

    if (!item) {
      res.status(404).json({ error: 'not_found', id });
      return;
    }

    res.json(item);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/l2/search - Search L2
 */
app.get('/api/l2/search', async (req: Request, res: Response) => {
  try {
    const queryParam = req.query.query;
    const query = typeof queryParam === 'string' ? queryParam : undefined;
    const typeParam = req.query.type;
    const type = typeof typeParam === 'string' ? (typeParam as 'entity' | 'session' | 'learning') : undefined;
    const tagsRaw = req.query.tags;
    const tags = typeof tagsRaw === 'string' ? tagsRaw.split(',') : undefined;
    const limitParam = req.query.limit;
    const limit = typeof limitParam === 'string' ? parseInt(limitParam, 10) : undefined;

    const results = await l2.search({ query, type, tags, limit });
    res.json({ results, count: results.length });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * POST /api/signup - Create a new user profile
 */
app.post('/api/signup', async (req: Request, res: Response) => {
  try {
    const {
      name,
      github_id,
      username,  // Alternative to github_id for local auth
      roles = [],
      org_name,
      org_role,
      style = [],
      key_refs: rawKeyRefs = [],
      heroes = [],
      planning_mode = 'important',
      verbosity = 'concise',
      emoji: rawEmoji = false,
    } = req.body;

    // Convert emoji to boolean (might come as string from form)
    const emoji = rawEmoji === true || rawEmoji === 'true';

    // Transform key_refs to required format (author:title with lowercase/underscores)
    const key_refs = rawKeyRefs.map((ref: string) => {
      // If already in correct format, use as-is
      if (/^[a-z_]+:[a-z0-9_]+$/.test(ref)) return ref;
      // Otherwise, try to normalize it
      return ref.toLowerCase().replace(/[^a-z0-9:]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
    }).filter((ref: string) => /^[a-z_]+:[a-z0-9_]+$/.test(ref));

    // Accept either github_id or username for user identification
    const userIdentifier = github_id || username;
    if (!name || !userIdentifier) {
      res.status(400).json({ error: 'Name and username (or GitHub ID) are required' });
      return;
    }

    // Generate user ID from identifier
    const userId = userIdentifier.toLowerCase().replace(/[^a-z0-9]/g, '_');

    // Check if user already exists
    const storage = getStorageProvider();
    const existing = await storage.readL1(userId);
    if (existing) {
      res.status(409).json({ error: 'User already exists' });
      return;
    }

    // Build the L1 hot context
    const now = new Date().toISOString();
    const orgs = org_name && org_name.toLowerCase() !== 'independent'
      ? [{ id: org_name.toLowerCase().replace(/\s+/g, '_'), name: org_name, role: org_role || 'member' }]
      : [];

    // Build notes from heroes if provided
    const notes: string[] = [];
    if (heroes.length > 0) {
      notes.push(`Heroes: ${heroes.join(', ')}`);
    }

    const newContext = {
      version: 1,
      updated_at: now,
      identity: {
        id: userId,
        name,
        roles,
        orgs,
        key_refs,
        style,
        github_id: github_id || userIdentifier,  // Use github_id if provided, otherwise username
        tz: 'UTC',
      },
      active: {
        project: null,
        sprint: null,
        focus: null,
        blockers: [],
        next: [],
        context_refs: [],
        notes,
      },
      prefs: {
        planning_mode,
        feedback_style: 'continuous',
        verbosity,
        emoji,
        proactive_suggestions: true,
        auto_commit: false,
      },
      delegation: {
        allowed: true,
        max_parallel: 3,
        require_approval: ['git_push', 'destructive_operations', 'external_api_calls', 'file_delete'],
        autonomous: ['file_read', 'file_write', 'git_commit', 'code_execution_sandbox'],
      },
      ephemeral: {
        session_count: 1,
        current_session_start: now,
        last_session_end: null,
        last_summary: null,
        open_threads: [],
        vessel: null,
        integrity: {
          chain_hash: crypto.createHash('sha256').update(`genesis:${now}:${userId}`).digest('hex'),
          previous_hash: '0000000000000000000000000000000000000000000000000000000000000000',
          genesis: now,
        },
      },
    };

    // Validate against schema
    const validated = L1HotContextSchema.parse(newContext);

    // Write to file (encrypt if crypto is enabled)
    const cryptoProvider = getDefaultCryptoProvider();
    let fileContent: string;

    if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
      const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
      const encrypted = await cryptoProvider.encrypt(plaintext);
      fileContent = JSON.stringify(encrypted, null, 2);
    } else {
      fileContent = JSON.stringify(validated, null, 2);
    }

    await storage.writeL1(userId, Buffer.from(fileContent, 'utf-8'));

    // Update the session to link this user to their new Cordelia profile
    const sessionId = req.signedCookies?.cordelia_session;
    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
      session.cordelia_user = userId;
      sessions.set(sessionId, session);
    }

    res.json({ success: true, user_id: userId });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

// =============================================================================
// Profile Management Routes
// =============================================================================

/**
 * @deprecated Use OAuth 2.0 dynamic client registration instead.
 * POST /api/profile/:userId/api-key - Generate or regenerate legacy API key
 * Requires session auth (must be logged in as this user)
 *
 * This endpoint is deprecated. Use POST /register for OAuth client registration.
 */
app.post('/api/profile/:userId/api-key', async (req: Request, res: Response) => {
  console.warn('DEPRECATED: /api/profile/:userId/api-key endpoint called. Use OAuth 2.0 instead.');
  const session = getSession(req);
  const userId = req.params.userId;

  // Must be authenticated
  if (!session) {
    res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in' });
    return;
  }

  // Can only generate API key for own profile
  if (session.username !== userId && session.cordelia_user !== userId) {
    res.status(403).json({ error: 'forbidden', detail: 'Can only generate API key for your own profile' });
    return;
  }

  try {
    const storage = getStorageProvider();
    const context = await loadHotContext(userId);

    if (!context) {
      res.status(404).json({ error: 'not_found', detail: 'User profile not found' });
      return;
    }

    // Generate new API key (32 bytes = 64 hex chars)
    const apiKey = `ck_${crypto.randomBytes(32).toString('hex')}`;

    // Update context with new API key
    context.identity.api_key = apiKey;
    context.updated_at = new Date().toISOString();

    // Validate and save
    const validated = L1HotContextSchema.parse(context);
    const cryptoProvider = getDefaultCryptoProvider();
    let fileContent: string;

    if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
      const plaintext = Buffer.from(JSON.stringify(validated, null, 2), 'utf-8');
      const encrypted = await cryptoProvider.encrypt(plaintext);
      fileContent = JSON.stringify(encrypted, null, 2);
    } else {
      fileContent = JSON.stringify(validated, null, 2);
    }

    await storage.writeL1(userId, Buffer.from(fileContent, 'utf-8'));

    res.json({ success: true, api_key: apiKey });
  } catch (error) {
    console.error('API key generation error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * DELETE /api/profile/:userId - Delete a user profile (suicide is painless)
 * Removes L1 context and optionally associated L2 items
 */
app.delete('/api/profile/:userId', async (req: Request, res: Response) => {
  const session = getSession(req);

  // Must be authenticated
  if (!session) {
    res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in' });
    return;
  }

  const userId = req.params.userId;
  const deleteL2 = req.query.deleteL2 === 'true';

  // Can only delete own profile (unless admin - future feature)
  if (session.cordelia_user !== userId) {
    res.status(403).json({ error: 'forbidden', detail: 'Can only delete your own profile' });
    return;
  }

  try {
    const storage = getStorageProvider();

    // Delete L1 context
    await storage.deleteL1(userId);

    // Optionally delete associated L2 items (check owner via storage meta)
    let l2Deleted = 0;
    if (deleteL2) {
      const index = await l2.loadIndex();
      for (const entry of index.entries) {
        // Check owner via storage meta
        const meta = await storage.readL2ItemMeta(entry.id);
        if (meta?.owner_id === userId) {
          await l2.deleteItem(entry.id);
          l2Deleted++;
        }
      }
    }

    // Clear the session
    const sessionId = req.signedCookies?.cordelia_session;
    if (sessionId) {
      sessions.delete(sessionId);
    }
    res.clearCookie('cordelia_session');

    res.json({
      success: true,
      message: 'Profile deleted. Goodbye.',
      l2_items_deleted: l2Deleted
    });
  } catch (error) {
    console.error('Delete profile error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

/**
 * GET /api/profile/:userId/export - Export all user data
 * Returns L1 context and all L2 items for download
 */
app.get('/api/profile/:userId/export', async (req: Request, res: Response) => {
  const session = getSession(req);

  // Must be authenticated
  if (!session) {
    res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in' });
    return;
  }

  const userId = req.params.userId;

  // Can only export own profile
  if (session.cordelia_user !== userId) {
    res.status(403).json({ error: 'forbidden', detail: 'Can only export your own profile' });
    return;
  }

  try {
    const storage = getStorageProvider();

    // Get L1 context
    const l1Context = await loadHotContext(userId);
    if (!l1Context) {
      res.status(404).json({ error: 'not_found', user_id: userId });
      return;
    }

    // Get all L2 items owned by this user (check via storage meta)
    const index = await l2.loadIndex();
    const userItems: Array<{ type: string; data: unknown }> = [];

    for (const entry of index.entries) {
      const meta = await storage.readL2ItemMeta(entry.id);
      if (meta?.owner_id === userId) {
        const item = await l2.readItem(entry.id);
        if (item) {
          userItems.push({ type: entry.type, data: item });
        }
      }
    }

    const exportData = {
      export_version: '1.0',
      exported_at: new Date().toISOString(),
      user_id: userId,
      l1_context: l1Context,
      l2_items: userItems,
      l2_count: {
        entities: userItems.filter(i => i.type === 'entity').length,
        sessions: userItems.filter(i => i.type === 'session').length,
        learnings: userItems.filter(i => i.type === 'learning').length,
      }
    };

    // Set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="cordelia-export-${userId}-${new Date().toISOString().split('T')[0]}.json"`);
    res.json(exportData);
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

// =============================================================================
// Admin Routes
// =============================================================================

/**
 * GET /api/admin/users - List all users with summary info
 */
app.get('/api/admin/users', async (req: Request, res: Response) => {
  const session = getSession(req);

  // Must be authenticated (future: check admin role)
  if (!session) {
    res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in' });
    return;
  }

  try {
    const users = await listUsers();
    const userSummaries = [];

    for (const userId of users) {
      try {
        const context = await loadHotContext(userId);
        if (context) {
          userSummaries.push({
            id: userId,
            name: context.identity.name,
            github_id: context.identity.github_id,
            org: context.identity.orgs?.[0]?.name || 'Independent',
            roles: context.identity.roles || [],
            updated_at: context.updated_at,
            session_count: context.ephemeral?.session_count || 0,
          });
        }
      } catch {
        // Skip users that can't be loaded
        userSummaries.push({
          id: userId,
          name: userId,
          error: 'Could not load profile'
        });
      }
    }

    // Get L2 stats
    const l2Index = await l2.loadIndex();

    res.json({
      users: userSummaries,
      total_users: users.length,
      l2_stats: {
        total_items: l2Index.entries.length,
        entities: l2Index.entries.filter(e => e.type === 'entity').length,
        sessions: l2Index.entries.filter(e => e.type === 'session').length,
        learnings: l2Index.entries.filter(e => e.type === 'learning').length,
      }
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

// =============================================================================
// MCP SSE Transport
// =============================================================================

// Store active SSE transports by session ID, along with authenticated user
interface McpSession {
  transport: SSEServerTransport;
  userId: string;
}
const mcpTransports = new Map<string, McpSession>();

/**
 * Create an MCP server with all Cordelia tools registered.
 * Each SSE connection gets its own server instance.
 */
function createMcpServer(): McpServer {
  const server = new McpServer(
    { name: 'cordelia', version: '0.4.0' },
    { capabilities: { tools: {}, resources: {} } }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'memory_read_hot',
        description: 'Read L1 hot context for a user. Returns dense structured memory including identity, active state, preferences, and delegation rules.',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string', description: 'User identifier (e.g., "russell")' },
          },
          required: ['user_id'],
        },
      },
      {
        name: 'memory_write_hot',
        description: 'Write to L1 hot context for a user. Use patch for partial updates, replace for full replacement.',
        inputSchema: {
          type: 'object',
          properties: {
            user_id: { type: 'string', description: 'User identifier' },
            operation: { type: 'string', enum: ['patch', 'replace'] },
            data: { type: 'object', description: 'Data to write/merge' },
            expected_updated_at: { type: 'string', description: 'Optional optimistic lock' },
          },
          required: ['user_id', 'operation', 'data'],
        },
      },
      {
        name: 'memory_status',
        description: 'Get memory system status and available users.',
        inputSchema: { type: 'object', properties: {} },
      },
      {
        name: 'memory_search',
        description: 'Search L2 warm index by keyword, type, and/or tags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query' },
            type: { type: 'string', enum: ['entity', 'session', 'learning'] },
            tags: { type: 'array', items: { type: 'string' } },
            limit: { type: 'number', description: 'Max results (default: 20)' },
          },
        },
      },
      {
        name: 'memory_read_warm',
        description: 'Read a specific L2 warm item by ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Item ID' },
          },
          required: ['id'],
        },
      },
      {
        name: 'memory_write_warm',
        description: 'Create or update an L2 warm item (entity, session, or learning).',
        inputSchema: {
          type: 'object',
          properties: {
            type: { type: 'string', enum: ['entity', 'session', 'learning'] },
            data: { type: 'object', description: 'Item data' },
          },
          required: ['type', 'data'],
        },
      },
    ],
  }));

  // List available resources
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      const storage = getStorageProvider();
      const users = await storage.listL1Users();
      return {
        resources: users.map((userId) => ({
          uri: `cordelia://hot/${userId}`,
          name: `Hot context: ${userId}`,
          mimeType: 'application/json',
        })),
      };
    } catch {
      return { resources: [] };
    }
  });

  // Read resource
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;
    const match = uri.match(/^cordelia:\/\/hot\/(.+)$/);
    if (!match) throw new Error(`Unknown resource URI: ${uri}`);

    const userId = match[1];
    const context = await loadHotContext(userId);
    if (!context) throw new Error(`No hot context found for user: ${userId}`);

    return {
      contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(context, null, 2) }],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    switch (name) {
      case 'memory_read_hot': {
        const userId = (args as { user_id: string }).user_id;
        const context = await loadHotContext(userId);

        if (!context) {
          let knownUsers: string[] = [];
          try {
            const storage = getStorageProvider();
            knownUsers = await storage.listL1Users();
          } catch { /* ignore */ }

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                error: 'user_not_found',
                user_id: userId,
                known_users: knownUsers,
              }),
            }],
          };
        }

        return { content: [{ type: 'text', text: JSON.stringify(context) }] };
      }

      case 'memory_write_hot': {
        const { user_id, operation, data, expected_updated_at } = args as {
          user_id: string;
          operation: 'patch' | 'replace';
          data: Record<string, unknown>;
          expected_updated_at?: string;
        };

        // Load current, merge/replace, validate, write
        const current = await loadHotContext(user_id);
        if (!current) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'user_not_found' }) }] };
        }

        if (expected_updated_at && current.updated_at !== expected_updated_at) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'conflict', current_updated_at: current.updated_at }) }] };
        }

        const newUpdatedAt = new Date().toISOString();
        let newContext: L1HotContext;

        if (operation === 'replace') {
          const merged = { ...data, version: 1, updated_at: newUpdatedAt };
          try {
            newContext = L1HotContextSchema.parse(merged);
          } catch (e) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `validation_failed: ${(e as Error).message}` }) }] };
          }
        } else {
          // Patch - deep merge
          const merged = deepMerge(current as unknown as Record<string, unknown>, data);
          merged.updated_at = newUpdatedAt;
          try {
            newContext = L1HotContextSchema.parse(merged);
          } catch (e) {
            return { content: [{ type: 'text', text: JSON.stringify({ error: `validation_failed: ${(e as Error).message}` }) }] };
          }
        }

        // Write to storage
        const cryptoProvider = getDefaultCryptoProvider();
        let fileContent: string;
        if (cryptoProvider.isUnlocked() && cryptoProvider.name !== 'none') {
          const plaintext = Buffer.from(JSON.stringify(newContext, null, 2), 'utf-8');
          const encrypted = await cryptoProvider.encrypt(plaintext);
          fileContent = JSON.stringify(encrypted, null, 2);
        } else {
          fileContent = JSON.stringify(newContext, null, 2);
        }

        const storage = getStorageProvider();
        await storage.writeL1(user_id, Buffer.from(fileContent, 'utf-8'));

        return { content: [{ type: 'text', text: JSON.stringify({ success: true, updated_at: newUpdatedAt }) }] };
      }

      case 'memory_status': {
        let users: string[] = [];
        try {
          const storage = getStorageProvider();
          users = await storage.listL1Users();
        } catch { /* ignore */ }

        const l2Index = await l2.loadIndex();
        const cryptoProvider = getDefaultCryptoProvider();

        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              status: 'ok',
              version: '0.4.0',
              layers: {
                L1_hot: { users },
                L2_warm: {
                  entries: l2Index.entries.length,
                  entities: l2Index.entries.filter((e) => e.type === 'entity').length,
                  sessions: l2Index.entries.filter((e) => e.type === 'session').length,
                  learnings: l2Index.entries.filter((e) => e.type === 'learning').length,
                },
              },
              encryption: { provider: cryptoProvider.name, unlocked: cryptoProvider.isUnlocked() },
            }),
          }],
        };
      }

      case 'memory_search': {
        const { query, type, tags, limit } = args as {
          query?: string;
          type?: 'entity' | 'session' | 'learning';
          tags?: string[];
          limit?: number;
        };

        const results = await l2.search({ query, type, tags, limit });
        return { content: [{ type: 'text', text: JSON.stringify({ results, count: results.length }) }] };
      }

      case 'memory_read_warm': {
        const { id } = args as { id: string };
        const item = await l2.readItem(id);

        if (!item) {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'not_found', id }) }] };
        }

        return { content: [{ type: 'text', text: JSON.stringify(item) }] };
      }

      case 'memory_write_warm': {
        const { type, data } = args as {
          type: 'entity' | 'session' | 'learning';
          data: Record<string, unknown>;
        };

        const result = await l2.writeItem(type, data, {});
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  });

  return server;
}

/**
 * Deep merge two objects (for patch operations).
 */
function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = target[key];
    if (
      sourceVal !== null && typeof sourceVal === 'object' && !Array.isArray(sourceVal) &&
      targetVal !== null && typeof targetVal === 'object' && !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(targetVal as Record<string, unknown>, sourceVal as Record<string, unknown>);
    } else {
      result[key] = sourceVal;
    }
  }
  return result;
}

/**
 * GET /mcp/sse - Establish SSE connection for MCP
 * Requires OAuth 2.0 Bearer token authentication
 * Returns the session endpoint URL in the initial message
 */
app.get('/mcp/sse', async (req: Request, res: Response) => {
  console.log('MCP SSE: New connection attempt');

  if (!oauthProvider) {
    console.log('MCP SSE: OAuth not initialized');
    res.status(503).json({ error: 'OAuth not initialized' });
    return;
  }

  // Extract Bearer token from Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    console.log('MCP SSE: Missing Bearer token');
    res.status(401).json({
      error: 'unauthorized',
      detail: 'Bearer token required',
      www_authenticate: `Bearer realm="Cordelia MCP", resource="${BASE_URL}"`,
    });
    return;
  }

  const token = authHeader.slice(7);
  let authInfo: AuthInfo;

  try {
    authInfo = await oauthProvider.verifyAccessToken(token);
  } catch (error) {
    console.log('MCP SSE: Invalid token -', (error as Error).message);
    res.status(401).json({
      error: 'unauthorized',
      detail: (error as Error).message,
      www_authenticate: `Bearer realm="Cordelia MCP", error="invalid_token"`,
    });
    return;
  }

  // Check required scope
  if (!authInfo.scopes.includes('mcp') && !authInfo.scopes.includes('memory_read')) {
    console.log('MCP SSE: Insufficient scope');
    res.status(403).json({
      error: 'forbidden',
      detail: 'Token does not have required scope (mcp or memory_read)',
    });
    return;
  }

  const userId = authInfo.extra?.userId as string;
  if (!userId) {
    console.log('MCP SSE: Token missing user ID');
    res.status(401).json({ error: 'unauthorized', detail: 'Token missing user context' });
    return;
  }

  console.log(`MCP SSE: Authenticated as user ${userId}`);

  // Create transport - it will generate its own session ID
  const transport = new SSEServerTransport('/mcp/messages', res);

  // Store transport by its session ID (from _sessionId after start)
  const server = createMcpServer();

  // Connect server to transport
  await server.connect(transport);

  // Store transport for message routing (access private _sessionId)
  const sessionId = (transport as unknown as { _sessionId: string })._sessionId;
  mcpTransports.set(sessionId, { transport, userId });

  console.log(`MCP SSE: Session ${sessionId} connected for user ${userId}`);

  // Clean up on disconnect
  req.on('close', () => {
    console.log(`MCP SSE: Session ${sessionId} disconnected`);
    mcpTransports.delete(sessionId);
  });
});

/**
 * POST /mcp/messages - Receive messages from MCP client
 * Query param: sessionId
 * Validates OAuth Bearer token matches the session owner
 */
app.post('/mcp/messages', async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;

  if (!sessionId) {
    res.status(400).json({ error: 'Missing sessionId query parameter' });
    return;
  }

  const mcpSession = mcpTransports.get(sessionId);
  if (!mcpSession) {
    res.status(404).json({ error: 'Session not found', sessionId });
    return;
  }

  if (!oauthProvider) {
    res.status(503).json({ error: 'OAuth not initialized' });
    return;
  }

  // Validate OAuth Bearer token
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'unauthorized',
      detail: 'Bearer token required',
    });
    return;
  }

  const token = authHeader.slice(7);
  let authInfo: AuthInfo;

  try {
    authInfo = await oauthProvider.verifyAccessToken(token);
  } catch (error) {
    res.status(401).json({
      error: 'unauthorized',
      detail: (error as Error).message,
    });
    return;
  }

  const userId = authInfo.extra?.userId as string;
  if (!userId || userId !== mcpSession.userId) {
    res.status(401).json({
      error: 'unauthorized',
      detail: 'Token does not match session owner',
    });
    return;
  }

  try {
    await mcpSession.transport.handlePostMessage(req, res);
  } catch (error) {
    console.error('MCP SSE: Error handling message:', error);
    res.status(500).json({ error: (error as Error).message });
  }
});

// Swagger API docs
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Cordelia API Docs',
}));
app.get('/api/docs.json', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// Serve dashboard static files (after API routes)
app.use(express.static(DASHBOARD_ROOT));

// Error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('HTTP API error:', err);
  Sentry.captureException(err);
  res.status(500).json({ error: err.message });
});

// =============================================================================
// Server Startup
// =============================================================================

async function initEncryption(): Promise<void> {
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const config = getCryptoConfig(MEMORY_ROOT);

  if (!config.enabled || !passphrase) {
    console.log('Cordelia HTTP: Encryption disabled (no CORDELIA_ENCRYPTION_KEY)');
    return;
  }

  try {
    const salt = await loadOrCreateSalt(config.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Cordelia HTTP: Encryption enabled (AES-256-GCM)');
  } catch (error) {
    console.error('Cordelia HTTP: Failed to initialize encryption:', (error as Error).message);
  }
}

/**
 * Start the server on the given port/host. Returns the HTTP server instance.
 * Exported for test use - tests can start/stop the server programmatically.
 */
export async function startServer(opts?: { port?: number; host?: string; memoryRoot?: string }): Promise<import('http').Server> {
  const port = opts?.port ?? PORT;
  const host = opts?.host ?? process.env.HOST ?? '0.0.0.0';
  const memRoot = opts?.memoryRoot ?? MEMORY_ROOT;

  const storageProvider = await initStorageProvider(memRoot);
  console.log(`Cordelia HTTP: Storage provider: ${storageProvider.name}`);

  await initEncryption();

  // Initialize OAuth provider (requires SQLite storage)
  if (storageProvider.name === 'sqlite') {
    const sqliteStorage = storageProvider as SqliteStorageProvider;
    oauthProvider = new CordeliaOAuthProvider({
      storage: sqliteStorage,
      baseUrl: BASE_URL,
      accessTokenExpirySeconds: parseInt(process.env.OAUTH_ACCESS_TOKEN_EXPIRY || '3600', 10),
      refreshTokenExpirySeconds: parseInt(process.env.OAUTH_REFRESH_TOKEN_EXPIRY || '2592000', 10),
    });

    // Custom authorize handler that allows localhost redirect URIs (RFC 8252)
    // MUST be registered BEFORE mcpAuthRouter to intercept localhost requests
    app.get('/authorize', async (req: Request, res: Response, next: NextFunction) => {
      const redirectUri = req.query.redirect_uri as string;
      const clientId = req.query.client_id as string;

      // Only handle localhost redirect URIs specially
      if (!redirectUri || !clientId) {
        return next();
      }

      try {
        const redirectUrl = new URL(redirectUri);
        const isLocalhost = redirectUrl.hostname === 'localhost' ||
                           redirectUrl.hostname === '127.0.0.1' ||
                           redirectUrl.hostname === '[::1]';

        if (!isLocalhost) {
          return next(); // Let mcpAuthRouter handle non-localhost
        }

        // For localhost URIs, we need to verify the client exists and allow the redirect
        const client = await oauthProvider!.clientsStore.getClient(clientId);
        if (!client) {
          res.status(400).json({ error: 'invalid_request', error_description: 'Unknown client_id' });
          return;
        }

        // Check if any registered redirect_uri is a localhost URI
        const hasLocalhostRegistered = client.redirect_uris.some((uri) => {
          const u = new URL(uri.toString());
          return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
        });

        if (!hasLocalhostRegistered) {
          // Client didn't register any localhost URIs, reject
          res.status(400).json({ error: 'invalid_request', error_description: 'Unregistered redirect_uri' });
          return;
        }

        // Per RFC 8252, allow any port on localhost for native apps
        console.log(`OAuth: Allowing localhost redirect: ${redirectUri}`);

        // Build authorization params
        const scopes = (req.query.scope as string)?.split(' ').filter(Boolean) || [];
        const codeChallenge = req.query.code_challenge as string;
        const state = req.query.state as string;
        const resource = req.query.resource as string;

        if (!codeChallenge) {
          res.status(400).json({ error: 'invalid_request', error_description: 'PKCE code_challenge required' });
          return;
        }

        // Call provider.authorize directly
        await oauthProvider!.authorize(client, {
          redirectUri,
          scopes,
          codeChallenge,
          state,
          resource: resource ? new URL(resource) : undefined,
        }, res);

      } catch (error) {
        console.error('OAuth authorize error:', error);
        res.status(400).json({ error: 'invalid_request', error_description: (error as Error).message });
      }
    });

    // Mount OAuth router for standard endpoints (after custom /authorize handler)
    app.use(mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl: new URL(BASE_URL),
      scopesSupported: ['memory_read', 'memory_write', 'memory_search', 'mcp'],
      serviceDocumentationUrl: new URL(`${BASE_URL}/api/docs`),
    }));

    console.log('Cordelia HTTP: OAuth 2.0 enabled');
  } else {
    console.log('Cordelia HTTP: OAuth disabled (requires SQLite storage)');
  }

  return new Promise((resolve) => {
    const server = app.listen(port, host, () => {
      console.log(`Cordelia HTTP API running on http://${host}:${port}`);
      resolve(server);
    });
  });
}

export { app };

// Run main() only when executed directly (not imported by tests)
const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith('http-server.ts') ||
  process.argv[1].endsWith('http-server.js')
);

if (isDirectRun) {
  startServer().catch(console.error);
}
