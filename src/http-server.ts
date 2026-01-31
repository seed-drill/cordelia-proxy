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

const PORT = parseInt(process.env.CORDELIA_HTTP_PORT || '3847', 10);
const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');
const DASHBOARD_ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'dashboard');

// GitHub OAuth config
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const SESSION_SECRET = process.env.CORDELIA_SESSION_SECRET || crypto.randomBytes(32).toString('hex');

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

// Simple in-memory session store (for production, use Redis or similar)
const sessions = new Map<string, { github_id: string; github_login: string; cordelia_user: string | null; expires: number }>();

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
function getSession(req: Request): { github_id: string; github_login: string; cordelia_user: string | null } | null {
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
 * Create a new session.
 */
function createSession(githubId: string, githubLogin: string, cordeliaUser: string | null): string {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  sessions.set(sessionId, {
    github_id: githubId,
    github_login: githubLogin,
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
    res.json({ authenticated: false });
    return;
  }

  res.json({
    authenticated: true,
    github_login: session.github_login,
    cordelia_user: session.cordelia_user,
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
    const sessionId = createSession(String(userData.id), userData.login, cordeliaUser);

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
      if (session.github_login !== userId && session.cordelia_user !== userId) {
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

    if (!name || !github_id) {
      res.status(400).json({ error: 'Name and GitHub ID are required' });
      return;
    }

    // Generate user ID from GitHub ID
    const userId = github_id.toLowerCase().replace(/[^a-z0-9]/g, '_');

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
        github_id,
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
 * POST /api/profile/:userId/api-key - Generate or regenerate API key for CLI uploads
 * Requires session auth (must be logged in as this user)
 */
app.post('/api/profile/:userId/api-key', async (req: Request, res: Response) => {
  const session = getSession(req);
  const userId = req.params.userId;

  // Must be authenticated
  if (!session) {
    res.status(401).json({ error: 'unauthorized', detail: 'Must be logged in' });
    return;
  }

  // Can only generate API key for own profile
  if (session.github_login !== userId && session.cordelia_user !== userId) {
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
