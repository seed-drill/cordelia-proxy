/**
 * Project Cordelia - HTTP Server Tests
 *
 * Integration tests for the HTTP API. Starts a real server on a random port
 * with an isolated temp directory for storage.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import type { Server } from 'http';

let server: Server;
let API_BASE: string;
let tmpDir: string;

// Test user data
const testUsers = {
  minimal: {
    name: 'Test User',
    github_id: 'testuser123',
  },
  complete: {
    name: 'Jane Developer',
    github_id: 'janedev',
    roles: ['engineer', 'founder', 'writer'],
    org_name: 'Acme Corp',
    org_role: 'CTO',
    style: ['first_principles', 'iterative', 'systems_thinking'],
    key_refs: ['brooks:mythical_man_month', 'knuth:art_of_programming'],
    heroes: ['Ada Lovelace', 'Grace Hopper', 'Margaret Hamilton'],
    planning_mode: 'critical',
    verbosity: 'detailed',
    emoji: false,
  },
  withBadKeyRefs: {
    name: 'Bob Tester',
    github_id: 'bobtester',
    key_refs: ['Some Book by Author', 'another:valid_ref', 'Invalid Format Here'],
    emoji: 'false', // String instead of boolean - should be converted
  },
  independent: {
    name: 'Solo Dev',
    github_id: 'solodev',
    org_name: 'independent',
    org_role: 'Freelance Developer',
    roles: ['developer', 'consultant'],
  },
  withEmoji: {
    name: 'Emoji Fan',
    github_id: 'emojifan',
    emoji: true,
  },
  emojiAsString: {
    name: 'String Emoji',
    github_id: 'stringemoji',
    emoji: 'true', // String that should convert to boolean true
  },
};

// Helper to make API requests
async function apiRequest(endpoint: string, options: RequestInit = {}): Promise<{ status: number; data: any }> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers as Record<string, string> },
    ...options,
  });
  const data = await response.json();
  return { status: response.status, data };
}

// Global setup: create temp dir, start server
before(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'cordelia-test-'));
  // Create required subdirectories
  await fs.mkdir(path.join(tmpDir, 'L1-hot'), { recursive: true });
  await fs.mkdir(path.join(tmpDir, 'L2-warm', 'items'), { recursive: true });

  // Use SQLite storage, disable encryption for test simplicity
  process.env.CORDELIA_STORAGE = 'sqlite';
  delete process.env.CORDELIA_ENCRYPTION_KEY;

  const { startServer } = await import('./http-server.js');
  server = await startServer({ port: 0, host: '127.0.0.1', memoryRoot: tmpDir });

  const addr = server.address();
  if (addr && typeof addr === 'object') {
    API_BASE = `http://127.0.0.1:${addr.port}`;
  } else {
    throw new Error('Failed to get server address');
  }
});

// Global teardown: stop server, remove temp dir
after(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  if (tmpDir) {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

describe('Signup Endpoint', () => {
  describe('POST /api/signup', () => {
    it('should create user with minimal data', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.minimal),
      });

      assert.strictEqual(status, 200);
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.user_id, 'testuser123');
    });

    it('should create user with complete data', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.complete),
      });

      assert.strictEqual(status, 200);
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.user_id, 'janedev');

      // Verify the created user
      const { data: userData } = await apiRequest('/api/hot/janedev');
      assert.strictEqual(userData.identity.name, 'Jane Developer');
      assert.strictEqual(userData.identity.github_id, 'janedev');
      assert.deepStrictEqual(userData.identity.roles, ['engineer', 'founder', 'writer']);
      assert.strictEqual(userData.identity.orgs[0].name, 'Acme Corp');
      assert.strictEqual(userData.identity.orgs[0].role, 'CTO');
      assert.deepStrictEqual(userData.identity.style, ['first_principles', 'iterative', 'systems_thinking']);
      assert.deepStrictEqual(userData.identity.key_refs, ['brooks:mythical_man_month', 'knuth:art_of_programming']);
      assert.strictEqual(userData.prefs.planning_mode, 'critical');
      assert.strictEqual(userData.prefs.verbosity, 'detailed');
      assert.strictEqual(userData.prefs.emoji, false);
      assert.ok(userData.active.notes.includes('Heroes: Ada Lovelace, Grace Hopper, Margaret Hamilton'));
    });

    it('should normalize invalid key_refs and convert emoji string', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.withBadKeyRefs),
      });

      assert.strictEqual(status, 200);
      assert.strictEqual(data.success, true);

      // Verify the created user
      const { data: userData } = await apiRequest('/api/hot/bobtester');
      // Only the valid key_ref should remain
      assert.ok(userData.identity.key_refs.includes('another:valid_ref'));
      // Invalid formats should be filtered out or normalized
      assert.strictEqual(userData.prefs.emoji, false); // String 'false' converted to boolean
    });

    it('should handle independent users without org', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.independent),
      });

      assert.strictEqual(status, 200);
      assert.strictEqual(data.success, true);

      const { data: userData } = await apiRequest('/api/hot/solodev');
      assert.deepStrictEqual(userData.identity.orgs, []); // No org for independent
      assert.deepStrictEqual(userData.identity.roles, ['developer', 'consultant']);
    });

    it('should handle emoji as boolean true', async () => {
      const { status, data: _data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.withEmoji),
      });

      assert.strictEqual(status, 200);
      const { data: userData } = await apiRequest('/api/hot/emojifan');
      assert.strictEqual(userData.prefs.emoji, true);
    });

    it('should convert emoji string "true" to boolean', async () => {
      const { status, data: _data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.emojiAsString),
      });

      assert.strictEqual(status, 200);
      const { data: userData } = await apiRequest('/api/hot/stringemoji');
      assert.strictEqual(userData.prefs.emoji, true);
    });

    it('should reject signup without name', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify({ github_id: 'noname' }),
      });

      assert.strictEqual(status, 400);
      assert.ok(data.error.includes('Name'));
    });

    it('should reject signup without github_id', async () => {
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify({ name: 'No GitHub' }),
      });

      assert.strictEqual(status, 400);
      assert.ok(data.error.includes('GitHub'));
    });

    it('should reject duplicate signup', async () => {
      // testUsers.minimal was already created above
      const { status, data } = await apiRequest('/api/signup', {
        method: 'POST',
        body: JSON.stringify(testUsers.minimal),
      });

      assert.strictEqual(status, 409);
      assert.strictEqual(data.error, 'User already exists');
    });
  });
});

describe('Auth Endpoints', () => {
  describe('GET /auth/status', () => {
    it('should return unauthenticated when no session', async () => {
      const { status, data } = await apiRequest('/auth/status');

      assert.strictEqual(status, 200);
      assert.strictEqual(data.authenticated, false);
    });
  });
});

describe('API Endpoints', () => {
  describe('GET /api/status', () => {
    it('should return system status', async () => {
      const { status, data } = await apiRequest('/api/status');

      assert.strictEqual(status, 200);
      assert.strictEqual(data.status, 'ok');
      assert.ok(data.version);
      assert.ok(data.layers);
      assert.ok(data.layers.L1_hot);
      assert.ok(data.layers.L2_warm);
    });
  });

  describe('GET /api/users', () => {
    it('should return list of users', async () => {
      const { status, data } = await apiRequest('/api/users');

      assert.strictEqual(status, 200);
      assert.ok(Array.isArray(data.users));
    });
  });

  describe('GET /api/hot/:userId', () => {
    it('should return 404 for non-existent user', async () => {
      const { status, data } = await apiRequest('/api/hot/nonexistent_user_xyz');

      assert.strictEqual(status, 404);
      assert.strictEqual(data.error, 'not_found');
    });
  });

  describe('GET /api/l2/index', () => {
    it('should return L2 index', async () => {
      const { status, data } = await apiRequest('/api/l2/index');

      assert.strictEqual(status, 200);
      assert.ok(data.version);
      assert.ok(Array.isArray(data.entries));
    });
  });

  describe('GET /api/l2/search', () => {
    it('should search with query', async () => {
      const { status, data } = await apiRequest('/api/l2/search?query=test');

      assert.strictEqual(status, 200);
      assert.ok(Array.isArray(data.results));
      assert.ok(typeof data.count === 'number');
    });

    it('should filter by type', async () => {
      const { status, data } = await apiRequest('/api/l2/search?type=entity');

      assert.strictEqual(status, 200);
      assert.ok(Array.isArray(data.results));
      // All results should be entities
      for (const result of data.results) {
        assert.strictEqual(result.type, 'entity');
      }
    });
  });
});
