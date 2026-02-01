/**
 * Project Cordelia - SQLite Storage Provider
 *
 * Implements StorageProvider using better-sqlite3.
 * All data stored as encrypted blobs (Buffer -> BLOB).
 * Includes access tracking (R2-019).
 * Schema v2: FTS5, embedding cache, sqlite-vec (R2-012/R2-013).
 */

import Database from 'better-sqlite3';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import { createRequire } from 'module';
import type { StorageProvider, L2ItemMeta, GroupRow, GroupMemberRow, AccessLogEntry } from './storage.js';

const SCHEMA_VERSION = 6;

const SCHEMA_V1_SQL = `
CREATE TABLE IF NOT EXISTS l1_hot (
  user_id TEXT PRIMARY KEY,
  data BLOB NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS l2_items (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
  owner_id TEXT,
  visibility TEXT NOT NULL DEFAULT 'private'
    CHECK(visibility IN ('private', 'team', 'public')),
  data BLOB NOT NULL,
  last_accessed_at TEXT,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS l2_index (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  data BLOB NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  entry TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL,
  migrated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

const SCHEMA_V2_SQL = `
CREATE VIRTUAL TABLE IF NOT EXISTS l2_fts USING fts5(
  item_id UNINDEXED,
  name,
  content,
  tags,
  tokenize = 'porter unicode61'
);

CREATE TABLE IF NOT EXISTS embedding_cache (
  content_hash TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  dimensions INTEGER NOT NULL,
  vector BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (content_hash, provider, model)
);
`;

const _SCHEMA_V3_SQL = `
ALTER TABLE l2_items ADD COLUMN checksum TEXT;

CREATE TABLE IF NOT EXISTS integrity_canary (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  value TEXT NOT NULL,
  written_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;

export class SqliteStorageProvider implements StorageProvider {
  readonly name = 'sqlite';
  private db!: Database.Database;
  private dbPath: string;
  private vecLoaded = false;

  constructor(memoryRoot: string) {
    this.dbPath = path.join(memoryRoot, 'cordelia.db');
  }

  async initialize(): Promise<void> {
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(this.dbPath);

    // Set PRAGMAs
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    // Create v1 tables
    this.db.exec(SCHEMA_V1_SQL);

    // Check schema version and migrate
    const versionRow = this.db.prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number } | undefined;
    const currentVersion = versionRow?.version ?? 0;

    if (currentVersion < 1) {
      this.db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(SCHEMA_VERSION);
    }

    if (currentVersion < 2) {
      this.migrateToV2();
    }

    if (currentVersion < 3) {
      this.migrateToV3();
    }

    if (currentVersion < 4) {
      this.migrateToV4();
    }

    if (currentVersion < 5) {
      this.migrateToV5();
    }

    if (currentVersion < 6) {
      this.migrateToV6();
    }

    // Try to load sqlite-vec
    this.loadSqliteVec();
  }

  private migrateToV2(): void {
    this.db.exec(SCHEMA_V2_SQL);

    // Populate FTS from existing l2_index blob if present
    const indexRow = this.db.prepare('SELECT data FROM l2_index WHERE id = 1').get() as { data: Buffer } | undefined;
    if (indexRow) {
      try {
        const parsed = JSON.parse(indexRow.data.toString('utf-8'));
        // Handle both encrypted and plain index - only populate from plain
        if (parsed.entries && Array.isArray(parsed.entries)) {
          const insert = this.db.prepare(
            'INSERT OR REPLACE INTO l2_fts (item_id, name, content, tags) VALUES (?, ?, ?, ?)'
          );
          const tx = this.db.transaction(() => {
            for (const entry of parsed.entries) {
              insert.run(
                entry.id,
                entry.name || '',
                (entry.keywords || []).join(' '),
                (entry.tags || []).join(' ')
              );
            }
          });
          tx();
        }
      } catch {
        // Index might be encrypted or corrupt - skip FTS population
        // FTS will be populated on next write
      }
    }

    // Update schema version
    this.db.prepare('UPDATE schema_version SET version = ?, migrated_at = datetime(\'now\')').run(SCHEMA_VERSION);
  }

  private migrateToV3(): void {
    // Add checksum column (ignore if already exists from partial migration)
    try {
      this.db.exec('ALTER TABLE l2_items ADD COLUMN checksum TEXT');
    } catch {
      // Column may already exist
    }

    // Create integrity canary table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS integrity_canary (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        value TEXT NOT NULL,
        written_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Backfill checksums on existing items
    const items = this.db.prepare('SELECT id, data FROM l2_items WHERE checksum IS NULL').all() as Array<{ id: string; data: Buffer }>;
    if (items.length > 0) {
      const update = this.db.prepare('UPDATE l2_items SET checksum = ? WHERE id = ?');
      const tx = this.db.transaction(() => {
        for (const item of items) {
          const hash = crypto.createHash('sha256').update(item.data).digest('hex');
          update.run(hash, item.id);
        }
      });
      tx();
    }

    // Write initial canary value
    const canaryValue = crypto.randomBytes(32).toString('hex');
    this.db.prepare(`
      INSERT OR REPLACE INTO integrity_canary (id, value, written_at)
      VALUES (1, ?, datetime('now'))
    `).run(canaryValue);

    // Update schema version
    this.db.prepare('UPDATE schema_version SET version = ?, migrated_at = datetime(\'now\')').run(SCHEMA_VERSION);
  }

  private migrateToV4(): void {
    const tx = this.db.transaction(() => {
      // 1. Create groups table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS groups (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          culture TEXT NOT NULL DEFAULT '{}',
          security_policy TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
      `);

      // 2. Create group_members table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS group_members (
          group_id TEXT NOT NULL,
          entity_id TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'member'
            CHECK(role IN ('owner', 'admin', 'member', 'viewer')),
          posture TEXT DEFAULT 'active'
            CHECK(posture IN ('active', 'silent', 'emcon')),
          joined_at TEXT NOT NULL DEFAULT (datetime('now')),
          PRIMARY KEY (group_id, entity_id),
          FOREIGN KEY (group_id) REFERENCES groups(id),
          FOREIGN KEY (entity_id) REFERENCES l1_hot(user_id)
        );
      `);

      // 3. Create access_log table
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS access_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL DEFAULT (datetime('now')),
          entity_id TEXT NOT NULL,
          action TEXT NOT NULL,
          resource_type TEXT NOT NULL,
          resource_id TEXT,
          group_id TEXT,
          detail TEXT
        );
      `);

      // 4-7. Rebuild l2_items with new CHECK constraint and new columns
      // SQLite doesn't support ALTER CHECK, so we rebuild the table.
      this.db.exec(`
        CREATE TABLE l2_items_new (
          id TEXT PRIMARY KEY,
          type TEXT NOT NULL CHECK(type IN ('entity', 'session', 'learning')),
          owner_id TEXT,
          visibility TEXT NOT NULL DEFAULT 'private'
            CHECK(visibility IN ('private', 'group', 'public')),
          data BLOB NOT NULL,
          last_accessed_at TEXT,
          access_count INTEGER NOT NULL DEFAULT 0,
          checksum TEXT,
          group_id TEXT,
          author_id TEXT,
          key_version INTEGER DEFAULT 1,
          parent_id TEXT,
          is_copy INTEGER DEFAULT 0,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
      `);

      // Copy data, reconciling 'team' -> 'group' and backfilling author_id/key_version
      this.db.exec(`
        INSERT INTO l2_items_new (id, type, owner_id, visibility, data, last_accessed_at, access_count, checksum, author_id, key_version, is_copy, created_at, updated_at)
        SELECT id, type, owner_id,
          CASE WHEN visibility = 'team' THEN 'group' ELSE visibility END,
          data, last_accessed_at, access_count, checksum,
          owner_id,
          1,
          0,
          created_at, updated_at
        FROM l2_items;
      `);

      this.db.exec('DROP TABLE l2_items');
      this.db.exec('ALTER TABLE l2_items_new RENAME TO l2_items');

      // 8. Seed seed-drill group + founders (only insert members whose user_id exists in l1_hot)
      this.db.exec(`
        INSERT OR IGNORE INTO groups (id, name, culture, security_policy)
        VALUES (
          'seed-drill',
          'Seed Drill',
          '{"broadcast_eagerness":"moderate","ttl_default":null,"notification_policy":"notify","departure_policy":"standard"}',
          '{}'
        );
      `);

      const founders = ['russell', 'martin', 'bill'];
      const insertMember = this.db.prepare(
        'INSERT OR IGNORE INTO group_members (group_id, entity_id, role) VALUES (?, ?, ?)'
      );
      const checkUser = this.db.prepare('SELECT user_id FROM l1_hot WHERE user_id = ?');
      for (const f of founders) {
        if (checkUser.get(f)) {
          insertMember.run('seed-drill', f, 'owner');
        }
      }

      // 9. Create indexes
      this.db.exec(`
        CREATE INDEX IF NOT EXISTS idx_l2_items_group ON l2_items(group_id) WHERE group_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_l2_items_parent ON l2_items(parent_id) WHERE parent_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_l2_items_author ON l2_items(author_id) WHERE author_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_access_log_entity ON access_log(entity_id);
        CREATE INDEX IF NOT EXISTS idx_access_log_group ON access_log(group_id) WHERE group_id IS NOT NULL;
      `);

      // 10. Update schema version
      this.db.prepare('UPDATE schema_version SET version = ?, migrated_at = datetime(\'now\')').run(SCHEMA_VERSION);
    });
    tx();
  }

  private migrateToV5(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sync_state (
        group_id TEXT PRIMARY KEY,
        last_sync_at TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);
    this.db.prepare('UPDATE schema_version SET version = ?, migrated_at = datetime(\'now\')').run(SCHEMA_VERSION);
  }

  private migrateToV6(): void {
    // Add domain and ttl_expires_at columns (O(1) in SQLite, no table rebuild)
    try {
      this.db.exec(`ALTER TABLE l2_items ADD COLUMN domain TEXT CHECK(domain IS NULL OR domain IN ('value', 'procedural', 'interrupt'))`);
    } catch {
      // Column may already exist from partial migration
    }
    try {
      this.db.exec('ALTER TABLE l2_items ADD COLUMN ttl_expires_at TEXT');
    } catch {
      // Column may already exist
    }

    // Partial indexes for domain queries
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_l2_items_domain ON l2_items(domain) WHERE domain IS NOT NULL');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_l2_items_ttl ON l2_items(ttl_expires_at) WHERE ttl_expires_at IS NOT NULL');

    // Conservative backfill: sessions -> interrupt, learnings/entities -> procedural
    this.db.exec("UPDATE l2_items SET domain = 'interrupt' WHERE type = 'session' AND domain IS NULL");
    this.db.exec("UPDATE l2_items SET domain = 'procedural' WHERE type = 'learning' AND domain IS NULL");
    this.db.exec("UPDATE l2_items SET domain = 'procedural' WHERE type = 'entity' AND domain IS NULL");

    this.db.prepare('UPDATE schema_version SET version = ?, migrated_at = datetime(\'now\')').run(SCHEMA_VERSION);
  }

  private loadSqliteVec(): void {
    try {
      const require = createRequire(import.meta.url);
      const sqliteVec = require('sqlite-vec');
      sqliteVec.load(this.db);

      // Migrate from L2 (Euclidean) to cosine distance metric if needed.
      // vec0 tables don't expose their config, so check for the sentinel row.
      const needsMigration = (() => {
        try {
          const sentinel = this.db.prepare(
            "SELECT 1 FROM l2_vec_meta WHERE key = 'distance_metric' AND value = 'cosine'"
          ).get();
          return !sentinel;
        } catch {
          // l2_vec_meta doesn't exist yet — migration needed
          return true;
        }
      })();

      if (needsMigration) {
        console.error('Cordelia: migrating l2_vec to cosine distance metric');
        this.db.exec('DROP TABLE IF EXISTS l2_vec');
        this.db.exec(`
          CREATE VIRTUAL TABLE l2_vec USING vec0(
            item_id TEXT PRIMARY KEY,
            embedding float[768] distance_metric=cosine
          );
        `);
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS l2_vec_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          );
        `);
        this.db.prepare(
          "INSERT OR REPLACE INTO l2_vec_meta (key, value) VALUES ('distance_metric', 'cosine')"
        ).run();
      } else {
        this.db.exec(`
          CREATE VIRTUAL TABLE IF NOT EXISTS l2_vec USING vec0(
            item_id TEXT PRIMARY KEY,
            embedding float[768] distance_metric=cosine
          );
        `);
      }

      this.vecLoaded = true;
      console.error('Cordelia: sqlite-vec loaded successfully (cosine distance)');
    } catch (e) {
      console.error(`Cordelia: sqlite-vec not available: ${(e as Error).message}`);
      this.vecLoaded = false;
    }
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
    }
  }

  // -- L1 Hot Context --

  async readL1(userId: string): Promise<Buffer | null> {
    const row = this.db.prepare('SELECT data FROM l1_hot WHERE user_id = ?').get(userId) as { data: Buffer } | undefined;
    return row ? row.data : null;
  }

  async writeL1(userId: string, data: Buffer): Promise<void> {
    this.db.prepare(`
      INSERT INTO l1_hot (user_id, data, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        data = excluded.data,
        updated_at = datetime('now')
    `).run(userId, data);
  }

  async deleteL1(userId: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM l1_hot WHERE user_id = ?').run(userId);
    return result.changes > 0;
  }

  async listL1Users(): Promise<string[]> {
    const rows = this.db.prepare('SELECT user_id FROM l1_hot ORDER BY user_id').all() as Array<{ user_id: string }>;
    return rows.map((r) => r.user_id);
  }

  // -- L2 Items --

  async readL2Item(id: string): Promise<{ data: Buffer; type: string } | null> {
    const row = this.db.prepare('SELECT data, type FROM l2_items WHERE id = ?').get(id) as { data: Buffer; type: string } | undefined;
    return row ? { data: row.data, type: row.type } : null;
  }

  listL2ItemIds(): Array<{ id: string; type: string }> {
    return this.db.prepare('SELECT id, type FROM l2_items').all() as Array<{ id: string; type: string }>;
  }

  async writeL2Item(id: string, type: string, data: Buffer, meta: L2ItemMeta): Promise<void> {
    const checksum = crypto.createHash('sha256').update(data).digest('hex');
    this.db.prepare(`
      INSERT INTO l2_items (id, type, owner_id, visibility, data, checksum, group_id, author_id, key_version, parent_id, is_copy, domain, ttl_expires_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        type = excluded.type,
        owner_id = excluded.owner_id,
        visibility = excluded.visibility,
        data = excluded.data,
        checksum = excluded.checksum,
        group_id = excluded.group_id,
        author_id = excluded.author_id,
        key_version = excluded.key_version,
        parent_id = excluded.parent_id,
        is_copy = excluded.is_copy,
        domain = excluded.domain,
        ttl_expires_at = excluded.ttl_expires_at,
        updated_at = datetime('now')
    `).run(
      id, type,
      meta.owner_id || null,
      meta.visibility || 'private',
      data, checksum,
      meta.group_id || null,
      meta.author_id || null,
      meta.key_version ?? 1,
      meta.parent_id || null,
      meta.is_copy ? 1 : 0,
      meta.domain || null,
      meta.ttl_expires_at || null,
    );
  }

  async deleteL2Item(id: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM l2_items WHERE id = ?').run(id);
    if (result.changes > 0) {
      // Cascade to FTS and vec to prevent orphaned index entries
      this.db.prepare('DELETE FROM l2_fts WHERE item_id = ?').run(id);
      if (this.vecLoaded) {
        this.db.prepare('DELETE FROM l2_vec WHERE item_id = ?').run(id);
      }
    }
    return result.changes > 0;
  }

  // -- L2 Index --

  async readL2Index(): Promise<Buffer | null> {
    const row = this.db.prepare('SELECT data FROM l2_index WHERE id = 1').get() as { data: Buffer } | undefined;
    return row ? row.data : null;
  }

  async writeL2Index(data: Buffer): Promise<void> {
    this.db.prepare(`
      INSERT INTO l2_index (id, data, updated_at)
      VALUES (1, ?, datetime('now'))
      ON CONFLICT(id) DO UPDATE SET
        data = excluded.data,
        updated_at = datetime('now')
    `).run(data);
  }

  // -- FTS5 Full-Text Search --

  async ftsUpsert(itemId: string, name: string, content: string, tags: string): Promise<void> {
    // Delete existing entry first (FTS5 doesn't support ON CONFLICT)
    this.db.prepare('DELETE FROM l2_fts WHERE item_id = ?').run(itemId);
    this.db.prepare(
      'INSERT INTO l2_fts (item_id, name, content, tags) VALUES (?, ?, ?, ?)'
    ).run(itemId, name, content, tags);
  }

  async ftsDelete(itemId: string): Promise<void> {
    this.db.prepare('DELETE FROM l2_fts WHERE item_id = ?').run(itemId);
  }

  async ftsSearch(query: string, limit: number): Promise<Array<{ item_id: string; rank: number }>> {
    if (!query.trim()) return [];

    // Sanitize query: split on whitespace, wrap each token in double quotes with prefix matching
    const tokens = query.trim().split(/\s+/).filter(Boolean);
    const safeQuery = tokens.map((t) => `"${t.replace(/"/g, '')}"*`).join(' ');

    if (!safeQuery) return [];

    try {
      const rows = this.db.prepare(`
        SELECT item_id, rank
        FROM l2_fts
        WHERE l2_fts MATCH ?
        ORDER BY rank
        LIMIT ?
      `).all(safeQuery, limit) as Array<{ item_id: string; rank: number }>;
      return rows;
    } catch {
      // FTS query syntax error - return empty
      return [];
    }
  }

  // -- Vector Search (sqlite-vec) --

  async vecUpsert(itemId: string, embedding: Float32Array): Promise<void> {
    if (!this.vecLoaded) return;
    const buf = Buffer.from(embedding.buffer, embedding.byteOffset, embedding.byteLength);
    // Delete then insert (vec0 doesn't support ON CONFLICT)
    this.db.prepare('DELETE FROM l2_vec WHERE item_id = ?').run(itemId);
    this.db.prepare('INSERT INTO l2_vec (item_id, embedding) VALUES (?, ?)').run(itemId, buf);
  }

  async vecDelete(itemId: string): Promise<void> {
    if (!this.vecLoaded) return;
    this.db.prepare('DELETE FROM l2_vec WHERE item_id = ?').run(itemId);
  }

  async vecSearch(embedding: Float32Array, limit: number): Promise<Array<{ item_id: string; distance: number }>> {
    if (!this.vecLoaded) return [];
    const buf = Buffer.from(embedding.buffer, embedding.byteOffset, embedding.byteLength);
    try {
      const rows = this.db.prepare(`
        SELECT item_id, distance
        FROM l2_vec
        WHERE embedding MATCH ?
        ORDER BY distance
        LIMIT ?
      `).all(buf, limit) as Array<{ item_id: string; distance: number }>;
      return rows;
    } catch {
      return [];
    }
  }

  vecAvailable(): boolean {
    return this.vecLoaded;
  }

  // -- Embedding Cache --

  async getEmbedding(contentHash: string, provider: string, model: string): Promise<Buffer | null> {
    const row = this.db.prepare(
      'SELECT vector FROM embedding_cache WHERE content_hash = ? AND provider = ? AND model = ?'
    ).get(contentHash, provider, model) as { vector: Buffer } | undefined;
    return row ? row.vector : null;
  }

  async putEmbedding(contentHash: string, provider: string, model: string, dimensions: number, vector: Buffer): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO embedding_cache (content_hash, provider, model, dimensions, vector)
      VALUES (?, ?, ?, ?, ?)
    `).run(contentHash, provider, model, dimensions, vector);
  }

  // -- Access Tracking --

  async recordAccess(id: string): Promise<void> {
    this.db.prepare(`
      UPDATE l2_items
      SET access_count = access_count + 1,
          last_accessed_at = datetime('now')
      WHERE id = ?
    `).run(id);
  }

  async getAccessStats(id: string): Promise<{ access_count: number; last_accessed_at: string | null } | null> {
    const row = this.db.prepare(
      'SELECT access_count, last_accessed_at FROM l2_items WHERE id = ?'
    ).get(id) as { access_count: number; last_accessed_at: string | null } | undefined;

    return row || null;
  }

  // -- Prefetch (R3-012) --

  async getRecentItems(entityId: string, groupIds: string[], limit: number): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null; domain: string | null }>> {
    // Build query: private items owned by entity + items in specified groups
    // Ordered by last_accessed_at DESC (most recently accessed first)
    const placeholders = groupIds.map(() => '?').join(',');
    const params: (string | number)[] = [];

    let sql = `SELECT id, type, group_id, last_accessed_at, domain FROM l2_items WHERE (`;

    // Private items owned by this entity
    sql += `(visibility = 'private' AND owner_id = ?)`;
    params.push(entityId);

    // Group items in specified groups
    if (groupIds.length > 0) {
      sql += ` OR (visibility = 'group' AND group_id IN (${placeholders}))`;
      params.push(...groupIds);
    }

    sql += `) ORDER BY last_accessed_at DESC NULLS LAST LIMIT ?`;
    params.push(limit);

    return this.db.prepare(sql).all(...params) as Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null; domain: string | null }>;
  }

  // -- Audit --

  async appendAudit(line: string): Promise<void> {
    this.db.prepare('INSERT INTO audit (entry) VALUES (?)').run(line);
  }

  // -- Backup & Restore --

  async backup(destPath: string): Promise<{ size: number; duration_ms: number }> {
    const start = Date.now();
    await this.db.backup(destPath);
    const stat = fs.statSync(destPath);
    return { size: stat.size, duration_ms: Date.now() - start };
  }

  async restore(srcPath: string, opts?: { dryRun?: boolean }): Promise<{ items: number; schemaVersion: number }> {
    // Verify source exists
    if (!fs.existsSync(srcPath)) {
      throw new Error(`Backup file not found: ${srcPath}`);
    }

    // Open source and run integrity check
    const srcDb = new Database(srcPath, { readonly: true });
    try {
      const pragmaResult = srcDb.pragma('integrity_check') as Array<{ integrity_check: string }>;
      if (pragmaResult[0]?.integrity_check !== 'ok') {
        throw new Error(`Source database failed integrity check: ${pragmaResult[0]?.integrity_check}`);
      }

      const versionRow = srcDb.prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number } | undefined;
      const schemaVersion = versionRow?.version ?? 0;

      const itemCount = srcDb.prepare('SELECT COUNT(*) as cnt FROM l2_items').get() as { cnt: number };
      const items = itemCount.cnt;

      if (opts?.dryRun) {
        return { items, schemaVersion };
      }
    } finally {
      srcDb.close();
    }

    // Close current DB, copy source over it, re-open
    this.db.close();
    fs.copyFileSync(srcPath, this.dbPath);

    // Remove WAL/SHM files if they exist from old DB
    for (const suffix of ['-wal', '-shm']) {
      const walPath = this.dbPath + suffix;
      if (fs.existsSync(walPath)) {
        fs.unlinkSync(walPath);
      }
    }

    // Re-initialize (triggers migrations if needed)
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');

    // Check schema version and migrate
    const versionRow = this.db.prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number } | undefined;
    const currentVersion = versionRow?.version ?? 0;

    if (currentVersion < 2) {
      this.migrateToV2();
    }
    if (currentVersion < 3) {
      this.migrateToV3();
    }
    if (currentVersion < 4) {
      this.migrateToV4();
    }
    if (currentVersion < 5) {
      this.migrateToV5();
    }
    if (currentVersion < 6) {
      this.migrateToV6();
    }

    // Rebuild FTS from l2_items
    try {
      this.db.exec('DELETE FROM l2_fts');
    } catch {
      // FTS table may not exist yet (handled by migration)
    }

    // Reload sqlite-vec
    this.loadSqliteVec();

    const itemCount = this.db.prepare('SELECT COUNT(*) as cnt FROM l2_items').get() as { cnt: number };
    const finalVersion = this.db.prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number };

    return { items: itemCount.cnt, schemaVersion: finalVersion.version };
  }

  async integrityCheck(): Promise<{ ok: boolean; errors: string[] }> {
    const errors: string[] = [];

    // SQLite PRAGMA integrity_check
    try {
      const pragmaResult = this.db.pragma('integrity_check') as Array<{ integrity_check: string }>;
      if (pragmaResult[0]?.integrity_check !== 'ok') {
        errors.push(`PRAGMA integrity_check: ${pragmaResult[0]?.integrity_check}`);
      }
    } catch (e) {
      errors.push(`PRAGMA integrity_check failed: ${(e as Error).message}`);
    }

    // SQLite PRAGMA foreign_key_check
    try {
      const fkResult = this.db.pragma('foreign_key_check') as Array<Record<string, unknown>>;
      if (fkResult.length > 0) {
        errors.push(`Foreign key violations: ${fkResult.length}`);
      }
    } catch (e) {
      errors.push(`PRAGMA foreign_key_check failed: ${(e as Error).message}`);
    }

    // Validate L2 item checksums
    try {
      const items = this.db.prepare('SELECT id, data, checksum FROM l2_items WHERE checksum IS NOT NULL').all() as Array<{ id: string; data: Buffer; checksum: string }>;
      for (const item of items) {
        const computed = crypto.createHash('sha256').update(item.data).digest('hex');
        if (computed !== item.checksum) {
          errors.push(`Checksum mismatch for item ${item.id}: expected ${item.checksum}, got ${computed}`);
        }
      }
    } catch (e) {
      errors.push(`Checksum validation failed: ${(e as Error).message}`);
    }

    // Validate canary
    try {
      const canary = this.db.prepare('SELECT value FROM integrity_canary WHERE id = 1').get() as { value: string } | undefined;
      if (!canary) {
        errors.push('Integrity canary missing');
      }
    } catch (e) {
      errors.push(`Canary check failed: ${(e as Error).message}`);
    }

    return { ok: errors.length === 0, errors };
  }

  // -- Groups --

  async createGroup(id: string, name: string, culture: string, securityPolicy: string): Promise<void> {
    this.db.prepare(`
      INSERT INTO groups (id, name, culture, security_policy)
      VALUES (?, ?, ?, ?)
    `).run(id, name, culture, securityPolicy);
  }

  async readGroup(id: string): Promise<GroupRow | null> {
    const row = this.db.prepare('SELECT * FROM groups WHERE id = ?').get(id) as GroupRow | undefined;
    return row || null;
  }

  async listGroups(): Promise<GroupRow[]> {
    return this.db.prepare('SELECT * FROM groups ORDER BY name').all() as GroupRow[];
  }

  async deleteGroup(id: string): Promise<boolean> {
    // Delete members first (FK constraint)
    this.db.prepare('DELETE FROM group_members WHERE group_id = ?').run(id);
    const result = this.db.prepare('DELETE FROM groups WHERE id = ?').run(id);
    return result.changes > 0;
  }

  async addMember(groupId: string, entityId: string, role: string): Promise<void> {
    this.db.prepare(`
      INSERT INTO group_members (group_id, entity_id, role)
      VALUES (?, ?, ?)
    `).run(groupId, entityId, role);
  }

  async removeMember(groupId: string, entityId: string): Promise<boolean> {
    const result = this.db.prepare('DELETE FROM group_members WHERE group_id = ? AND entity_id = ?').run(groupId, entityId);
    return result.changes > 0;
  }

  async listMembers(groupId: string): Promise<GroupMemberRow[]> {
    return this.db.prepare('SELECT * FROM group_members WHERE group_id = ? ORDER BY entity_id').all(groupId) as GroupMemberRow[];
  }

  async getMembership(groupId: string, entityId: string): Promise<GroupMemberRow | null> {
    const row = this.db.prepare('SELECT * FROM group_members WHERE group_id = ? AND entity_id = ?').get(groupId, entityId) as GroupMemberRow | undefined;
    return row || null;
  }

  async updateMemberPosture(groupId: string, entityId: string, posture: string): Promise<boolean> {
    const result = this.db.prepare('UPDATE group_members SET posture = ? WHERE group_id = ? AND entity_id = ?').run(posture, groupId, entityId);
    return result.changes > 0;
  }

  async logAccess(entry: AccessLogEntry): Promise<void> {
    this.db.prepare(`
      INSERT INTO access_log (entity_id, action, resource_type, resource_id, group_id, detail)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(entry.entity_id, entry.action, entry.resource_type, entry.resource_id || null, entry.group_id || null, entry.detail || null);
  }

  async listGroupItems(groupId: string, limit = 100): Promise<Array<{ id: string; type: string; data: Buffer }>> {
    return this.db.prepare(
      'SELECT id, type, data FROM l2_items WHERE group_id = ? ORDER BY updated_at DESC LIMIT ?'
    ).all(groupId, limit) as Array<{ id: string; type: string; data: Buffer }>;
  }

  async readL2ItemMeta(id: string): Promise<{ owner_id: string | null; visibility: string; group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number; domain: string | null; ttl_expires_at: string | null } | null> {
    const row = this.db.prepare(
      'SELECT owner_id, visibility, group_id, author_id, key_version, parent_id, is_copy, domain, ttl_expires_at FROM l2_items WHERE id = ?'
    ).get(id) as { owner_id: string | null; visibility: string; group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number; domain: string | null; ttl_expires_at: string | null } | undefined;
    return row || null;
  }

  // -- Domain-aware queries (R3-domain) --

  async getItemsByDomain(entityId: string, groupIds: string[], domain: string, limit: number): Promise<Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }>> {
    const placeholders = groupIds.map(() => '?').join(',');
    const params: (string | number)[] = [];

    let sql = `SELECT id, type, domain, group_id, last_accessed_at FROM l2_items WHERE domain = ? AND (`;
    params.push(domain);

    sql += `(visibility = 'private' AND owner_id = ?)`;
    params.push(entityId);

    if (groupIds.length > 0) {
      sql += ` OR (visibility = 'group' AND group_id IN (${placeholders}))`;
      params.push(...groupIds);
    }

    // Order: value by last_accessed_at, procedural by access_count DESC, interrupt by last_accessed_at DESC
    if (domain === 'procedural') {
      sql += `) ORDER BY access_count DESC, last_accessed_at DESC NULLS LAST LIMIT ?`;
    } else {
      sql += `) ORDER BY last_accessed_at DESC NULLS LAST LIMIT ?`;
    }
    params.push(limit);

    return this.db.prepare(sql).all(...params) as Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }>;
  }

  async getExpiredItems(now: string): Promise<Array<{ id: string; domain: string | null }>> {
    return this.db.prepare(
      `SELECT id, domain FROM l2_items WHERE ttl_expires_at IS NOT NULL AND ttl_expires_at < ? AND (domain IS NULL OR domain != 'value')`
    ).all(now) as Array<{ id: string; domain: string | null }>;
  }

  async getEvictableProceduralItems(cap: number): Promise<string[]> {
    const rows = this.db.prepare(`
      SELECT id FROM l2_items
      WHERE domain = 'procedural'
      ORDER BY access_count ASC, last_accessed_at ASC NULLS FIRST
      LIMIT max(0, (SELECT COUNT(*) FROM l2_items WHERE domain = 'procedural') - ?)
    `).all(cap) as Array<{ id: string }>;
    return rows.map((r) => r.id);
  }

  async updateTtl(id: string, ttlExpiresAt: string): Promise<void> {
    this.db.prepare('UPDATE l2_items SET ttl_expires_at = ? WHERE id = ?').run(ttlExpiresAt, id);
  }

  async getDomainCounts(): Promise<{ value: number; procedural: number; interrupt: number; unclassified: number }> {
    const rows = this.db.prepare(
      'SELECT domain, COUNT(*) as cnt FROM l2_items GROUP BY domain'
    ).all() as Array<{ domain: string | null; cnt: number }>;

    const counts = { value: 0, procedural: 0, interrupt: 0, unclassified: 0 };
    for (const row of rows) {
      if (row.domain === 'value') counts.value = row.cnt;
      else if (row.domain === 'procedural') counts.procedural = row.cnt;
      else if (row.domain === 'interrupt') counts.interrupt = row.cnt;
      else counts.unclassified = row.cnt;
    }
    return counts;
  }

  // -- Canary --

  getCanaryValue(): string | null {
    try {
      const row = this.db.prepare('SELECT value FROM integrity_canary WHERE id = 1').get() as { value: string } | undefined;
      return row?.value ?? null;
    } catch {
      return null;
    }
  }

  writeCanary(value: string): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO integrity_canary (id, value, written_at)
      VALUES (1, ?, datetime('now'))
    `).run(value);
  }

  // -- Utility --

  getDatabase(): Database.Database {
    return this.db;
  }

  /**
   * Check if FTS5 tables are populated.
   */
  hasFtsData(): boolean {
    try {
      const row = this.db.prepare('SELECT COUNT(*) as cnt FROM l2_fts').get() as { cnt: number };
      return row.cnt > 0;
    } catch {
      return false;
    }
  }

  /**
   * Count rows in l2_items table.
   */
  itemCount(): number {
    try {
      const row = this.db.prepare('SELECT COUNT(*) as cnt FROM l2_items').get() as { cnt: number };
      return row.cnt;
    } catch {
      return 0;
    }
  }

  /**
   * Count rows in l2_fts table.
   */
  ftsCount(): number {
    try {
      const row = this.db.prepare('SELECT COUNT(*) as cnt FROM l2_fts').get() as { cnt: number };
      return row.cnt;
    } catch {
      return 0;
    }
  }

  /**
   * Count rows in embedding_cache table.
   */
  embeddingCacheCount(): number {
    try {
      const row = this.db.prepare('SELECT COUNT(*) as cnt FROM embedding_cache').get() as { cnt: number };
      return row.cnt;
    } catch {
      return 0;
    }
  }

  /**
   * Count rows in l2_vec table.
   */
  vecCount(): number {
    if (!this.vecLoaded) return 0;
    try {
      const row = this.db.prepare('SELECT COUNT(*) as cnt FROM l2_vec').get() as { cnt: number };
      return row.cnt;
    } catch {
      return 0;
    }
  }

  // -- Sync State (node bridge) --

  getSyncTimestamp(groupId: string): string | null {
    try {
      const row = this.db.prepare('SELECT last_sync_at FROM sync_state WHERE group_id = ?').get(groupId) as { last_sync_at: string } | undefined;
      return row?.last_sync_at ?? null;
    } catch {
      return null;
    }
  }

  setSyncTimestamp(groupId: string, timestamp: string): void {
    this.db.prepare(`
      INSERT INTO sync_state (group_id, last_sync_at, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(group_id) DO UPDATE SET
        last_sync_at = excluded.last_sync_at,
        updated_at = datetime('now')
    `).run(groupId, timestamp);
  }
}
