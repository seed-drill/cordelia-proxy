/**
 * Project Cordelia - Storage Provider Interface
 *
 * Thin abstraction over storage backends (JSON files, SQLite).
 * The storage layer works with opaque Buffers (encrypted blobs).
 * Crypto boundary sits above storage - storage never sees plaintext.
 */

export interface L2ItemMeta {
  type: 'entity' | 'session' | 'learning';
  owner_id?: string;
  visibility?: 'private' | 'group' | 'public';
  group_id?: string;
  author_id?: string;
  key_version?: number;
  parent_id?: string;
  is_copy?: boolean;
  domain?: 'value' | 'procedural' | 'interrupt';
  ttl_expires_at?: string;
}

export interface GroupRow {
  id: string;
  name: string;
  culture: string;
  security_policy: string;
  created_at: string;
  updated_at: string;
}

export interface GroupMemberRow {
  group_id: string;
  entity_id: string;
  role: 'owner' | 'admin' | 'member' | 'viewer';
  posture: 'active' | 'silent' | 'emcon';
  joined_at: string;
}

export interface AccessLogEntry {
  entity_id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  group_id?: string;
  detail?: string;
}

export interface StorageProvider {
  name: string;

  // L1 Hot Context
  readL1(userId: string): Promise<Buffer | null>;
  writeL1(userId: string, data: Buffer): Promise<void>;
  deleteL1(userId: string): Promise<boolean>;
  listL1Users(): Promise<string[]>;

  // L2 Items
  readL2Item(id: string): Promise<{ data: Buffer; type: string } | null>;
  writeL2Item(id: string, type: string, data: Buffer, meta: L2ItemMeta): Promise<void>;
  deleteL2Item(id: string): Promise<boolean>;

  // L2 Index (stored as encrypted blob, same as current)
  readL2Index(): Promise<Buffer | null>;
  writeL2Index(data: Buffer): Promise<void>;

  // Access tracking (R2-019)
  recordAccess(id: string): Promise<void>;
  getAccessStats(id: string): Promise<{ access_count: number; last_accessed_at: string | null } | null>;

  // FTS5 full-text search
  ftsUpsert(itemId: string, name: string, content: string, tags: string): Promise<void>;
  ftsDelete(itemId: string): Promise<void>;
  ftsSearch(query: string, limit: number): Promise<Array<{ item_id: string; rank: number }>>;

  // Vector search (sqlite-vec)
  vecUpsert(itemId: string, embedding: Float32Array): Promise<void>;
  vecDelete(itemId: string): Promise<void>;
  vecSearch(embedding: Float32Array, limit: number): Promise<Array<{ item_id: string; distance: number }>>;
  vecAvailable(): boolean;

  // Embedding cache
  getEmbedding(contentHash: string, provider: string, model: string): Promise<Buffer | null>;
  putEmbedding(contentHash: string, provider: string, model: string, dimensions: number, vector: Buffer): Promise<void>;

  // Groups
  createGroup(id: string, name: string, culture: string, securityPolicy: string): Promise<void>;
  readGroup(id: string): Promise<GroupRow | null>;
  listGroups(): Promise<GroupRow[]>;
  deleteGroup(id: string): Promise<boolean>;
  addMember(groupId: string, entityId: string, role: string): Promise<void>;
  removeMember(groupId: string, entityId: string): Promise<boolean>;
  listMembers(groupId: string): Promise<GroupMemberRow[]>;
  getMembership(groupId: string, entityId: string): Promise<GroupMemberRow | null>;
  updateMemberPosture(groupId: string, entityId: string, posture: string): Promise<boolean>;
  logAccess(entry: AccessLogEntry): Promise<void>;
  listGroupItems(groupId: string, limit?: number): Promise<Array<{ id: string; type: string; data: Buffer }>>;

  // Prefetch (R3-012)
  getRecentItems(entityId: string, groupIds: string[], limit: number): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null; domain: string | null }>>;

  // Domain-aware queries (R3-domain)
  getItemsByDomain(entityId: string, groupIds: string[], domain: string, limit: number): Promise<Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }>>;
  getExpiredItems(now: string): Promise<Array<{ id: string; domain: string | null }>>;
  getEvictableProceduralItems(cap: number): Promise<string[]>;
  updateTtl(id: string, ttlExpiresAt: string): Promise<void>;
  getDomainCounts(): Promise<{ value: number; procedural: number; interrupt: number; unclassified: number }>;
  readL2ItemMeta(id: string): Promise<{ owner_id: string | null; visibility: string; group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number; domain: string | null; ttl_expires_at: string | null } | null>;

  // Audit
  appendAudit(line: string): Promise<void>;

  // Backup & Restore (R2-004)
  backup(destPath: string): Promise<{ size: number; duration_ms: number }>;
  restore(srcPath: string, opts?: { dryRun?: boolean }): Promise<{ items: number; schemaVersion: number }>;
  integrityCheck(): Promise<{ ok: boolean; errors: string[] }>;

  // Lifecycle
  initialize(): Promise<void>;
  close(): Promise<void>;
}

let activeProvider: StorageProvider | null = null;

/**
 * Get the active storage provider singleton.
 * Must call setStorageProvider() or initStorageProvider() before first use.
 */
export function getStorageProvider(): StorageProvider {
  if (!activeProvider) {
    throw new Error('Storage provider not initialized. Call initStorageProvider() first.');
  }
  return activeProvider;
}

/**
 * Set the active storage provider (for testing or manual configuration).
 */
export function setStorageProvider(provider: StorageProvider): void {
  activeProvider = provider;
}

/**
 * Initialize the storage provider based on CORDELIA_STORAGE env var.
 * Returns the initialized provider.
 */
/**
 * Resolve node URL and token from config.toml and file fallbacks.
 */
async function resolveNodeConfig(): Promise<{ url: string; token: string }> {
  let url = process.env.CORDELIA_NODE_URL || '';
  let token = process.env.CORDELIA_NODE_TOKEN || '';

  if (!url || !token) {
    try {
      const fs = await import('fs/promises');
      const path = await import('path');
      const os = await import('os');

      // Read config.toml for node URL
      if (!url) {
        try {
          const configPath = path.join(os.homedir(), '.cordelia', 'config.toml');
          const content = await fs.readFile(configPath, 'utf-8');
          // Simple TOML extraction for [node].api_addr
          const nodeMatch = content.match(/\[node\][\s\S]*?api_addr\s*=\s*"?([^"\n]+)"?/);
          if (nodeMatch) {
            const addr = nodeMatch[1].trim();
            const transport = content.match(/\[node\][\s\S]*?api_transport\s*=\s*"?([^"\n]+)"?/);
            const proto = transport?.[1]?.trim() === 'https' ? 'https' : 'http';
            url = `${proto}://${addr}`;
          }
        } catch {
          // config.toml not found -- use default
        }
      }

      // Read token from file
      if (!token) {
        try {
          const tokenPath = path.join(os.homedir(), '.cordelia', 'node-token');
          token = (await fs.readFile(tokenPath, 'utf-8')).trim();
        } catch {
          // token file not found
        }
      }
    } catch {
      // fs/path/os import failed -- shouldn't happen
    }
  }

  return { url: url || 'http://127.0.0.1:9473', token };
}

export async function initStorageProvider(memoryRoot: string): Promise<StorageProvider> {
  const storageType = process.env.CORDELIA_STORAGE || 'sqlite';

  let provider: StorageProvider;

  if (storageType === 'node') {
    const { NodeStorageProvider } = await import('./storage-node.js');
    const { url: nodeUrl, token: nodeToken } = await resolveNodeConfig();
    provider = new NodeStorageProvider(nodeUrl, nodeToken, memoryRoot);
  } else if (storageType === 'sqlite') {
    const { SqliteStorageProvider } = await import('./storage-sqlite.js');
    provider = new SqliteStorageProvider(memoryRoot);
  } else {
    const { JsonStorageProvider } = await import('./storage-json.js');
    provider = new JsonStorageProvider(memoryRoot);
  }

  await provider.initialize();
  activeProvider = provider;
  return provider;
}
