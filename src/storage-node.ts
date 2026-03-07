/**
 * Project Cordelia - Node HTTP Storage Provider
 *
 * Implements StorageProvider by delegating L1/L2/group operations to
 * the cordelia-node Rust HTTP API (localhost:9473).
 *
 * Local SQLite is used ONLY for proxy-side concerns: FTS indexing,
 * vec search, embeddings, backup, audit, and domain/TTL queries.
 *
 * L1/L2/group operations fail fast if the node is unreachable.
 * No silent SQLite fallback -- callers see the error immediately.
 */

import type {
  StorageProvider,
  L2ItemMeta,
  GroupRow,
  GroupMemberRow,
  AccessLogEntry,
} from './storage.js';
import { NodeClient, NodeClientError } from './node-client.js';
import type { GroupMemberInfo } from './node-client.js';
import { encryptL1, decryptL1 } from './group-keys.js';

const HEALTH_CHECK_INTERVAL_MS = 30_000;

export class NodeStorageProvider implements StorageProvider {
  name = 'node';

  private readonly client: NodeClient;
  private local: StorageProvider;
  private _nodeAvailable = false;
  private _lastHealthCheck = 0;

  constructor(nodeUrl: string, token: string, memoryRoot: string) {
    this.client = new NodeClient({ baseUrl: nodeUrl, token });
    // Lazily set in initialize()
    this.local = null as unknown as StorageProvider;
    this._memoryRoot = memoryRoot;
  }

  private readonly _memoryRoot: string;

  async initialize(): Promise<void> {
    // Initialize local SQLite for proxy-side concerns (FTS, vec, embeddings, backup)
    const { SqliteStorageProvider } = await import('./storage-sqlite.js');
    this.local = new SqliteStorageProvider(this._memoryRoot);
    await this.local.initialize();

    // Verify node is reachable at startup
    this._nodeAvailable = await this.client.isAvailable();
    this._lastHealthCheck = Date.now();
    if (!this._nodeAvailable) {
      console.warn('[storage-node] Node unreachable at startup -- L1/L2/group ops will fail until node is available');
    }
  }

  async close(): Promise<void> {
    await this.local.close();
  }

  // ====================================================================
  // Health check with caching
  // ====================================================================

  private async nodeAvailable(): Promise<boolean> {
    const now = Date.now();
    if (now - this._lastHealthCheck > HEALTH_CHECK_INTERVAL_MS) {
      this._nodeAvailable = await this.client.isAvailable();
      this._lastHealthCheck = now;
    }
    return this._nodeAvailable;
  }

  /** Throw if node is unreachable. Used for L1/L2/group ops that must not silently fallback. */
  private async requireNode(): Promise<void> {
    if (!(await this.nodeAvailable())) {
      throw new Error('Cordelia node is unreachable. L1/L2/group operations require a running node.');
    }
  }

  // ====================================================================
  // L1 Hot Context -> node or local fallback
  // ====================================================================

  async readL1(userId: string): Promise<Buffer | null> {
    await this.requireNode();
    try {
      const data = await this.client.readL1(userId);
      if (data === null) return null;
      // Decrypt if encrypted (transparent: plaintext data passes through unchanged)
      const decrypted = await decryptL1(data as Record<string, unknown>);
      return Buffer.from(JSON.stringify(decrypted));
    } catch (e) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      this._nodeAvailable = false;
      throw e;
    }
  }

  async writeL1(userId: string, data: Buffer): Promise<void> {
    await this.requireNode();
    const parsed = JSON.parse(data.toString('utf-8'));
    try {
      // Encrypt with personal group PSK before sending to node
      const encrypted = await encryptL1(parsed);
      await this.client.writeL1(userId, encrypted ?? parsed);
    } catch (e) {
      if (!(e instanceof SyntaxError)) this._nodeAvailable = false;
      throw e;
    }
  }

  async deleteL1(userId: string): Promise<boolean> {
    await this.requireNode();
    try {
      return await this.client.deleteL1(userId);
    } catch (e) {
      if (e instanceof NodeClientError && e.status === 0) this._nodeAvailable = false;
      throw e;
    }
  }

  async listL1Users(): Promise<string[]> {
    await this.requireNode();
    try {
      return await this.client.listL1Users();
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  // ====================================================================
  // L2 Items -> node or local fallback
  // ====================================================================

  async readL2Item(id: string): Promise<{ data: Buffer; type: string } | null> {
    await this.requireNode();
    try {
      const res = await this.client.readL2Item(id);
      if (!res) return null;
      return {
        data: Buffer.from(JSON.stringify(res.data)),
        type: res.type,
      };
    } catch (e) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      this._nodeAvailable = false;
      throw e;
    }
  }

  async writeL2Item(id: string, type: string, data: Buffer, meta: L2ItemMeta): Promise<void> {
    await this.requireNode();
    const parsed = JSON.parse(data.toString('utf-8'));
    try {
      await this.client.writeL2Item(id, type, parsed, {
        owner_id: meta.owner_id,
        visibility: meta.visibility,
        group_id: meta.group_id,
        author_id: meta.author_id,
        key_version: meta.key_version,
        parent_id: meta.parent_id,
        is_copy: meta.is_copy,
        domain: meta.domain,
        ttl_expires_at: meta.ttl_expires_at,
      });
    } catch (e) {
      if (!(e instanceof SyntaxError)) this._nodeAvailable = false;
      throw e;
    }
  }

  async deleteL2Item(id: string): Promise<boolean> {
    await this.requireNode();
    try {
      return await this.client.deleteL2Item(id);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  // ====================================================================
  // L2 Index -> node or local fallback
  // ====================================================================

  async readL2Index(): Promise<Buffer | null> {
    // L2 index is proxy-managed (contains embedding vectors etc.)
    // Always local
    return this.local.readL2Index();
  }

  async writeL2Index(data: Buffer): Promise<void> {
    return this.local.writeL2Index(data);
  }

  // ====================================================================
  // Access tracking -> local (proxy-side concern)
  // ====================================================================

  async recordAccess(id: string): Promise<void> {
    return this.local.recordAccess(id);
  }

  async getAccessStats(id: string): Promise<{ access_count: number; last_accessed_at: string | null } | null> {
    return this.local.getAccessStats(id);
  }

  // ====================================================================
  // FTS -> node for search, local for index management
  // ====================================================================

  async ftsUpsert(itemId: string, name: string, content: string, tags: string): Promise<void> {
    // Always maintain local FTS index
    return this.local.ftsUpsert(itemId, name, content, tags);
  }

  async ftsDelete(itemId: string): Promise<void> {
    return this.local.ftsDelete(itemId);
  }

  async ftsSearch(query: string, limit: number): Promise<Array<{ item_id: string; rank: number }>> {
    // Always use local FTS -- local hybrid search (FTS5 BM25 + sqlite-vec) is
    // superior to node-side FTS which lacks vec and returns synthetic ranks.
    return this.local.ftsSearch(query, limit);
  }

  // ====================================================================
  // Vector search -> always local (proxy-side, embedding provider)
  // ====================================================================

  async vecUpsert(itemId: string, embedding: Float32Array): Promise<void> {
    return this.local.vecUpsert(itemId, embedding);
  }

  async vecDelete(itemId: string): Promise<void> {
    return this.local.vecDelete(itemId);
  }

  async vecSearch(embedding: Float32Array, limit: number): Promise<Array<{ item_id: string; distance: number }>> {
    return this.local.vecSearch(embedding, limit);
  }

  vecAvailable(): boolean {
    return this.local.vecAvailable();
  }

  // ====================================================================
  // Embedding cache -> always local
  // ====================================================================

  async getEmbedding(contentHash: string, provider: string, model: string): Promise<Buffer | null> {
    return this.local.getEmbedding(contentHash, provider, model);
  }

  async putEmbedding(contentHash: string, provider: string, model: string, dimensions: number, vector: Buffer): Promise<void> {
    return this.local.putEmbedding(contentHash, provider, model, dimensions, vector);
  }

  // ====================================================================
  // Groups -> node or local fallback
  // ====================================================================

  async createGroup(id: string, name: string, culture: string, securityPolicy: string): Promise<void> {
    await this.requireNode();
    try {
      await this.client.createGroup(id, name, culture, securityPolicy);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async readGroup(id: string): Promise<GroupRow | null> {
    await this.requireNode();
    try {
      const res = await this.client.readGroup(id);
      if (!res) return null;
      return res.group as GroupRow;
    } catch (e) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      this._nodeAvailable = false;
      throw e;
    }
  }

  async listGroups(): Promise<GroupRow[]> {
    await this.requireNode();
    try {
      return (await this.client.listGroups()) as GroupRow[];
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async deleteGroup(id: string): Promise<boolean> {
    await this.requireNode();
    try {
      return await this.client.deleteGroup(id);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async addMember(groupId: string, entityId: string, role: string): Promise<void> {
    await this.requireNode();
    try {
      await this.client.addMember(groupId, entityId, role);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async removeMember(groupId: string, entityId: string): Promise<boolean> {
    await this.requireNode();
    try {
      return await this.client.removeMember(groupId, entityId);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async listMembers(groupId: string): Promise<GroupMemberRow[]> {
    await this.requireNode();
    try {
      const res = await this.client.readGroup(groupId);
      if (!res) return [];
      return res.members.map((m: GroupMemberInfo) => ({
        group_id: m.group_id,
        entity_id: m.entity_id,
        role: m.role as GroupMemberRow['role'],
        posture: (m.posture ?? 'active') as GroupMemberRow['posture'],
        joined_at: m.joined_at,
      }));
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async getMembership(groupId: string, entityId: string): Promise<GroupMemberRow | null> {
    await this.requireNode();
    try {
      const res = await this.client.readGroup(groupId);
      if (!res) return null;
      const member = res.members.find((m: GroupMemberInfo) => m.entity_id === entityId);
      if (!member) return null;
      return {
        group_id: member.group_id,
        entity_id: member.entity_id,
        role: member.role as GroupMemberRow['role'],
        posture: (member.posture ?? 'active') as GroupMemberRow['posture'],
        joined_at: member.joined_at,
      };
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async updateMemberPosture(groupId: string, entityId: string, posture: string): Promise<boolean> {
    await this.requireNode();
    try {
      return await this.client.updateMemberPosture(groupId, entityId, posture);
    } catch (e) {
      this._nodeAvailable = false;
      throw e;
    }
  }

  async logAccess(entry: AccessLogEntry): Promise<void> {
    // Always local (audit is proxy-side concern)
    return this.local.logAccess(entry);
  }

  async listGroupItems(groupId: string, limit?: number): Promise<Array<{ id: string; type: string; data: Buffer }>> {
    // listGroupItems returns actual data blobs -- use local since node returns headers only
    return this.local.listGroupItems(groupId, limit);
  }

  async readL2ItemMeta(id: string): Promise<{
    owner_id: string | null;
    visibility: string;
    group_id: string | null;
    author_id: string | null;
    key_version: number;
    parent_id: string | null;
    is_copy: number;
    domain: string | null;
    ttl_expires_at: string | null;
  } | null> {
    await this.requireNode();
    try {
      const res = await this.client.readL2Item(id);
      if (!res) return null;
      return {
        owner_id: res.meta.owner_id,
        visibility: res.meta.visibility,
        group_id: res.meta.group_id,
        author_id: res.meta.author_id,
        key_version: res.meta.key_version,
        parent_id: res.meta.parent_id ?? null,
        is_copy: res.meta.is_copy ? 1 : 0,
        domain: res.meta.domain ?? null,
        ttl_expires_at: res.meta.ttl_expires_at ?? null,
      };
    } catch (e) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      this._nodeAvailable = false;
      throw e;
    }
  }

  // ====================================================================
  // Prefetch (R3-012)
  // ====================================================================

  async getRecentItems(entityId: string, groupIds: string[], limit: number): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null; domain: string | null }>> {
    return this.local.getRecentItems(entityId, groupIds, limit);
  }

  // ====================================================================
  // Domain-aware queries -> always local
  // ====================================================================

  async getItemsByDomain(entityId: string, groupIds: string[], domain: string, limit: number): Promise<Array<{ id: string; type: string; domain: string | null; group_id: string | null; last_accessed_at: string | null }>> {
    return this.local.getItemsByDomain(entityId, groupIds, domain, limit);
  }

  async getExpiredItems(now: string): Promise<Array<{ id: string; domain: string | null }>> {
    return this.local.getExpiredItems(now);
  }

  async getEvictableProceduralItems(cap: number): Promise<string[]> {
    return this.local.getEvictableProceduralItems(cap);
  }

  async updateTtl(id: string, ttlExpiresAt: string): Promise<void> {
    return this.local.updateTtl(id, ttlExpiresAt);
  }

  async getDomainCounts(): Promise<{ value: number; procedural: number; interrupt: number; unclassified: number }> {
    return this.local.getDomainCounts();
  }

  // ====================================================================
  // Audit -> always local
  // ====================================================================

  async appendAudit(line: string): Promise<void> {
    return this.local.appendAudit(line);
  }

  // ====================================================================
  // Backup & Restore -> always local
  // ====================================================================

  async backup(destPath: string): Promise<{ size: number; duration_ms: number }> {
    return this.local.backup(destPath);
  }

  async restore(srcPath: string, opts?: { dryRun?: boolean }): Promise<{ items: number; schemaVersion: number }> {
    return this.local.restore(srcPath, opts);
  }

  async integrityCheck(): Promise<{ ok: boolean; errors: string[] }> {
    return this.local.integrityCheck();
  }
}
