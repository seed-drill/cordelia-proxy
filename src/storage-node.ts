/**
 * Project Cordelia - Node HTTP Storage Provider
 *
 * Implements StorageProvider by delegating L1/L2/group operations to
 * the cordelia-node Rust HTTP API (localhost:9473).
 *
 * Local-only operations (FTS indexing, vec search, embeddings, backup,
 * audit) stay on the local SQLite provider as fallback.
 *
 * FR-PRX-006: Falls back to local SQLite if node is unreachable.
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

const HEALTH_CHECK_INTERVAL_MS = 30_000;

export class NodeStorageProvider implements StorageProvider {
  name = 'node';

  private client: NodeClient;
  private local: StorageProvider;
  private _nodeAvailable = false;
  private _lastHealthCheck = 0;

  constructor(nodeUrl: string, token: string, memoryRoot: string) {
    this.client = new NodeClient({ baseUrl: nodeUrl, token });
    // Lazily set in initialize()
    this.local = null as unknown as StorageProvider;
    this._memoryRoot = memoryRoot;
  }

  private _memoryRoot: string;

  async initialize(): Promise<void> {
    // Initialize local SQLite as fallback for local-only ops and when node is down
    const { SqliteStorageProvider } = await import('./storage-sqlite.js');
    this.local = new SqliteStorageProvider(this._memoryRoot);
    await this.local.initialize();

    // Initial health check
    this._nodeAvailable = await this.client.isAvailable();
    this._lastHealthCheck = Date.now();
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

  private async useNode(): Promise<boolean> {
    return this.nodeAvailable();
  }

  // ====================================================================
  // L1 Hot Context -> node or local fallback
  // ====================================================================

  async readL1(userId: string): Promise<Buffer | null> {
    if (await this.useNode()) {
      try {
        const data = await this.client.readL1(userId);
        if (data === null) return null;
        return Buffer.from(JSON.stringify(data));
      } catch (e) {
        if (e instanceof NodeClientError && e.status === 404) return null;
        this._nodeAvailable = false;
      }
    }
    return this.local.readL1(userId);
  }

  async writeL1(userId: string, data: Buffer): Promise<void> {
    if (await this.useNode()) {
      try {
        const parsed = JSON.parse(data.toString('utf-8'));
        await this.client.writeL1(userId, parsed);
        return;
      } catch (e) {
        if (!(e instanceof SyntaxError)) this._nodeAvailable = false;
      }
    }
    return this.local.writeL1(userId, data);
  }

  async deleteL1(userId: string): Promise<boolean> {
    // No delete endpoint on node yet -- use local
    return this.local.deleteL1(userId);
  }

  async listL1Users(): Promise<string[]> {
    // No list endpoint on node yet -- use local
    return this.local.listL1Users();
  }

  // ====================================================================
  // L2 Items -> node or local fallback
  // ====================================================================

  async readL2Item(id: string): Promise<{ data: Buffer; type: string } | null> {
    if (await this.useNode()) {
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
      }
    }
    return this.local.readL2Item(id);
  }

  async writeL2Item(id: string, type: string, data: Buffer, meta: L2ItemMeta): Promise<void> {
    if (await this.useNode()) {
      try {
        const parsed = JSON.parse(data.toString('utf-8'));
        await this.client.writeL2Item(id, type, parsed, {
          owner_id: meta.owner_id,
          visibility: meta.visibility,
          group_id: meta.group_id,
          author_id: meta.author_id,
          key_version: meta.key_version,
          parent_id: meta.parent_id,
          is_copy: meta.is_copy,
        });
        return;
      } catch (e) {
        if (!(e instanceof SyntaxError)) this._nodeAvailable = false;
      }
    }
    return this.local.writeL2Item(id, type, data, meta);
  }

  async deleteL2Item(id: string): Promise<boolean> {
    if (await this.useNode()) {
      try {
        return await this.client.deleteL2Item(id);
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.deleteL2Item(id);
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
    if (await this.useNode()) {
      try {
        const ids = await this.client.ftsSearch(query, limit);
        // Node returns just IDs, we assign synthetic ranks
        return ids.map((id, i) => ({ item_id: id, rank: -(i + 1) }));
      } catch {
        this._nodeAvailable = false;
      }
    }
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
    if (await this.useNode()) {
      try {
        await this.client.createGroup(id, name, culture, securityPolicy);
        return;
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.createGroup(id, name, culture, securityPolicy);
  }

  async readGroup(id: string): Promise<GroupRow | null> {
    if (await this.useNode()) {
      try {
        const res = await this.client.readGroup(id);
        if (!res) return null;
        return res.group as GroupRow;
      } catch (e) {
        if (e instanceof NodeClientError && e.status === 404) return null;
        this._nodeAvailable = false;
      }
    }
    return this.local.readGroup(id);
  }

  async listGroups(): Promise<GroupRow[]> {
    if (await this.useNode()) {
      try {
        return (await this.client.listGroups()) as GroupRow[];
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.listGroups();
  }

  async deleteGroup(id: string): Promise<boolean> {
    if (await this.useNode()) {
      try {
        return await this.client.deleteGroup(id);
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.deleteGroup(id);
  }

  async addMember(groupId: string, entityId: string, role: string): Promise<void> {
    if (await this.useNode()) {
      try {
        await this.client.addMember(groupId, entityId, role);
        return;
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.addMember(groupId, entityId, role);
  }

  async removeMember(groupId: string, entityId: string): Promise<boolean> {
    if (await this.useNode()) {
      try {
        return await this.client.removeMember(groupId, entityId);
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.removeMember(groupId, entityId);
  }

  async listMembers(groupId: string): Promise<GroupMemberRow[]> {
    if (await this.useNode()) {
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
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.listMembers(groupId);
  }

  async getMembership(groupId: string, entityId: string): Promise<GroupMemberRow | null> {
    if (await this.useNode()) {
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
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.getMembership(groupId, entityId);
  }

  async updateMemberPosture(groupId: string, entityId: string, posture: string): Promise<boolean> {
    if (await this.useNode()) {
      try {
        return await this.client.updateMemberPosture(groupId, entityId, posture);
      } catch {
        this._nodeAvailable = false;
      }
    }
    return this.local.updateMemberPosture(groupId, entityId, posture);
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
    if (await this.useNode()) {
      try {
        const res = await this.client.readL2Item(id);
        if (!res) return null;
        return {
          owner_id: res.meta.owner_id,
          visibility: res.meta.visibility,
          group_id: res.meta.group_id,
          author_id: res.meta.author_id,
          key_version: res.meta.key_version,
          parent_id: null, // Not in current API response
          is_copy: 0,
          domain: null,
          ttl_expires_at: null,
        };
      } catch (e) {
        if (e instanceof NodeClientError && e.status === 404) return null;
        this._nodeAvailable = false;
      }
    }
    return this.local.readL2ItemMeta(id);
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
