/**
 * Project Cordelia - Hybrid Storage Provider
 *
 * Delegates L1 to JSON files (hook-compatible) and everything else to SQLite
 * (FTS5, vec search, groups, access tracking).
 *
 * This resolves the dual-store divergence where hooks read/write JSON files
 * but CORDELIA_STORAGE=sqlite routes MCP calls to SQLite.
 */

import type { StorageProvider, L2ItemMeta, GroupRow, GroupMemberRow, AccessLogEntry } from './storage.js';
import { JsonStorageProvider } from './storage-json.js';
import { SqliteStorageProvider } from './storage-sqlite.js';

export class HybridStorageProvider implements StorageProvider {
  readonly name = 'hybrid';
  private json: JsonStorageProvider;
  private sqlite: SqliteStorageProvider;

  constructor(memoryRoot: string) {
    this.json = new JsonStorageProvider(memoryRoot);
    this.sqlite = new SqliteStorageProvider(memoryRoot);
  }

  async initialize(): Promise<void> {
    await this.json.initialize();
    await this.sqlite.initialize();
  }

  async close(): Promise<void> {
    await this.json.close();
    await this.sqlite.close();
  }

  // -- L1: JSON files (same files hooks read/write) --

  readL1(userId: string): Promise<Buffer | null> { return this.json.readL1(userId); }
  writeL1(userId: string, data: Buffer): Promise<void> { return this.json.writeL1(userId, data); }
  deleteL1(userId: string): Promise<boolean> { return this.json.deleteL1(userId); }
  listL1Users(): Promise<string[]> { return this.json.listL1Users(); }

  // -- L2: SQLite (FTS5, vec, access tracking) --

  readL2Item(id: string): Promise<{ data: Buffer; type: string } | null> { return this.sqlite.readL2Item(id); }
  writeL2Item(id: string, type: string, data: Buffer, meta: L2ItemMeta): Promise<void> { return this.sqlite.writeL2Item(id, type, data, meta); }
  deleteL2Item(id: string): Promise<boolean> { return this.sqlite.deleteL2Item(id); }

  readL2Index(): Promise<Buffer | null> { return this.sqlite.readL2Index(); }
  writeL2Index(data: Buffer): Promise<void> { return this.sqlite.writeL2Index(data); }

  // -- Access tracking -> SQLite --

  recordAccess(id: string): Promise<void> { return this.sqlite.recordAccess(id); }
  getAccessStats(id: string): Promise<{ access_count: number; last_accessed_at: string | null } | null> { return this.sqlite.getAccessStats(id); }

  // -- FTS5 -> SQLite --

  ftsUpsert(itemId: string, name: string, content: string, tags: string): Promise<void> { return this.sqlite.ftsUpsert(itemId, name, content, tags); }
  ftsDelete(itemId: string): Promise<void> { return this.sqlite.ftsDelete(itemId); }
  ftsSearch(query: string, limit: number): Promise<Array<{ item_id: string; rank: number }>> { return this.sqlite.ftsSearch(query, limit); }

  // -- Vector search -> SQLite --

  vecUpsert(itemId: string, embedding: Float32Array): Promise<void> { return this.sqlite.vecUpsert(itemId, embedding); }
  vecDelete(itemId: string): Promise<void> { return this.sqlite.vecDelete(itemId); }
  vecSearch(embedding: Float32Array, limit: number): Promise<Array<{ item_id: string; distance: number }>> { return this.sqlite.vecSearch(embedding, limit); }
  vecAvailable(): boolean { return this.sqlite.vecAvailable(); }

  // -- Embedding cache -> SQLite --

  getEmbedding(contentHash: string, provider: string, model: string): Promise<Buffer | null> { return this.sqlite.getEmbedding(contentHash, provider, model); }
  putEmbedding(contentHash: string, provider: string, model: string, dimensions: number, vector: Buffer): Promise<void> { return this.sqlite.putEmbedding(contentHash, provider, model, dimensions, vector); }

  // -- Groups -> SQLite --

  createGroup(id: string, name: string, culture: string, securityPolicy: string): Promise<void> { return this.sqlite.createGroup(id, name, culture, securityPolicy); }
  readGroup(id: string): Promise<GroupRow | null> { return this.sqlite.readGroup(id); }
  listGroups(): Promise<GroupRow[]> { return this.sqlite.listGroups(); }
  deleteGroup(id: string): Promise<boolean> { return this.sqlite.deleteGroup(id); }
  addMember(groupId: string, entityId: string, role: string): Promise<void> { return this.sqlite.addMember(groupId, entityId, role); }
  removeMember(groupId: string, entityId: string): Promise<boolean> { return this.sqlite.removeMember(groupId, entityId); }
  listMembers(groupId: string): Promise<GroupMemberRow[]> { return this.sqlite.listMembers(groupId); }
  getMembership(groupId: string, entityId: string): Promise<GroupMemberRow | null> { return this.sqlite.getMembership(groupId, entityId); }
  updateMemberPosture(groupId: string, entityId: string, posture: string): Promise<boolean> { return this.sqlite.updateMemberPosture(groupId, entityId, posture); }
  logAccess(entry: AccessLogEntry): Promise<void> { return this.sqlite.logAccess(entry); }
  listGroupItems(groupId: string, limit?: number): Promise<Array<{ id: string; type: string; data: Buffer }>> { return this.sqlite.listGroupItems(groupId, limit); }
  readL2ItemMeta(id: string): Promise<{ owner_id: string | null; visibility: string; group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number } | null> { return this.sqlite.readL2ItemMeta(id); }

  // -- Prefetch -> SQLite --

  getRecentItems(entityId: string, groupIds: string[], limit: number): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null }>> { return this.sqlite.getRecentItems(entityId, groupIds, limit); }

  // -- Audit -> SQLite --

  appendAudit(line: string): Promise<void> { return this.sqlite.appendAudit(line); }

  // -- Backup & Restore -> SQLite --

  backup(destPath: string): Promise<{ size: number; duration_ms: number }> { return this.sqlite.backup(destPath); }
  restore(srcPath: string, opts?: { dryRun?: boolean }): Promise<{ items: number; schemaVersion: number }> { return this.sqlite.restore(srcPath, opts); }
  integrityCheck(): Promise<{ ok: boolean; errors: string[] }> { return this.sqlite.integrityCheck(); }
}
