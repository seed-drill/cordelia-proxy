/**
 * Project Cordelia - JSON File Storage Provider
 *
 * Implements StorageProvider using filesystem JSON files.
 * This is a refactor of existing I/O from server.ts and l2.ts.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { StorageProvider, L2ItemMeta, GroupRow, GroupMemberRow, AccessLogEntry } from './storage.js';

export class JsonStorageProvider implements StorageProvider {
  readonly name = 'json';
  private memoryRoot: string;

  constructor(memoryRoot: string) {
    this.memoryRoot = memoryRoot;
  }

  async initialize(): Promise<void> {
    // Ensure base directories exist
    const dirs = [
      path.join(this.memoryRoot, 'L1-hot'),
      path.join(this.memoryRoot, 'L2-warm', 'entities'),
      path.join(this.memoryRoot, 'L2-warm', 'sessions'),
      path.join(this.memoryRoot, 'L2-warm', 'learnings'),
    ];
    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  async close(): Promise<void> {
    // No-op for file-based storage
  }

  // -- L1 Hot Context --

  async readL1(userId: string): Promise<Buffer | null> {
    const filePath = path.join(this.memoryRoot, 'L1-hot', `${userId}.json`);
    try {
      return await fs.readFile(filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  async writeL1(userId: string, data: Buffer): Promise<void> {
    const filePath = path.join(this.memoryRoot, 'L1-hot', `${userId}.json`);
    await fs.writeFile(filePath, data);
  }

  async deleteL1(userId: string): Promise<boolean> {
    const filePath = path.join(this.memoryRoot, 'L1-hot', `${userId}.json`);
    try {
      await fs.unlink(filePath);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return false; // File didn't exist
      }
      throw error;
    }
  }

  async listL1Users(): Promise<string[]> {
    const hotDir = path.join(this.memoryRoot, 'L1-hot');
    try {
      const files = await fs.readdir(hotDir);
      return files.filter((f) => f.endsWith('.json')).map((f) => path.basename(f, '.json'));
    } catch {
      return [];
    }
  }

  // -- L2 Items --

  async readL2Item(id: string): Promise<{ data: Buffer; type: string } | null> {
    // We need to search across type directories since we only have the id
    const subdirs: Array<{ dir: string; type: string }> = [
      { dir: 'entities', type: 'entity' },
      { dir: 'sessions', type: 'session' },
      { dir: 'learnings', type: 'learning' },
    ];

    for (const { dir, type } of subdirs) {
      const filePath = path.join(this.memoryRoot, 'L2-warm', dir, `${id}.json`);
      try {
        const data = await fs.readFile(filePath);
        return { data, type };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          continue;
        }
        throw error;
      }
    }

    return null;
  }

  async writeL2Item(id: string, type: string, data: Buffer, _meta: L2ItemMeta): Promise<void> {
    const subdir = type === 'entity' ? 'entities' : type === 'session' ? 'sessions' : 'learnings';
    const filePath = path.join(this.memoryRoot, 'L2-warm', subdir, `${id}.json`);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, data);
  }

  async deleteL2Item(id: string): Promise<boolean> {
    const subdirs = ['entities', 'sessions', 'learnings'];

    for (const dir of subdirs) {
      const filePath = path.join(this.memoryRoot, 'L2-warm', dir, `${id}.json`);
      try {
        await fs.unlink(filePath);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          continue;
        }
        throw error;
      }
    }

    return false;
  }

  // -- L2 Index --

  async readL2Index(): Promise<Buffer | null> {
    const indexPath = path.join(this.memoryRoot, 'L2-warm', 'index.json');
    try {
      return await fs.readFile(indexPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  async writeL2Index(data: Buffer): Promise<void> {
    const indexPath = path.join(this.memoryRoot, 'L2-warm', 'index.json');
    await fs.writeFile(indexPath, data);
  }

  // -- Access Tracking --

  async recordAccess(_id: string): Promise<void> {
    // No-op for JSON file storage - no access tracking in file mode
  }

  async getAccessStats(_id: string): Promise<{ access_count: number; last_accessed_at: string | null } | null> {
    // No access tracking in file mode
    return null;
  }

  // -- FTS (no-op for JSON provider) --

  async ftsUpsert(_itemId: string, _name: string, _content: string, _tags: string): Promise<void> {}
  async ftsDelete(_itemId: string): Promise<void> {}
  async ftsSearch(_query: string, _limit: number): Promise<Array<{ item_id: string; rank: number }>> { return []; }

  // -- Vector search (no-op for JSON provider) --

  async vecUpsert(_itemId: string, _embedding: Float32Array): Promise<void> {}
  async vecDelete(_itemId: string): Promise<void> {}
  async vecSearch(_embedding: Float32Array, _limit: number): Promise<Array<{ item_id: string; distance: number }>> { return []; }
  vecAvailable(): boolean { return false; }

  // -- Embedding cache (no-op for JSON provider) --

  async getEmbedding(_contentHash: string, _provider: string, _model: string): Promise<Buffer | null> { return null; }
  async putEmbedding(_contentHash: string, _provider: string, _model: string, _dimensions: number, _vector: Buffer): Promise<void> {}

  // -- Groups (not supported for JSON provider) --

  private groupStubError(): never {
    throw new Error('Group operations require SQLite provider');
  }

  async createGroup(_id: string, _name: string, _culture: string, _securityPolicy: string): Promise<void> { this.groupStubError(); }
  async readGroup(_id: string): Promise<GroupRow | null> { this.groupStubError(); }
  async listGroups(): Promise<GroupRow[]> { this.groupStubError(); }
  async deleteGroup(_id: string): Promise<boolean> { this.groupStubError(); }
  async addMember(_groupId: string, _entityId: string, _role: string): Promise<void> { this.groupStubError(); }
  async removeMember(_groupId: string, _entityId: string): Promise<boolean> { this.groupStubError(); }
  async listMembers(_groupId: string): Promise<GroupMemberRow[]> { this.groupStubError(); }
  async getMembership(_groupId: string, _entityId: string): Promise<GroupMemberRow | null> { this.groupStubError(); }
  async updateMemberPosture(_groupId: string, _entityId: string, _posture: string): Promise<boolean> { this.groupStubError(); }
  async logAccess(_entry: AccessLogEntry): Promise<void> { this.groupStubError(); }
  async listGroupItems(_groupId: string, _limit?: number): Promise<Array<{ id: string; type: string; data: Buffer }>> { this.groupStubError(); }
  async readL2ItemMeta(_id: string): Promise<{ owner_id: string | null; visibility: string; group_id: string | null; author_id: string | null; key_version: number; parent_id: string | null; is_copy: number } | null> { this.groupStubError(); }

  // -- Backup & Restore (not supported for JSON provider) --

  async backup(_destPath: string): Promise<{ size: number; duration_ms: number }> {
    throw new Error('Backup not supported for JSON storage provider. Use SQLite provider.');
  }

  async restore(_srcPath: string, _opts?: { dryRun?: boolean }): Promise<{ items: number; schemaVersion: number }> {
    throw new Error('Restore not supported for JSON storage provider. Use SQLite provider.');
  }

  async integrityCheck(): Promise<{ ok: boolean; errors: string[] }> {
    throw new Error('Integrity check not supported for JSON storage provider. Use SQLite provider.');
  }

  // -- Prefetch (R3-012) --

  async getRecentItems(_entityId: string, _groupIds: string[], _limit: number): Promise<Array<{ id: string; type: string; group_id: string | null; last_accessed_at: string | null }>> {
    // JSON provider does not support access tracking; return empty
    return [];
  }

  // -- Audit --

  async appendAudit(line: string): Promise<void> {
    const auditPath = path.join(this.memoryRoot, 'audit.jsonl');
    await fs.appendFile(auditPath, line + '\n', 'utf-8');
  }
}
