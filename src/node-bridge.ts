/**
 * Project Cordelia - Node Bridge
 *
 * Lightweight bridge between local SQLite storage and the Rust P2P node.
 * Pushes group items to the node for replication. Pulls new group items
 * on startup for local indexing.
 *
 * SQLite remains the primary storage (source of truth). The node is a
 * replication layer. If the node is unavailable, everything works locally.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { NodeClient, NodeClientError } from './node-client.js';
import { isEncryptedPayload } from './crypto.js';
import { getGroupKey, groupDecrypt } from './group-keys.js';
import type { StorageProvider } from './storage.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';

const NODE_URL = process.env.CORDELIA_NODE_URL || 'http://127.0.0.1:9473';
const TOKEN_PATH = path.join(os.homedir(), '.cordelia', 'node-token');

// Health check cache (30 seconds)
let healthCache: { available: boolean; checkedAt: number } | null = null;
const HEALTH_CACHE_TTL_MS = 30_000;

let singleton: NodeBridge | null = null;

export function getNodeBridge(): NodeBridge {
  if (!singleton) {
    singleton = new NodeBridge();
  }
  return singleton;
}

/**
 * Reset singleton (for testing).
 */
export function resetNodeBridge(): void {
  singleton = null;
  healthCache = null;
}

export class NodeBridge {
  private client: NodeClient | null = null;
  private tokenResolved = false;

  /**
   * Lazily resolve the node token and create a client.
   * Returns null if no token is available (node bridge disabled).
   */
  private async getClient(): Promise<NodeClient | null> {
    if (this.client) return this.client;
    if (this.tokenResolved) return null; // Already tried, no token

    this.tokenResolved = true;

    let token = process.env.CORDELIA_NODE_TOKEN || '';
    if (!token) {
      try {
        token = (await fs.readFile(TOKEN_PATH, 'utf-8')).trim();
      } catch {
        // No token file -- node bridge disabled
        return null;
      }
    }

    if (!token) return null;

    this.client = new NodeClient({
      baseUrl: NODE_URL,
      token,
      timeoutMs: 5000,
    });
    return this.client;
  }

  /**
   * Check if the node is available (cached 30 seconds).
   */
  async isAvailable(): Promise<boolean> {
    const now = Date.now();
    if (healthCache && now - healthCache.checkedAt < HEALTH_CACHE_TTL_MS) {
      return healthCache.available;
    }

    const client = await this.getClient();
    if (!client) {
      healthCache = { available: false, checkedAt: now };
      return false;
    }

    const available = await client.isAvailable();
    healthCache = { available, checkedAt: now };
    return available;
  }

  /**
   * Push a group item to the Rust node for P2P replication.
   * Takes already-encrypted data (encrypted with group PSK in writeItem/shareItem).
   * Fire-and-forget: caller should .catch() the returned promise.
   */
  async pushGroupItem(
    itemId: string,
    type: string,
    encryptedData: unknown,
    meta: {
      owner_id?: string | null;
      visibility?: string;
      group_id?: string | null;
      author_id?: string | null;
      key_version?: number;
      parent_id?: string | null;
      is_copy?: boolean;
    },
  ): Promise<void> {
    const client = await this.getClient();
    if (!client) return;

    if (!(await this.isAvailable())) {
      console.error('Cordelia: node unavailable, group item will stay local-only');
      return;
    }

    await client.writeL2Item(itemId, type, encryptedData, {
      owner_id: meta.owner_id,
      visibility: meta.visibility,
      group_id: meta.group_id,
      author_id: meta.author_id,
      key_version: meta.key_version,
      parent_id: meta.parent_id,
      is_copy: meta.is_copy,
    });
  }

  /**
   * Sync groups from the P2P network into local storage.
   * Creates locally any groups that exist on the network but not locally.
   */
  async syncGroups(storage: StorageProvider): Promise<{ created: number }> {
    const client = await this.getClient();
    if (!client) return { created: 0 };

    const remoteGroups = await client.listGroups();
    const localGroups = await storage.listGroups();
    const localIds = new Set(localGroups.map((g) => g.id));

    let created = 0;
    for (const rg of remoteGroups) {
      if (!localIds.has(rg.id)) {
        try {
          await storage.createGroup(rg.id, rg.name, rg.culture, rg.security_policy);
          created++;
        } catch (e) {
          console.error(`Cordelia: failed to create local group ${rg.id}: ${(e as Error).message}`);
        }
      }

      // Sync members (best-effort, FK on l1_hot may prevent adding remote users)
      try {
        const remote = await client.readGroup(rg.id);
        if (remote) {
          for (const member of remote.members) {
            try {
              const existing = await storage.getMembership(rg.id, member.entity_id);
              if (!existing) {
                await storage.addMember(rg.id, member.entity_id, member.role);
              }
            } catch {
              // FK constraint: entity_id not in local l1_hot -- skip silently
            }
          }
        }
      } catch {
        // Group read failed -- skip member sync
      }
    }

    return { created };
  }

  /**
   * Decrypt remote item data based on key version.
   * Returns decrypted buffer or null if item should be skipped.
   */
  private async decryptRemoteItem(
    data: unknown,
    keyVersion: number,
    groupId: string,
    itemId: string,
  ): Promise<{ data: Buffer; skip: boolean }> {
    if (isEncryptedPayload(data) && keyVersion === 2) {
      const groupKey = await getGroupKey(groupId);
      if (!groupKey) {
        console.error(`Cordelia: no PSK for group ${groupId}, skipping item ${itemId}`);
        return { data: Buffer.alloc(0), skip: true };
      }
      const decrypted = await groupDecrypt(
        data as { iv: string; authTag: string; ciphertext: string },
        groupKey,
      );
      return { data: decrypted, skip: false };
    }

    if (isEncryptedPayload(data) && keyVersion === 1) {
      return { data: Buffer.alloc(0), skip: true };
    }

    return { data: Buffer.from(JSON.stringify(data), 'utf-8'), skip: false };
  }

  /**
   * Index item in FTS.
   */
  private async indexItemInFts(
    itemId: string,
    itemData: Buffer,
    storage: StorageProvider,
  ): Promise<void> {
    try {
      const parsed = JSON.parse(itemData.toString('utf-8'));
      const name = parsed.name || parsed.focus || parsed.content?.slice(0, 50) || itemId;
      const tags = (parsed.tags || []).join(' ');
      const content = [
        name,
        parsed.summary || '',
        parsed.content || '',
        parsed.context || '',
        ...(parsed.highlights || []),
        ...(parsed.aliases || []),
      ].join(' ');
      await storage.ftsUpsert(itemId, name, content, tags);
    } catch {
      // FTS indexing failed -- item still stored
    }
  }

  /**
   * Process a single remote item for sync.
   */
  private async processSyncItem(
    client: NodeClient,
    header: { item_id: string; is_deletion?: boolean; updated_at: string },
    groupId: string,
    storage: StorageProvider,
  ): Promise<'synced' | 'skipped' | 'error'> {
    if (header.is_deletion) return 'skipped';

    const localItem = await storage.readL2Item(header.item_id);
    if (localItem) return 'skipped';

    const remote = await client.readL2Item(header.item_id);
    if (!remote) return 'skipped';

    const keyVersion = remote.meta?.key_version ?? 1;
    const { data: itemData, skip } = await this.decryptRemoteItem(
      remote.data,
      keyVersion,
      groupId,
      header.item_id,
    );
    if (skip) return 'skipped';

    await storage.writeL2Item(header.item_id, remote.type, itemData, {
      type: remote.type as 'entity' | 'session' | 'learning',
      owner_id: remote.meta?.owner_id ?? undefined,
      visibility: (remote.meta?.visibility as 'private' | 'group' | 'public') ?? 'group',
      group_id: remote.meta?.group_id ?? groupId,
      author_id: remote.meta?.author_id ?? undefined,
      key_version: 0,
    });

    await this.indexItemInFts(header.item_id, itemData, storage);
    return 'synced';
  }

  /**
   * Sync items for a single group.
   */
  private async syncSingleGroup(
    client: NodeClient,
    groupId: string,
    storage: StorageProvider,
    sqliteStorage: SqliteStorageProvider | null,
  ): Promise<{ synced: number; skipped: number; errors: number }> {
    let synced = 0;
    let skipped = 0;
    let errors = 0;

    const since = sqliteStorage?.getSyncTimestamp(groupId) ?? undefined;
    const headers = await client.listGroupItems(groupId, since, 200);

    for (const header of headers) {
      try {
        const result = await this.processSyncItem(client, header, groupId, storage);
        if (result === 'synced') synced++;
        else if (result === 'skipped') skipped++;
        else errors++;
      } catch (e) {
        if (e instanceof NodeClientError && e.status === 404) {
          skipped++;
        } else {
          console.error(`Cordelia: failed to sync item ${header.item_id}: ${(e as Error).message}`);
          errors++;
        }
      }
    }

    if (sqliteStorage && headers.length > 0) {
      const maxUpdatedAt = headers.reduce(
        (max, h) => (h.updated_at > max ? h.updated_at : max),
        '',
      );
      if (maxUpdatedAt) {
        sqliteStorage.setSyncTimestamp(groupId, maxUpdatedAt);
      }
    }

    return { synced, skipped, errors };
  }

  /**
   * Pull new group items from the P2P network and index locally.
   * For each group, queries the node for items updated since last sync.
   * Decrypts group PSK items (key_version=2), skips proxy-key items (key_version=1).
   */
  async syncGroupItems(
    groupIds: string[],
    storage: StorageProvider,
  ): Promise<{ synced: number; skipped: number; errors: number }> {
    const client = await this.getClient();
    if (!client) return { synced: 0, skipped: 0, errors: 0 };

    const sqliteStorage = storage.name === 'sqlite' ? (storage as SqliteStorageProvider) : null;

    let totalSynced = 0;
    let totalSkipped = 0;
    let totalErrors = 0;

    for (const groupId of groupIds) {
      try {
        const result = await this.syncSingleGroup(client, groupId, storage, sqliteStorage);
        totalSynced += result.synced;
        totalSkipped += result.skipped;
        totalErrors += result.errors;
      } catch (e) {
        console.error(`Cordelia: failed to sync group ${groupId}: ${(e as Error).message}`);
        totalErrors++;
      }
    }

    return { synced: totalSynced, skipped: totalSkipped, errors: totalErrors };
  }
}
