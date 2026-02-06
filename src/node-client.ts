/**
 * Project Cordelia - Node HTTP Client
 *
 * Typed HTTP client wrapping all cordelia-node API endpoints.
 * Bearer token auth. Timeout handling. Health check.
 */

import { request } from 'node:http';
import { URL } from 'node:url';

export interface NodeClientOptions {
  baseUrl: string;
  token: string;
  timeoutMs?: number;
}

export interface L2ReadResponse {
  data: unknown;
  type: string;
  meta: {
    owner_id: string | null;
    visibility: string;
    group_id: string | null;
    author_id: string | null;
    key_version: number;
    checksum: string | null;
    parent_id?: string | null;
    is_copy?: boolean;
    domain?: string | null;
    ttl_expires_at?: string | null;
  };
}

export interface L2WriteMeta {
  owner_id?: string | null;
  visibility?: string;
  group_id?: string | null;
  author_id?: string | null;
  key_version?: number;
  parent_id?: string | null;
  is_copy?: boolean;
  domain?: string | null;
  ttl_expires_at?: string | null;
}

export interface GroupInfo {
  id: string;
  name: string;
  culture: string;
  security_policy: string;
  created_at: string;
  updated_at: string;
}

export interface GroupMemberInfo {
  group_id: string;
  entity_id: string;
  role: string;
  posture: string | null;
  joined_at: string;
}

export interface ItemHeader {
  item_id: string;
  item_type: string;
  checksum: string;
  updated_at: string;
  author_id: string;
  is_deletion: boolean;
}

export interface StatusResponse {
  node_id: string;
  entity_id: string;
  uptime_secs: number;
  peers_warm: number;
  peers_hot: number;
  groups: string[];
}

export class NodeClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(opts: NodeClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '');
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  /**
   * Health check: GET /api/v1/status with a short timeout.
   * Returns true if the node responds with a 200.
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.post('/api/v1/status', {}, 2000);
      return true;
    } catch {
      return false;
    }
  }

  // ====================================================================
  // L1 Hot Context
  // ====================================================================

  async readL1(userId: string): Promise<unknown | null> {
    try {
      return await this.post('/api/v1/l1/read', { user_id: userId });
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      throw e;
    }
  }

  async writeL1(userId: string, data: unknown): Promise<void> {
    await this.post('/api/v1/l1/write', { user_id: userId, data });
  }

  async deleteL1(userId: string): Promise<boolean> {
    try {
      await this.post('/api/v1/l1/delete', { user_id: userId });
      return true;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return false;
      throw e;
    }
  }

  async listL1Users(): Promise<string[]> {
    const res = await this.post('/api/v1/l1/list', {}) as { users: string[] };
    return res.users ?? [];
  }

  // ====================================================================
  // L2 Items
  // ====================================================================

  async readL2Item(itemId: string): Promise<L2ReadResponse | null> {
    try {
      return await this.post('/api/v1/l2/read', { item_id: itemId }) as L2ReadResponse;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      throw e;
    }
  }

  async writeL2Item(
    itemId: string,
    type: string,
    data: unknown,
    meta?: L2WriteMeta,
  ): Promise<void> {
    await this.post('/api/v1/l2/write', {
      item_id: itemId,
      type,
      data,
      meta,
    });
  }

  async deleteL2Item(itemId: string): Promise<boolean> {
    try {
      await this.post('/api/v1/l2/delete', { item_id: itemId });
      return true;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return false;
      throw e;
    }
  }

  // ====================================================================
  // L2 Search (FTS)
  // ====================================================================

  async ftsSearch(query: string, limit: number): Promise<string[]> {
    const res = await this.post('/api/v1/l2/search', { query, limit }) as { results: string[] };
    return res.results ?? [];
  }

  // ====================================================================
  // Groups
  // ====================================================================

  async createGroup(
    groupId: string,
    name: string,
    culture?: string,
    securityPolicy?: string,
  ): Promise<void> {
    await this.post('/api/v1/groups/create', {
      group_id: groupId,
      name,
      culture: culture ?? '{"broadcast_eagerness":"moderate"}',
      security_policy: securityPolicy ?? '{}',
    });
  }

  async readGroup(groupId: string): Promise<{ group: GroupInfo; members: GroupMemberInfo[] } | null> {
    try {
      return await this.post('/api/v1/groups/read', { group_id: groupId }) as {
        group: GroupInfo;
        members: GroupMemberInfo[];
      };
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return null;
      throw e;
    }
  }

  async listGroups(): Promise<GroupInfo[]> {
    const res = await this.post('/api/v1/groups/list', {}) as { groups: GroupInfo[] };
    return res.groups ?? [];
  }

  async deleteGroup(groupId: string): Promise<boolean> {
    try {
      await this.post('/api/v1/groups/delete', { group_id: groupId });
      return true;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return false;
      throw e;
    }
  }

  async listGroupItems(
    groupId: string,
    since?: string,
    limit?: number,
  ): Promise<ItemHeader[]> {
    const res = await this.post('/api/v1/groups/items', {
      group_id: groupId,
      since,
      limit: limit ?? 100,
    }) as { items: ItemHeader[] };
    return res.items ?? [];
  }

  // ====================================================================
  // Members
  // ====================================================================

  async addMember(groupId: string, entityId: string, role?: string): Promise<void> {
    await this.post('/api/v1/groups/add_member', {
      group_id: groupId,
      entity_id: entityId,
      role: role ?? 'member',
    });
  }

  async removeMember(groupId: string, entityId: string): Promise<boolean> {
    try {
      await this.post('/api/v1/groups/remove_member', {
        group_id: groupId,
        entity_id: entityId,
      });
      return true;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return false;
      throw e;
    }
  }

  async updateMemberPosture(
    groupId: string,
    entityId: string,
    posture: string,
  ): Promise<boolean> {
    try {
      await this.post('/api/v1/groups/update_posture', {
        group_id: groupId,
        entity_id: entityId,
        posture,
      });
      return true;
    } catch (e: unknown) {
      if (e instanceof NodeClientError && e.status === 404) return false;
      throw e;
    }
  }

  // ====================================================================
  // Status
  // ====================================================================

  async status(): Promise<StatusResponse> {
    return await this.post('/api/v1/status', {}) as StatusResponse;
  }

  // ====================================================================
  // HTTP transport
  // ====================================================================

  private post(path: string, body: unknown, timeoutOverride?: number): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.baseUrl);
      const payload = JSON.stringify(body);

      const req = request(
        {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'Authorization': `Bearer ${this.token}`,
          },
          timeout: timeoutOverride ?? this.timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf-8');
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              try {
                resolve(JSON.parse(raw));
              } catch {
                resolve(raw);
              }
            } else {
              reject(new NodeClientError(res.statusCode ?? 500, raw));
            }
          });
        },
      );

      req.on('error', (err) => reject(new NodeClientError(0, err.message)));
      req.on('timeout', () => {
        req.destroy();
        reject(new NodeClientError(0, 'request timeout'));
      });
      req.write(payload);
      req.end();
    });
  }
}

export class NodeClientError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(`NodeClient ${status}: ${message}`);
    this.name = 'NodeClientError';
    this.status = status;
  }
}
