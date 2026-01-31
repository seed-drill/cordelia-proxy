/**
 * Project Cordelia - Node Storage Provider Tests
 *
 * Tests the NodeStorageProvider with a mock HTTP server
 * that simulates the cordelia-node API endpoints.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { NodeStorageProvider } from './storage-node.js';
import { NodeClient, NodeClientError } from './node-client.js';

const TEST_TOKEN = 'test-bearer-token-1234';
const TEST_PORT = 19473;

// ============================================================================
// Mock HTTP server simulating cordelia-node API
// ============================================================================

interface MockStore {
  l1: Map<string, unknown>;
  l2: Map<string, { data: unknown; type: string; meta: Record<string, unknown> }>;
  groups: Map<string, { group: Record<string, unknown>; members: Array<Record<string, unknown>> }>;
}

function createMockServer(): { server: http.Server; store: MockStore } {
  const store: MockStore = {
    l1: new Map(),
    l2: new Map(),
    groups: new Map(),
  };

  const server = http.createServer((req, res) => {
    // Auth check
    const auth = req.headers['authorization'];
    if (auth !== `Bearer ${TEST_TOKEN}`) {
      res.writeHead(401);
      res.end('unauthorized');
      return;
    }

    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}');
      const path = req.url;

      let status = 200;
      let response: unknown = { ok: true };

      switch (path) {
        case '/api/v1/status':
          response = {
            node_id: 'test-node',
            entity_id: 'test-entity',
            uptime_secs: 42,
            peers_warm: 1,
            peers_hot: 2,
            groups: ['seed-drill'],
          };
          break;

        case '/api/v1/l1/read': {
          const data = store.l1.get(body.user_id);
          if (data === undefined) {
            status = 404;
            response = 'not found';
          } else {
            response = data;
          }
          break;
        }

        case '/api/v1/l1/write':
          store.l1.set(body.user_id, body.data);
          break;

        case '/api/v1/l2/read': {
          const item = store.l2.get(body.item_id);
          if (!item) {
            status = 404;
            response = 'not found';
          } else {
            response = {
              data: item.data,
              type: item.type,
              meta: item.meta,
            };
          }
          break;
        }

        case '/api/v1/l2/write':
          store.l2.set(body.item_id, {
            data: body.data,
            type: body.type,
            meta: body.meta ?? {},
          });
          break;

        case '/api/v1/l2/delete': {
          if (store.l2.has(body.item_id)) {
            store.l2.delete(body.item_id);
          } else {
            status = 404;
            response = 'not found';
          }
          break;
        }

        case '/api/v1/l2/search':
          response = { results: ['item-1', 'item-2'] };
          break;

        case '/api/v1/groups/create':
          store.groups.set(body.group_id, {
            group: {
              id: body.group_id,
              name: body.name,
              culture: body.culture,
              security_policy: body.security_policy,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
            members: [],
          });
          break;

        case '/api/v1/groups/read': {
          const grp = store.groups.get(body.group_id);
          if (!grp) {
            status = 404;
            response = 'group not found';
          } else {
            response = grp;
          }
          break;
        }

        case '/api/v1/groups/list':
          response = {
            groups: Array.from(store.groups.values()).map((g) => g.group),
          };
          break;

        case '/api/v1/groups/delete': {
          if (store.groups.has(body.group_id)) {
            store.groups.delete(body.group_id);
          } else {
            status = 404;
            response = 'group not found';
          }
          break;
        }

        case '/api/v1/groups/items':
          response = { items: [] };
          break;

        case '/api/v1/groups/add_member': {
          const g = store.groups.get(body.group_id);
          if (g) {
            g.members.push({
              group_id: body.group_id,
              entity_id: body.entity_id,
              role: body.role,
              posture: 'active',
              joined_at: new Date().toISOString(),
            });
          }
          break;
        }

        case '/api/v1/groups/remove_member': {
          const gr = store.groups.get(body.group_id);
          if (gr) {
            const idx = gr.members.findIndex((m) => m.entity_id === body.entity_id);
            if (idx >= 0) {
              gr.members.splice(idx, 1);
            } else {
              status = 404;
              response = 'member not found';
            }
          } else {
            status = 404;
            response = 'member not found';
          }
          break;
        }

        case '/api/v1/groups/update_posture': {
          const gp = store.groups.get(body.group_id);
          if (gp) {
            const member = gp.members.find((m) => m.entity_id === body.entity_id);
            if (member) {
              member.posture = body.posture;
            } else {
              status = 404;
              response = 'member not found';
            }
          } else {
            status = 404;
            response = 'member not found';
          }
          break;
        }

        default:
          status = 404;
          response = 'not found';
      }

      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(typeof response === 'string' ? response : JSON.stringify(response));
    });
  });

  return { server, store };
}

// ============================================================================
// Tests
// ============================================================================

describe('NodeClient', () => {
  let server: http.Server;
  let store: MockStore;
  let client: NodeClient;

  before(async () => {
    const mock = createMockServer();
    server = mock.server;
    store = mock.store;
    await new Promise<void>((resolve) => server.listen(TEST_PORT, resolve));
    client = new NodeClient({
      baseUrl: `http://127.0.0.1:${TEST_PORT}`,
      token: TEST_TOKEN,
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('health check returns true', async () => {
    assert.equal(await client.isAvailable(), true);
  });

  it('health check with wrong port returns false', async () => {
    const badClient = new NodeClient({
      baseUrl: 'http://127.0.0.1:19999',
      token: 'bad',
      timeoutMs: 500,
    });
    assert.equal(await badClient.isAvailable(), false);
  });

  it('rejects invalid bearer token', async () => {
    const badClient = new NodeClient({
      baseUrl: `http://127.0.0.1:${TEST_PORT}`,
      token: 'wrong-token',
    });
    await assert.rejects(
      () => badClient.status(),
      (err: unknown) => err instanceof NodeClientError && err.status === 401,
    );
  });

  it('L1 read/write round-trip', async () => {
    assert.equal(await client.readL1('test-user'), null);
    await client.writeL1('test-user', { version: 1, data: 'hello' });
    const result = await client.readL1('test-user');
    assert.deepEqual(result, { version: 1, data: 'hello' });
  });

  it('L2 read/write/delete', async () => {
    assert.equal(await client.readL2Item('item-1'), null);
    await client.writeL2Item('item-1', 'entity', { name: 'Test' }, {
      owner_id: 'russell',
      visibility: 'private',
    });
    const item = await client.readL2Item('item-1');
    assert.ok(item);
    assert.equal(item.type, 'entity');

    assert.equal(await client.deleteL2Item('item-1'), true);
    assert.equal(await client.deleteL2Item('item-1'), false);
  });

  it('FTS search returns results', async () => {
    const results = await client.ftsSearch('test query', 10);
    assert.deepEqual(results, ['item-1', 'item-2']);
  });

  it('group CRUD', async () => {
    await client.createGroup('grp-1', 'Test Group');
    const groups = await client.listGroups();
    assert.equal(groups.length, 1);
    assert.equal(groups[0].name, 'Test Group');

    const grp = await client.readGroup('grp-1');
    assert.ok(grp);
    assert.equal(grp.group.name, 'Test Group');

    assert.equal(await client.deleteGroup('grp-1'), true);
    assert.equal(await client.deleteGroup('grp-1'), false);
  });

  it('member management', async () => {
    await client.createGroup('grp-2', 'Member Group');
    await client.addMember('grp-2', 'alice', 'admin');
    await client.addMember('grp-2', 'bob', 'member');

    const grp = await client.readGroup('grp-2');
    assert.ok(grp);
    assert.equal(grp.members.length, 2);

    assert.equal(await client.removeMember('grp-2', 'bob'), true);
    assert.equal(await client.removeMember('grp-2', 'bob'), false);

    assert.equal(
      await client.updateMemberPosture('grp-2', 'alice', 'emcon'),
      true,
    );
    const grp2 = await client.readGroup('grp-2');
    assert.equal(grp2!.members[0].posture, 'emcon');
  });

  it('status endpoint', async () => {
    const s = await client.status();
    assert.equal(s.node_id, 'test-node');
    assert.equal(s.uptime_secs, 42);
  });
});
