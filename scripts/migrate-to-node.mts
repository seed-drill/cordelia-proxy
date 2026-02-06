#!/usr/bin/env npx tsx
/**
 * Cordelia - Migrate Proxy SQLite to Node Storage
 *
 * Reads all L1, L2, group, and member data from the local proxy SQLite
 * database and pushes it to the cordelia-node HTTP API.
 *
 * Data is migrated as-is (encrypted blobs stay encrypted).
 * Existing items on the node are upserted (safe to re-run).
 *
 * Usage: npx tsx scripts/migrate-to-node.mts [--dry-run]
 */

import Database from 'better-sqlite3';
import { request } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || join(homedir(), '.cordelia', 'memory');
const DB_PATH = join(MEMORY_ROOT, 'cordelia.db');
const DRY_RUN = process.argv.includes('--dry-run');

function resolveNodeConfig(): { url: string; token: string } {
  let url = process.env.CORDELIA_NODE_URL || '';
  let token = process.env.CORDELIA_NODE_TOKEN || '';

  if (!url) {
    try {
      const configPath = join(homedir(), '.cordelia', 'config.toml');
      const content = readFileSync(configPath, 'utf-8');
      const nodeMatch = content.match(/\[node\][\s\S]*?api_addr\s*=\s*"?([^"\n]+)"?/);
      if (nodeMatch) {
        const addr = nodeMatch[1].trim();
        const transport = content.match(/\[node\][\s\S]*?api_transport\s*=\s*"?([^"\n]+)"?/);
        const proto = transport?.[1]?.trim() === 'https' ? 'https' : 'http';
        url = `${proto}://${addr}`;
      }
    } catch { /* use default */ }
  }

  if (!token) {
    try {
      token = readFileSync(join(homedir(), '.cordelia', 'node-token'), 'utf-8').trim();
    } catch { /* empty */ }
  }

  return { url: url || 'http://127.0.0.1:9473', token };
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

function post(baseUrl: string, token: string, path: string, body: unknown): Promise<{ status: number; data: unknown }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
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
          'Authorization': `Bearer ${token}`,
        },
        timeout: 10000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          let data: unknown;
          try { data = JSON.parse(raw); } catch { data = raw; }
          resolve({ status: res.statusCode ?? 500, data });
        });
      },
    );

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

async function main() {
  const { url, token } = resolveNodeConfig();
  console.log(`Migration: ${DB_PATH} -> ${url}`);
  if (DRY_RUN) console.log('DRY RUN — no writes will be made\n');

  // Verify node is reachable
  try {
    const { status } = await post(url, token, '/api/v1/status', {});
    if (status !== 200) throw new Error(`status ${status}`);
  } catch (e) {
    console.error(`Node unreachable at ${url}: ${(e as Error).message}`);
    process.exit(1);
  }

  const db = new Database(DB_PATH, { readonly: true });
  const stats = { l1: 0, l2: 0, groups: 0, members: 0, errors: 0, skipped: 0 };

  // ----- Groups -----
  console.log('\n--- Groups ---');
  const groups = db.prepare('SELECT id, name, culture, security_policy FROM groups').all() as Array<{
    id: string; name: string; culture: string; security_policy: string;
  }>;

  for (const g of groups) {
    console.log(`  group: ${g.id} (${g.name})`);
    if (!DRY_RUN) {
      try {
        const { status } = await post(url, token, '/api/v1/groups/create', {
          group_id: g.id,
          name: g.name,
          culture: g.culture,
          security_policy: g.security_policy,
        });
        // 409 = already exists, that's fine
        if (status >= 200 && status < 300) stats.groups++;
        else if (status === 409) { stats.skipped++; console.log('    (already exists)'); }
        else { stats.errors++; console.log(`    ERROR: status ${status}`); }
      } catch (e) { stats.errors++; console.error(`    ERROR: ${(e as Error).message}`); }
    } else {
      stats.groups++;
    }
  }

  // ----- Members -----
  console.log('\n--- Members ---');
  const members = db.prepare('SELECT group_id, entity_id, role FROM group_members').all() as Array<{
    group_id: string; entity_id: string; role: string;
  }>;

  for (const m of members) {
    console.log(`  member: ${m.entity_id} in ${m.group_id} (${m.role})`);
    if (!DRY_RUN) {
      try {
        const { status } = await post(url, token, '/api/v1/groups/add_member', {
          group_id: m.group_id,
          entity_id: m.entity_id,
          role: m.role,
        });
        if (status >= 200 && status < 300) stats.members++;
        else if (status === 409) { stats.skipped++; console.log('    (already exists)'); }
        else { stats.errors++; console.log(`    ERROR: status ${status}`); }
      } catch (e) { stats.errors++; console.error(`    ERROR: ${(e as Error).message}`); }
    } else {
      stats.members++;
    }
  }

  // ----- L1 Hot Context -----
  console.log('\n--- L1 Hot Context ---');
  const l1Users = db.prepare('SELECT user_id, data FROM l1_hot').all() as Array<{
    user_id: string; data: Buffer;
  }>;

  for (const u of l1Users) {
    const sizeKB = (u.data.length / 1024).toFixed(1);
    console.log(`  L1: ${u.user_id} (${sizeKB} KB)`);
    if (!DRY_RUN) {
      try {
        // L1 data is stored as an encrypted JSON blob. Parse it so the node
        // stores structured JSON (the node's l1_write serialises the Value).
        let parsed: unknown;
        try {
          parsed = JSON.parse(u.data.toString('utf-8'));
        } catch {
          // If not valid JSON (raw encrypted blob), base64-encode it
          parsed = { _raw: u.data.toString('base64') };
        }
        const { status } = await post(url, token, '/api/v1/l1/write', {
          user_id: u.user_id,
          data: parsed,
        });
        if (status >= 200 && status < 300) stats.l1++;
        else { stats.errors++; console.log(`    ERROR: status ${status}`); }
      } catch (e) { stats.errors++; console.error(`    ERROR: ${(e as Error).message}`); }
    } else {
      stats.l1++;
    }
  }

  // ----- L2 Items -----
  console.log('\n--- L2 Items ---');
  const l2Items = db.prepare(
    `SELECT id, type, owner_id, visibility, data, group_id, author_id,
            key_version, parent_id, is_copy
     FROM l2_items`
  ).all() as Array<{
    id: string; type: string; owner_id: string | null; visibility: string;
    data: Buffer; group_id: string | null; author_id: string | null;
    key_version: number | null; parent_id: string | null; is_copy: number;
  }>;

  let count = 0;
  for (const item of l2Items) {
    count++;
    const sizeB = item.data.length;
    const prefix = `  [${count}/${l2Items.length}]`;
    const group = item.group_id ?? '(private)';
    console.log(`${prefix} ${item.id} type=${item.type} group=${group} ${sizeB}B`);

    if (!DRY_RUN) {
      try {
        let parsed: unknown;
        try {
          parsed = JSON.parse(item.data.toString('utf-8'));
        } catch {
          parsed = { _raw: item.data.toString('base64') };
        }

        const { status, data: respData } = await post(url, token, '/api/v1/l2/write', {
          item_id: item.id,
          type: item.type,
          data: parsed,
          meta: {
            owner_id: item.owner_id,
            visibility: item.visibility,
            group_id: item.group_id,
            author_id: item.author_id,
            key_version: item.key_version ?? 1,
            parent_id: item.parent_id,
            is_copy: (item.is_copy ?? 0) !== 0,
          },
        });

        if (status >= 200 && status < 300) {
          stats.l2++;
        } else {
          stats.errors++;
          console.log(`    ERROR: status ${status} ${JSON.stringify(respData)}`);
        }
      } catch (e) { stats.errors++; console.error(`    ERROR: ${(e as Error).message}`); }
    } else {
      stats.l2++;
    }
  }

  // ----- Summary -----
  console.log('\n========================================');
  console.log('Migration Summary');
  console.log('========================================');
  console.log(`  Groups:  ${stats.groups} migrated`);
  console.log(`  Members: ${stats.members} migrated`);
  console.log(`  L1:      ${stats.l1} migrated`);
  console.log(`  L2:      ${stats.l2} migrated`);
  console.log(`  Skipped: ${stats.skipped}`);
  console.log(`  Errors:  ${stats.errors}`);
  if (DRY_RUN) console.log('\n  (DRY RUN — nothing was written)');

  // ----- Verification -----
  if (!DRY_RUN && stats.errors === 0) {
    console.log('\n--- Verification ---');
    const { data: listData } = await post(url, token, '/api/v1/l1/list', {});
    const nodeL1 = ((listData as { users?: string[] })?.users ?? []).length;
    const { data: groupsData } = await post(url, token, '/api/v1/groups/list', {});
    const nodeGroups = ((groupsData as { groups?: unknown[] })?.groups ?? []).length;

    console.log(`  Node L1 users:  ${nodeL1} (expected ${l1Users.length})`);
    console.log(`  Node groups:    ${nodeGroups} (expected ${groups.length})`);

    if (nodeL1 >= l1Users.length && nodeGroups >= groups.length) {
      console.log('\n  Migration verified successfully.');
    } else {
      console.log('\n  WARNING: Count mismatch — check node data.');
    }
  }

  db.close();
  process.exit(stats.errors > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(2);
});
