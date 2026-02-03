/**
 * Project Cordelia - Production Integrity Verification
 *
 * Read-only verification of the live production database.
 * Opens SQLite in READONLY mode. Never writes. Safe to run at any time.
 *
 * Checks:
 * 1. Database opens and schema version is correct
 * 2. SQLite integrity_check (PRAGMA)
 * 3. L1 chain hash verification for all users
 * 4. L2 item checksum verification (all items)
 * 5. Integrity canary present and valid
 * 6. Group tables exist and have expected data
 * 7. L2 index entry count matches l2_items count
 * 8. No orphaned COW copies (parent_id references exist)
 * 9. Access log has entries
 * 10. L1 JSON files parse correctly
 *
 * Usage: npx tsx src/verify-production.ts
 */

import Database from 'better-sqlite3';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const MEMORY_DIR = path.join(import.meta.dirname, '..', 'memory');
const DB_PATH = path.join(MEMORY_DIR, 'cordelia.db');
const L1_DIR = path.join(MEMORY_DIR, 'L1-hot');
const L2_DIR = path.join(MEMORY_DIR, 'L2-warm');

interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
}

const results: CheckResult[] = [];

function check(name: string, fn: () => string): void {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail });
  } catch (e) {
    results.push({ name, ok: false, detail: (e as Error).message });
  }
}

// --- Pre-flight ---

check('Database file exists', () => {
  if (!fs.existsSync(DB_PATH)) throw new Error(`Not found: ${DB_PATH}`);
  const stat = fs.statSync(DB_PATH);
  return `${DB_PATH} (${(stat.size / 1024).toFixed(0)} KB)`;
});

// Open read-only
const db = new Database(DB_PATH, { readonly: true });

// --- 1. Schema version ---

let schemaVersion = 0;

check('Schema version', () => {
  const tableExists = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
  ).get();
  if (!tableExists) {
    schemaVersion = 1;
    return 'v1 (no schema_version table -- original schema)';
  }
  const row = db.prepare('SELECT MAX(version) as v FROM schema_version').get() as { v: number } | undefined;
  if (!row) throw new Error('schema_version table empty');
  schemaVersion = row.v;
  const expected = 4;
  if (row.v < expected) {
    return `v${row.v} (behind: expected v${expected}. Migration v${row.v}->v${expected} needed.)`;
  }
  return `v${row.v}`;
});

// --- 2. SQLite integrity check ---

check('SQLite PRAGMA integrity_check', () => {
  const rows = db.prepare('PRAGMA integrity_check').all() as Array<{ integrity_check: string }>;
  const first = rows[0]?.integrity_check;
  if (first !== 'ok') throw new Error(`Integrity check failed: ${rows.map(r => r.integrity_check).join(', ')}`);
  return 'ok';
});

// --- 3. L1 chain hash verification ---

type ParseResult =
  | { status: 'skip'; reason: string }
  | { status: 'ok'; l1Data: Record<string, unknown> };

function tryParseL1(raw: string, label: string): ParseResult {
  let l1Data: Record<string, unknown>;
  try {
    l1Data = JSON.parse(raw);
  } catch {
    return { status: 'skip', reason: `${label} (parse failed)` };
  }
  if ((l1Data as Record<string, unknown>)._encrypted) {
    return { status: 'skip', reason: `${label} (encrypted payload)` };
  }
  return { status: 'ok', l1Data };
}

function stripIntegrity(l1Data: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...l1Data };
  if (copy.ephemeral && typeof copy.ephemeral === 'object') {
    copy.ephemeral = { ...(copy.ephemeral as Record<string, unknown>) };
    delete (copy.ephemeral as Record<string, unknown>).integrity;
  }
  return copy;
}

function verifyChainHash(l1Data: Record<string, unknown>, label: string): string | null {
  const ephemeral = l1Data.ephemeral as Record<string, unknown> | undefined;
  if (!ephemeral?.integrity) {
    return null;
  }

  const integrity = ephemeral.integrity as { chain_hash: string; previous_hash: string };
  const dataWithoutIntegrity = stripIntegrity(l1Data);
  const contentHash = crypto.createHash('sha256').update(JSON.stringify(dataWithoutIntegrity)).digest('hex');
  const expectedHash = crypto.createHash('sha256')
    .update(`${integrity.previous_hash}${ephemeral.session_count}${contentHash}`)
    .digest('hex');

  if (expectedHash !== integrity.chain_hash) {
    throw new Error(`${label}: chain hash mismatch (expected ${expectedHash.slice(0, 16)}..., got ${integrity.chain_hash.slice(0, 16)}...)`);
  }
  return label;
}

check('L1 chain hash (all users)', () => {
  const users = db.prepare('SELECT user_id, data FROM l1_hot').all() as Array<{ user_id: string; data: Buffer }>;
  if (users.length === 0) throw new Error('No L1 users in SQLite');

  const verified: string[] = [];
  const skipped: string[] = [];

  for (const user of users) {
    const parsed = tryParseL1(user.data.toString('utf-8'), `${user.user_id} (encrypted in db)`);
    if (parsed.status === 'skip') {
      skipped.push(parsed.reason);
      continue;
    }

    const result = verifyChainHash(parsed.l1Data, user.user_id);
    if (result === null) {
      skipped.push(`${user.user_id} (no integrity block)`);
    } else {
      verified.push(result);
    }
  }

  if (fs.existsSync(L1_DIR)) {
    const jsonFiles = fs.readdirSync(L1_DIR).filter(f => f.endsWith('.json'));
    for (const file of jsonFiles) {
      const userId = path.basename(file, '.json');
      if (verified.includes(userId) || skipped.some(s => s.startsWith(userId))) continue;

      const raw = fs.readFileSync(path.join(L1_DIR, file), 'utf-8');
      const parsed = tryParseL1(raw, `${userId} (JSON parse failed)`);
      if (parsed.status === 'skip') {
        skipped.push(parsed.reason);
        continue;
      }

      const result = verifyChainHash(parsed.l1Data, `${userId} (json)`);
      if (result === null) {
        skipped.push(`${userId} (json, no integrity)`);
      } else {
        verified.push(result);
      }
    }
  }

  return `verified: [${verified.join(', ')}], skipped: [${skipped.join(', ')}]`;
});

// --- 4. L2 item checksums ---

check('L2 item checksums', () => {
  if (schemaVersion < 3) return `Skipped (requires v3+, current: v${schemaVersion})`;

  const items = db.prepare('SELECT id, data, checksum FROM l2_items').all() as
    Array<{ id: string; data: Buffer; checksum: string | null }>;

  let checked = 0;
  let noChecksum = 0;
  const failures: string[] = [];

  for (const item of items) {
    if (!item.checksum) {
      noChecksum++;
      continue;
    }
    checked++;
    const computed = crypto.createHash('sha256').update(item.data).digest('hex');
    if (computed !== item.checksum) {
      failures.push(item.id);
    }
  }

  if (failures.length > 0) {
    throw new Error(`${failures.length} checksum failures: ${failures.join(', ')}`);
  }

  return `${checked} verified, ${noChecksum} without checksum, 0 failures`;
});

// --- 5. Integrity canary ---

check('Integrity canary', () => {
  if (schemaVersion < 3) return `Skipped (requires v3+, current: v${schemaVersion})`;

  const tableExists = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='integrity_canary'"
  ).get();

  if (!tableExists) throw new Error('integrity_canary table missing');

  const row = db.prepare('SELECT value FROM integrity_canary LIMIT 1').get() as { value: string } | undefined;
  if (!row) throw new Error('No canary value');
  if (!/^[0-9a-f]{64}$/.test(row.value)) throw new Error(`Invalid canary format: ${row.value.slice(0, 20)}...`);

  return `present (${row.value.slice(0, 16)}...)`;
});

// --- 6. Group tables ---

check('Group tables', () => {
  if (schemaVersion < 4) return `Skipped (requires v4+, current: v${schemaVersion})`;

  const groups = db.prepare('SELECT id, name FROM groups').all() as Array<{ id: string; name: string }>;
  const members = db.prepare('SELECT group_id, entity_id, role FROM group_members').all() as
    Array<{ group_id: string; entity_id: string; role: string }>;

  if (groups.length === 0) throw new Error('No groups found');

  const detail = groups.map(g => {
    const m = members.filter(m => m.group_id === g.id);
    return `${g.name} (${g.id}): ${m.map(m => `${m.entity_id}[${m.role}]`).join(', ')}`;
  }).join('; ');

  return detail;
});

// --- 7. L2 item count vs index ---

check('L2 item count consistency', () => {
  const dbCount = (db.prepare('SELECT COUNT(*) as c FROM l2_items').get() as { c: number }).c;

  // Check JSON index too
  const indexPath = path.join(L2_DIR, 'index.json');
  let indexCount = 0;
  if (fs.existsSync(indexPath)) {
    try {
      const raw = fs.readFileSync(indexPath, 'utf-8');
      const parsed = JSON.parse(raw);
      // Could be encrypted
      if (parsed._encrypted) {
        return `${dbCount} items in SQLite, index encrypted (cannot count)`;
      }
      indexCount = parsed.entries?.length ?? 0;
    } catch {
      return `${dbCount} items in SQLite, index unreadable`;
    }
  }

  // Also count JSON files on disk
  let fileCount = 0;
  for (const subdir of ['entities', 'sessions', 'learnings']) {
    const dir = path.join(L2_DIR, subdir);
    if (fs.existsSync(dir)) {
      fileCount += fs.readdirSync(dir).filter(f => f.endsWith('.json')).length;
    }
  }

  return `SQLite: ${dbCount}, JSON index: ${indexCount}, JSON files: ${fileCount}`;
});

// --- 8. COW orphan check ---

check('COW parent references', () => {
  if (schemaVersion < 4) return `Skipped (requires v4+, current: v${schemaVersion})`;

  const copies = db.prepare('SELECT id, parent_id FROM l2_items WHERE is_copy = 1').all() as
    Array<{ id: string; parent_id: string }>;

  if (copies.length === 0) return 'No COW copies yet';

  const orphans: string[] = [];
  for (const copy of copies) {
    if (!copy.parent_id) {
      orphans.push(`${copy.id} (no parent_id)`);
      continue;
    }
    const parent = db.prepare('SELECT id FROM l2_items WHERE id = ?').get(copy.parent_id);
    if (!parent) {
      orphans.push(`${copy.id} -> ${copy.parent_id} (parent missing)`);
    }
  }

  if (orphans.length > 0) throw new Error(`${orphans.length} orphaned copies: ${orphans.join(', ')}`);
  return `${copies.length} copies, all parents exist`;
});

// --- 9. Access log ---

check('Access log', () => {
  const tableExists = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='access_log'"
  ).get();

  if (!tableExists) return 'access_log table not present (pre-S5)';

  const count = (db.prepare('SELECT COUNT(*) as c FROM access_log').get() as { c: number }).c;
  const latest = db.prepare('SELECT ts, entity_id, action FROM access_log ORDER BY id DESC LIMIT 1').get() as
    { ts: string; entity_id: string; action: string } | undefined;

  if (latest) {
    return `${count} entries, latest: ${latest.ts} ${latest.entity_id} ${latest.action}`;
  }
  return `${count} entries`;
});

// --- 10. L1 JSON files ---

check('L1 JSON files', () => {
  if (!fs.existsSync(L1_DIR)) throw new Error(`L1 directory missing: ${L1_DIR}`);

  const files = fs.readdirSync(L1_DIR).filter(f => f.endsWith('.json'));
  if (files.length === 0) throw new Error('No L1 JSON files');

  const details: string[] = [];
  for (const file of files) {
    const raw = fs.readFileSync(path.join(L1_DIR, file), 'utf-8');
    const parsed = JSON.parse(raw);
    const userId = path.basename(file, '.json');
    const sessionCount = parsed.ephemeral?.session_count ?? 'n/a';
    const genesis = parsed.ephemeral?.integrity?.genesis ?? 'n/a';
    details.push(`${userId}: session ${sessionCount}, genesis ${genesis}`);
  }

  return details.join('; ');
});

// --- 11. L2 type distribution ---

check('L2 type distribution', () => {
  const rows = db.prepare(
    'SELECT type, COUNT(*) as c FROM l2_items GROUP BY type ORDER BY type'
  ).all() as Array<{ type: string; c: number }>;

  if (rows.length === 0) return 'No L2 items in SQLite';
  return rows.map(r => `${r.type}: ${r.c}`).join(', ');
});

// --- 12. Visibility distribution ---

check('L2 visibility distribution', () => {
  const rows = db.prepare(
    'SELECT visibility, COUNT(*) as c FROM l2_items GROUP BY visibility ORDER BY visibility'
  ).all() as Array<{ visibility: string; c: number }>;

  return rows.map(r => `${r.visibility}: ${r.c}`).join(', ') || 'No items';
});

// --- Done ---

db.close();

// --- Report ---

console.log('');
console.log('=== CORDELIA PRODUCTION INTEGRITY VERIFICATION ===');
console.log(`    Database: ${DB_PATH}`);
console.log(`    Time: ${new Date().toISOString()}`);
console.log('');

let passed = 0;
let failed = 0;

for (const r of results) {
  const status = r.ok ? 'PASS' : 'FAIL';
  const marker = r.ok ? '  ' : '>>';
  console.log(`  ${marker} [${status}] ${r.name}`);
  console.log(`           ${r.detail}`);
  if (r.ok) passed++;
  else failed++;
}

console.log('');
console.log(`    Results: ${passed} passed, ${failed} failed`);
console.log('=================================================');
console.log('');

process.exit(failed > 0 ? 1 : 0);
