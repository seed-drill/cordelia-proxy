#!/usr/bin/env node
/**
 * Cordelia E5 - Migrate v0/v1 items to v2 (group PSK encryption)
 *
 * Opens the node's SQLite database directly and:
 *   1. Finds all items with key_version < 2
 *   2. Encrypts plaintext data with the personal group PSK
 *   3. Updates key_version=2, group_id, visibility='group' in place
 *
 * Items that already have a group_id keep it (e.g. seed-drill items stay in seed-drill).
 * Items without a group_id get assigned to the personal group.
 *
 * Idempotent: skips items already at key_version >= 2.
 * Non-destructive: errors logged per-item, migration continues.
 *
 * Usage: npm run migrate:v2
 *
 * Prerequisites:
 *   - Node process should be stopped (avoids WAL contention)
 *   - Personal group PSK at ~/.cordelia/group-keys/{personal_group_id}.json
 *   - config.toml has [node] personal_group set
 */

import * as path from 'path';
import * as os from 'os';
import Database from 'better-sqlite3';
import { getGroupKey, groupEncrypt } from './group-keys.js';
import { getPersonalGroup } from './storage.js';

interface MigrationResult {
  migrated: number;
  skipped: number;
  errors: number;
  errorIds: string[];
}

async function migrate(): Promise<MigrationResult> {
  console.log('Cordelia E5: v0/v1 -> v2 encryption migration');
  console.log('='.repeat(50));

  // 1. Resolve personal group ID
  const personalGroupId = await getPersonalGroup();
  if (!personalGroupId) {
    console.error('ERROR: No personal group configured.');
    console.error('Set [node] personal_group in ~/.cordelia/config.toml');
    process.exit(1);
  }
  console.log(`Personal group: ${personalGroupId}`);

  // 2. Verify personal group PSK is available
  const groupKey = await getGroupKey(personalGroupId);
  if (!groupKey) {
    console.error(`ERROR: No PSK found for personal group ${personalGroupId}`);
    console.error('Enroll this device to receive the group PSK.');
    process.exit(1);
  }
  console.log('Personal group PSK loaded');

  // 3. Open node database directly
  const dbPath = path.join(os.homedir(), '.cordelia', 'cordelia.db');
  console.log(`Node database: ${dbPath}`);
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');

  // 4. Find all items needing migration
  const items = db.prepare(
    'SELECT id, type, data, group_id FROM l2_items WHERE key_version < 2',
  ).all() as Array<{ id: string; type: string; data: Buffer; group_id: string | null }>;

  console.log(`Found ${items.length} items needing migration`);
  if (items.length === 0) {
    console.log('Nothing to migrate.');
    db.close();
    return { migrated: 0, skipped: 0, errors: 0, errorIds: [] };
  }

  // 5. Migrate each item
  const result: MigrationResult = { migrated: 0, skipped: 0, errors: 0, errorIds: [] };

  const updateStmt = db.prepare(
    `UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = 'group', updated_at = datetime('now') WHERE id = ? AND key_version < 2`,
  );

  for (const item of items) {
    try {
      // Parse stored data
      let parsed: unknown;
      try {
        parsed = JSON.parse(item.data.toString('utf-8'));
      } catch {
        console.warn(`  SKIP ${item.id}: not valid JSON`);
        result.skipped++;
        continue;
      }

      // Encrypt with group PSK
      const plaintext = Buffer.from(JSON.stringify(parsed), 'utf-8');
      const encrypted = await groupEncrypt(plaintext, groupKey);
      const newData = Buffer.from(JSON.stringify(encrypted), 'utf-8');

      // Keep existing group_id if set, otherwise assign to personal group
      const targetGroup = item.group_id || personalGroupId;
      updateStmt.run(newData, targetGroup, item.id);
      result.migrated++;

      if (result.migrated % 50 === 0) {
        console.log(`  Progress: ${result.migrated}/${items.length}`);
      }
    } catch (err) {
      console.error(`  ERROR ${item.id}: ${(err as Error).message}`);
      result.errors++;
      result.errorIds.push(item.id);
    }
  }

  db.close();

  // 6. Report
  console.log('\n' + '='.repeat(50));
  console.log('Migration complete:');
  console.log(`  Migrated:  ${result.migrated}`);
  console.log(`  Skipped:   ${result.skipped}`);
  console.log(`  Errors:    ${result.errors}`);
  if (result.errorIds.length > 0) {
    console.log(`  Failed IDs: ${result.errorIds.join(', ')}`);
  }

  return result;
}

try {
  await migrate();
} catch (error) {
  console.error('Migration failed:', error);
  process.exit(1);
}
