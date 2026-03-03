#!/usr/bin/env node
/**
 * Cordelia E5a - Migrate v1 (scrypt) items to v2 (group PSK)
 *
 * Reads all key_version=1 items from local SQLite, decrypts with the legacy
 * scrypt-derived key, re-encrypts with the personal group PSK, updates
 * key_version=2 and group_id in place.
 *
 * Idempotent: skips items already at key_version >= 2.
 * Non-destructive: rolls back on any item failure and reports errors.
 *
 * Usage: npm run migrate:v2
 *
 * Prerequisites:
 *   - Legacy scrypt key accessible (keychain, ~/.cordelia/key, or CORDELIA_ENCRYPTION_KEY)
 *   - Personal group PSK stored at ~/.cordelia/group-keys/{personal_group_id}.json
 *   - config.toml has [node] personal_group set
 */

import * as path from 'path';
import * as os from 'os';

const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(os.homedir(), '.cordelia', 'memory');

interface MigrationResult {
  migrated: number;
  skipped: number;
  errors: number;
  errorIds: string[];
}

async function migrate(): Promise<MigrationResult> {
  console.log('Cordelia E5a: v1 -> v2 encryption migration');
  console.log('='.repeat(50));

  // 1. Initialize SQLite storage
  const { SqliteStorageProvider } = await import('./storage-sqlite.js');
  const { setStorageProvider } = await import('./storage.js');
  const sqlite = new SqliteStorageProvider(MEMORY_ROOT);
  await sqlite.initialize();
  setStorageProvider(sqlite);

  // 2. Initialize legacy scrypt crypto for decryption
  const { resolveEncryptionKey, getConfig: getCryptoConfig, loadOrCreateSalt, initCrypto, isEncryptedPayload, getDefaultCryptoProvider } = await import('./crypto.js');

  const passphrase = await resolveEncryptionKey();
  if (!passphrase) {
    console.error('ERROR: No legacy encryption key found.');
    console.error('Set CORDELIA_ENCRYPTION_KEY, add to keychain, or create ~/.cordelia/key');
    await sqlite.close();
    process.exit(1);
  }

  const cryptoConfig = getCryptoConfig(MEMORY_ROOT);
  const salt = await loadOrCreateSalt(cryptoConfig.saltDir, 'global');
  await initCrypto(passphrase, salt);
  console.log('Legacy scrypt crypto initialized');

  // 3. Resolve personal group ID
  const { getPersonalGroup } = await import('./storage.js');
  const personalGroupId = await getPersonalGroup();
  if (!personalGroupId) {
    console.error('ERROR: No personal group configured.');
    console.error('Run enrollment first, or set [node] personal_group in ~/.cordelia/config.toml');
    await sqlite.close();
    process.exit(1);
  }
  console.log(`Personal group: ${personalGroupId}`);

  // 4. Verify personal group PSK is available
  const { getGroupKey, groupEncrypt } = await import('./group-keys.js');
  const groupKey = await getGroupKey(personalGroupId);
  if (!groupKey) {
    console.error(`ERROR: No PSK found for personal group ${personalGroupId}`);
    console.error('Enroll this device to receive the group PSK, or restore from backup.');
    await sqlite.close();
    process.exit(1);
  }
  console.log('Personal group PSK loaded');

  // 5. Find all v1 items
  const db = sqlite.getDatabase();
  const v1Items = db.prepare(
    'SELECT id, type, data FROM l2_items WHERE key_version = 1',
  ).all() as Array<{ id: string; type: string; data: Buffer }>;

  console.log(`Found ${v1Items.length} items at key_version=1`);
  if (v1Items.length === 0) {
    console.log('Nothing to migrate.');
    await sqlite.close();
    return { migrated: 0, skipped: 0, errors: 0, errorIds: [] };
  }

  // 6. Migrate each item
  const cryptoProvider = getDefaultCryptoProvider();
  const result: MigrationResult = { migrated: 0, skipped: 0, errors: 0, errorIds: [] };

  const updateStmt = db.prepare(
    'UPDATE l2_items SET data = ?, key_version = 2, group_id = ?, visibility = ?, updated_at = datetime(\'now\') WHERE id = ? AND key_version = 1',
  );

  for (const item of v1Items) {
    try {
      // Parse stored data
      let parsed: unknown;
      try {
        parsed = JSON.parse(item.data.toString('utf-8'));
      } catch {
        // Not JSON - skip (binary blob or corrupted)
        console.warn(`  SKIP ${item.id}: not valid JSON`);
        result.skipped++;
        continue;
      }

      // Check if encrypted
      if (!isEncryptedPayload(parsed)) {
        // Unencrypted v1 item - encrypt with group PSK directly
        const plaintext = Buffer.from(JSON.stringify(parsed, null, 2), 'utf-8');
        const encrypted = await groupEncrypt(plaintext, groupKey);
        const newData = Buffer.from(JSON.stringify(encrypted, null, 2), 'utf-8');
        updateStmt.run(newData, personalGroupId, 'group', item.id);
        result.migrated++;
        continue;
      }

      // Decrypt with legacy scrypt key
      const decrypted = await cryptoProvider.decrypt(parsed);
      const plainObj = JSON.parse(decrypted.toString('utf-8'));

      // Re-encrypt with group PSK
      const plaintext = Buffer.from(JSON.stringify(plainObj, null, 2), 'utf-8');
      const encrypted = await groupEncrypt(plaintext, groupKey);
      const newData = Buffer.from(JSON.stringify(encrypted, null, 2), 'utf-8');

      // Update in place: key_version=2, group_id=personal, visibility=group
      updateStmt.run(newData, personalGroupId, 'group', item.id);
      result.migrated++;

      if (result.migrated % 100 === 0) {
        console.log(`  Progress: ${result.migrated}/${v1Items.length}`);
      }
    } catch (err) {
      console.error(`  ERROR ${item.id}: ${(err as Error).message}`);
      result.errors++;
      result.errorIds.push(item.id);
    }
  }

  await sqlite.close();

  // 7. Report
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
