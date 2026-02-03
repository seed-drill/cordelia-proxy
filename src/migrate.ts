#!/usr/bin/env node
/**
 * Project Cordelia - JSON to SQLite Migration Script
 *
 * Migrates existing JSON file storage to SQLite database.
 * JSON files are NOT deleted - they remain as backup.
 *
 * Usage: npm run migrate
 */

import * as fs from 'fs/promises';
import * as fsSync from 'fs';
import * as path from 'path';
import { SqliteStorageProvider } from './storage-sqlite.js';

const MEMORY_ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'memory');
const DB_PATH = path.join(MEMORY_ROOT, 'cordelia.db');

async function migrateL1(sqlite: SqliteStorageProvider, memoryRoot: string): Promise<number> {
  const l1Dir = path.join(memoryRoot, 'L1-hot');
  let count = 0;
  try {
    const l1Files = await fs.readdir(l1Dir);
    for (const file of l1Files) {
      if (!file.endsWith('.json')) continue;
      const userId = path.basename(file, '.json');
      const data = await fs.readFile(path.join(l1Dir, file));
      await sqlite.writeL1(userId, data);
      count++;
    }
    console.log(`Migrated ${count} L1 hot context files`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    console.log('No L1 hot context files found');
  }
  return count;
}

async function migrateL2Items(sqlite: SqliteStorageProvider, memoryRoot: string): Promise<number> {
  const l2Subdirs: Array<{ dir: string; type: string }> = [
    { dir: 'entities', type: 'entity' },
    { dir: 'sessions', type: 'session' },
    { dir: 'learnings', type: 'learning' },
  ];

  let count = 0;
  for (const { dir, type } of l2Subdirs) {
    const dirPath = path.join(memoryRoot, 'L2-warm', dir);
    try {
      const files = await fs.readdir(dirPath);
      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        const id = path.basename(file, '.json');
        const data = await fs.readFile(path.join(dirPath, file));
        await sqlite.writeL2Item(id, type, data, {
          type: type as 'entity' | 'session' | 'learning',
        });
        count++;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  console.log(`Migrated ${count} L2 items`);
  return count;
}

async function migrateAuditLog(sqlite: SqliteStorageProvider, memoryRoot: string): Promise<number> {
  const auditPath = path.join(memoryRoot, 'audit.jsonl');
  let count = 0;
  try {
    const auditContent = await fs.readFile(auditPath, 'utf-8');
    const lines = auditContent.split('\n').filter((line) => line.trim().length > 0);
    for (const line of lines) {
      await sqlite.appendAudit(line);
      count++;
    }
    console.log(`Migrated ${count} audit entries`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    console.log('No audit log found');
  }
  return count;
}

async function rebuildMigrationIndex(sqlite: SqliteStorageProvider, memoryRoot: string): Promise<void> {
  // The index is derived data - rebuild it rather than copying a potentially
  // corrupted index.json. This requires the storage provider to be set to
  // SQLite so rebuildIndex() writes to the correct backend.
  const { setStorageProvider } = await import('./storage.js');
  const { getConfig: getCryptoConfig, loadOrCreateSalt, initCrypto } = await import('./crypto.js');
  setStorageProvider(sqlite);

  // Initialize encryption so we can decrypt items for index keyword extraction
  const passphrase = process.env.CORDELIA_ENCRYPTION_KEY;
  const cryptoConfig = getCryptoConfig(memoryRoot);
  if (cryptoConfig.enabled && passphrase) {
    const salt = await loadOrCreateSalt(cryptoConfig.saltDir, 'global');
    await initCrypto(passphrase, salt);
    console.log('Encryption initialized for index rebuild');
  }

  const { rebuildIndex } = await import('./l2.js');
  const rebuildResult = await rebuildIndex();
  if ('error' in rebuildResult) {
    console.error(`WARNING: Index rebuild failed: ${rebuildResult.error}`);
    console.error('Run "npm run rebuild-index" manually after migration.');
  } else {
    console.log(`Rebuilt L2 index: ${rebuildResult.count} entries indexed`);
  }
}

async function migrate(): Promise<void> {
  console.log('Cordelia: JSON -> SQLite Migration');
  console.log('='.repeat(40));

  // Check if database already exists
  if (fsSync.existsSync(DB_PATH)) {
    console.error(`ERROR: Database already exists at ${DB_PATH}`);
    console.error('Remove it first if you want to re-migrate.');
    process.exit(1);
  }

  // Create SQLite provider and initialize schema
  const sqlite = new SqliteStorageProvider(MEMORY_ROOT);
  await sqlite.initialize();
  console.log('Created SQLite database with schema');

  const l1Count = await migrateL1(sqlite, MEMORY_ROOT);
  const l2Count = await migrateL2Items(sqlite, MEMORY_ROOT);

  // INCIDENT-001: Never copy index.json verbatim - it may be corrupted.
  // The index is derived data. Rebuild it from items post-migration.
  await rebuildMigrationIndex(sqlite, MEMORY_ROOT);

  const auditCount = await migrateAuditLog(sqlite, MEMORY_ROOT);

  // Verify SQLite integrity
  const db = sqlite.getDatabase();
  const integrityResult = db.pragma('integrity_check') as Array<{ integrity_check: string }>;
  const integrityOk = integrityResult.length === 1 && integrityResult[0].integrity_check === 'ok';

  if (!integrityOk) {
    console.error('WARNING: Integrity check failed!');
    console.error(integrityResult);
  } else {
    console.log('Integrity check: OK');
  }

  await sqlite.close();

  console.log('\n' + '='.repeat(40));
  console.log(`Migration complete:`);
  console.log(`  L1 users:     ${l1Count}`);
  console.log(`  L2 items:     ${l2Count}`);
  console.log(`  Audit entries: ${auditCount}`);
  console.log(`  Database:      ${DB_PATH}`);
  console.log('\nJSON files have NOT been deleted (backup).');
  console.log('SQLite is now the default storage backend.');
}

migrate().catch((error) => {
  console.error('Migration failed:', error);
  process.exit(1);
});
