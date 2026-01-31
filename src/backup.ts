/**
 * Project Cordelia - Backup & Restore Module (R2-004)
 *
 * Provides backup/restore with integrity verification:
 * - createBackup: integrity check -> backup -> SHA-256 -> manifest
 * - restoreBackup: verify manifest -> integrity check source -> replace -> migrate -> rebuild -> verify
 * - verifyBackup: SHA-256 check + PRAGMA integrity_check + sample items
 *
 * Backups are SQLite database snapshots with a JSON manifest alongside.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { getStorageProvider } from './storage.js';
import type { SqliteStorageProvider } from './storage-sqlite.js';
import { periodicCheck, type IntegrityReport } from './integrity.js';

export interface BackupManifest {
  version: 1;
  created_at: string;
  schema_version: number;
  item_count: number;
  l1_users: string[];
  db_sha256: string;
  chain_hashes: Record<string, string>;
}

export interface BackupResult {
  manifest: BackupManifest;
  dbPath: string;
  manifestPath: string;
  size: number;
  duration_ms: number;
}

export interface RestoreResult {
  items: number;
  schemaVersion: number;
  integrityReport: IntegrityReport;
}

/**
 * Compute SHA-256 hash of a file.
 */
function sha256File(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Create a backup of the current database.
 *
 * Flow: integrityCheck -> storage.backup -> SHA-256 -> write manifest -> return
 */
export async function createBackup(destDir: string): Promise<BackupResult> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    throw new Error('Backup requires SQLite storage provider');
  }

  const sqliteProvider = storage as SqliteStorageProvider;

  // Pre-backup integrity check
  const preCheck = await storage.integrityCheck();
  if (!preCheck.ok) {
    throw new Error(`Pre-backup integrity check failed: ${preCheck.errors.join('; ')}`);
  }

  // Ensure destination directory exists
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dbFileName = `cordelia-backup-${timestamp}.db`;
  const dbPath = path.join(destDir, dbFileName);
  const manifestPath = path.join(destDir, `cordelia-backup-${timestamp}.manifest.json`);

  // Hot backup via better-sqlite3 backup API
  const backupResult = await storage.backup(dbPath);

  // Compute SHA-256 of backup file
  const dbSha256 = sha256File(dbPath);

  // Gather metadata
  const db = sqliteProvider.getDatabase();
  const versionRow = db.prepare('SELECT version FROM schema_version LIMIT 1').get() as { version: number };
  const itemCount = db.prepare('SELECT COUNT(*) as cnt FROM l2_items').get() as { cnt: number };
  const users = await storage.listL1Users();

  // Collect chain hashes for all users
  const chainHashes: Record<string, string> = {};
  for (const userId of users) {
    const buffer = await storage.readL1(userId);
    if (buffer) {
      try {
        const parsed = JSON.parse(buffer.toString('utf-8'));
        if (parsed.ephemeral?.integrity?.chain_hash) {
          chainHashes[userId] = parsed.ephemeral.integrity.chain_hash;
        }
      } catch {
        // Skip users with unparseable data (encrypted)
      }
    }
  }

  const manifest: BackupManifest = {
    version: 1,
    created_at: new Date().toISOString(),
    schema_version: versionRow.version,
    item_count: itemCount.cnt,
    l1_users: users,
    db_sha256: dbSha256,
    chain_hashes: chainHashes,
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  return {
    manifest,
    dbPath,
    manifestPath,
    size: backupResult.size,
    duration_ms: backupResult.duration_ms,
  };
}

/**
 * Restore from a backup directory.
 *
 * Flow: verify manifest SHA-256 -> integrity check source -> replace DB -> migrate -> rebuild FTS -> verify chains
 */
export async function restoreBackup(
  srcDir: string,
  opts?: { dryRun?: boolean },
): Promise<RestoreResult> {
  const storage = getStorageProvider();
  if (storage.name !== 'sqlite') {
    throw new Error('Restore requires SQLite storage provider');
  }

  // Find manifest and DB files
  const files = fs.readdirSync(srcDir);
  const manifestFile = files.find((f) => f.endsWith('.manifest.json'));
  const dbFile = files.find((f) => f.endsWith('.db'));

  if (!manifestFile || !dbFile) {
    throw new Error(`Backup directory missing manifest or database file: ${srcDir}`);
  }

  const manifestPath = path.join(srcDir, manifestFile);
  const dbPath = path.join(srcDir, dbFile);

  // Read and verify manifest
  const manifest: BackupManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));

  // Verify SHA-256
  const actualSha256 = sha256File(dbPath);
  if (actualSha256 !== manifest.db_sha256) {
    throw new Error(
      `SHA-256 mismatch: manifest says ${manifest.db_sha256}, file is ${actualSha256}. Backup may be corrupted.`,
    );
  }

  if (opts?.dryRun) {
    return {
      items: manifest.item_count,
      schemaVersion: manifest.schema_version,
      integrityReport: {
        ok: true,
        timestamp: new Date().toISOString(),
        checks: {
          database: { ok: true, errors: [] },
          chainHash: { ok: true, errors: ['Dry run - chain verification skipped'] },
          canary: { ok: true, errors: ['Dry run - canary check skipped'] },
          checksums: { ok: true, errors: [], checked: 0, failed: 0 },
        },
      },
    };
  }

  // Restore the database
  const sqliteProvider = storage as SqliteStorageProvider;
  const restoreResult = await sqliteProvider.restore(dbPath);

  // Post-restore integrity check
  const postCheck = await periodicCheck();

  return {
    items: restoreResult.items,
    schemaVersion: restoreResult.schemaVersion,
    integrityReport: postCheck,
  };
}

/**
 * Verify a backup without restoring it.
 *
 * Checks: SHA-256 match + PRAGMA integrity_check on backup DB + sample items readable.
 */
export async function verifyBackup(srcDir: string): Promise<{ ok: boolean; errors: string[]; manifest: BackupManifest }> {
  const errors: string[] = [];

  // Find files
  const files = fs.readdirSync(srcDir);
  const manifestFile = files.find((f) => f.endsWith('.manifest.json'));
  const dbFile = files.find((f) => f.endsWith('.db'));

  if (!manifestFile) {
    return { ok: false, errors: ['Missing manifest file'], manifest: {} as BackupManifest };
  }
  if (!dbFile) {
    return { ok: false, errors: ['Missing database file'], manifest: {} as BackupManifest };
  }

  const manifestPath = path.join(srcDir, manifestFile);
  const dbPath = path.join(srcDir, dbFile);

  // Read manifest
  let manifest: BackupManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  } catch (e) {
    return { ok: false, errors: [`Failed to parse manifest: ${(e as Error).message}`], manifest: {} as BackupManifest };
  }

  // SHA-256 check
  const actualSha256 = sha256File(dbPath);
  if (actualSha256 !== manifest.db_sha256) {
    errors.push(`SHA-256 mismatch: manifest=${manifest.db_sha256}, actual=${actualSha256}`);
  }

  // Open backup DB and run PRAGMA integrity_check
  try {
    const Database = (await import('better-sqlite3')).default;
    const db = new Database(dbPath, { readonly: true });
    try {
      const result = db.pragma('integrity_check') as Array<{ integrity_check: string }>;
      if (result[0]?.integrity_check !== 'ok') {
        errors.push(`PRAGMA integrity_check: ${result[0]?.integrity_check}`);
      }

      // Sample: verify items are readable
      const sampleItems = db.prepare('SELECT id, data FROM l2_items LIMIT 5').all() as Array<{ id: string; data: Buffer }>;
      for (const item of sampleItems) {
        if (!item.data || item.data.length === 0) {
          errors.push(`Empty data for item ${item.id}`);
        }
      }
    } finally {
      db.close();
    }
  } catch (e) {
    errors.push(`Failed to verify backup database: ${(e as Error).message}`);
  }

  return { ok: errors.length === 0, errors, manifest };
}
