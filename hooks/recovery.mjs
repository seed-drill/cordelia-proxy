#!/usr/bin/env node
/**
 * Cordelia Recovery Module - Shared recovery logic for session hooks
 *
 * Recovery strategies (in order):
 * 1. Try .backup file if exists
 * 2. Restore from git (most recent valid commit)
 * 3. Alert user and fail gracefully
 */
import * as fs from 'fs/promises';
import * as path from 'path';
import { execSync } from 'child_process';

/**
 * Attempt to recover L1 memory from backup or git
 * @param {string} l1Path - Path to the L1 JSON file
 * @param {string} cordeliaDir - Root cordelia directory (for git operations)
 * @returns {Promise<{recovered: boolean, source: string, error?: string}>}
 */
export async function attemptRecovery(l1Path, cordeliaDir) {
  const backupPath = `${l1Path}.backup`;
  const relativePath = path.relative(cordeliaDir, l1Path);

  // Strategy 1: Try backup file
  try {
    await fs.access(backupPath);
    const backupContent = await fs.readFile(backupPath, 'utf-8');
    await fs.writeFile(l1Path, backupContent);
    await fs.unlink(backupPath); // Remove backup after successful restore
    return { recovered: true, source: 'backup file' };
  } catch {
    // No backup file or backup also corrupted, continue to git
  }

  // Strategy 2: Try git restore
  try {
    // Find the most recent commit that has our file
    const logOutput = execSync(
      `git log --oneline -10 -- "${relativePath}"`,
      { cwd: cordeliaDir, encoding: 'utf-8' }
    );

    const commits = logOutput.trim().split('\n').filter(Boolean);
    if (commits.length === 0) {
      return { recovered: false, error: 'No git history for this file' };
    }

    // Try each commit until we find one that decrypts successfully
    // (We can't actually test decryption here, so we just restore the most recent)
    const mostRecentCommit = commits[0].split(' ')[0];

    // Restore from git
    execSync(`git checkout ${mostRecentCommit} -- "${relativePath}"`, {
      cwd: cordeliaDir,
      encoding: 'utf-8',
    });

    return { recovered: true, source: `git commit ${mostRecentCommit}` };
  } catch (gitError) {
    return { recovered: false, error: `Git restore failed: ${gitError.message}` };
  }
}

/**
 * Create a backup of the current L1 file before risky operations
 * @param {string} l1Path - Path to the L1 JSON file
 */
export async function createBackup(l1Path) {
  const backupPath = `${l1Path}.backup`;
  try {
    const content = await fs.readFile(l1Path, 'utf-8');
    await fs.writeFile(backupPath, content);
    return true;
  } catch {
    return false;
  }
}

/**
 * Remove backup file after successful operation
 * @param {string} l1Path - Path to the L1 JSON file
 */
export async function removeBackup(l1Path) {
  const backupPath = `${l1Path}.backup`;
  try {
    await fs.unlink(backupPath);
  } catch {
    // Ignore - backup may not exist
  }
}

/**
 * Send macOS notification
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 */
export function notify(title, message) {
  try {
    execSync(`osascript -e 'display notification "${message}" with title "${title}"'`);
  } catch {
    // Ignore notification failures
  }
}
