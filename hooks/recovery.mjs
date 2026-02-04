#!/usr/bin/env node
/**
 * Cordelia Recovery Module - Notifications
 *
 * File-based recovery (backup/git restore) removed in favour of
 * single-store architecture (MCP over SQLite). Durability via WAL + remote sync.
 */
import { execSync } from 'child_process';

/**
 * Send macOS notification
 * @param {string} title - Notification title
 * @param {string} message - Notification message
 */
export function notify(title, message) {
  try {
    const safeTitle = title.replace(/[\\"]/g, '');
    const safeMessage = message.replace(/[\\"]/g, '');
    execSync(`osascript -e 'display notification "${safeMessage}" with title "${safeTitle}"'`);
  } catch {
    // Ignore notification failures
  }
}
