#!/usr/bin/env npx tsx
/**
 * One-time setup for sync
 *
 * Creates user profile on remote and generates API key.
 * Run once, then use the API key with sync-daemon.ts
 *
 * Usage:
 *   npx tsx scripts/setup-sync.ts [userId]
 */

import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';

const REMOTE_URL = process.env.CORDELIA_REMOTE_URL || 'https://cordelia-seed-drill.fly.dev';
const MEMORY_ROOT = process.env.CORDELIA_MEMORY_ROOT || path.join(import.meta.dirname, '..', 'memory');

const userId = process.argv[2] || 'budgester';
const localPath = path.join(MEMORY_ROOT, 'L1-hot', `${userId}.json`);

function log(message: string) {
  console.log(`[setup] ${message}`);
}

async function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function main() {
  log(`Setting up sync for user: ${userId}`);
  log(`Local path: ${localPath}`);
  log(`Remote URL: ${REMOTE_URL}`);
  log('');

  // Check if local profile exists
  if (!fs.existsSync(localPath)) {
    log(`Error: Local profile not found at ${localPath}`);
    process.exit(1);
  }

  const localContext = JSON.parse(fs.readFileSync(localPath, 'utf-8'));
  log(`Found local profile: ${localContext.identity?.name || userId}`);

  // Check if remote profile exists
  const remoteResponse = await fetch(`${REMOTE_URL}/api/hot/${userId}`);
  const remoteExists = remoteResponse.ok;

  if (remoteExists) {
    log('Remote profile already exists');
  } else {
    log('Remote profile does not exist - needs to be created via dashboard');
    log('');
    log('Please complete these steps:');
    log(`1. Open ${REMOTE_URL} in your browser`);
    log('2. Login with GitHub');
    log('3. Select "Yes - I want to upload my local profile"');
    log('4. Copy the API key shown');
    log('5. Come back here and paste it');
    log('');
  }

  // Get API key from user
  const apiKey = await prompt('Enter your API key (ck_...): ');

  if (!apiKey.startsWith('ck_')) {
    log('Error: Invalid API key format (should start with ck_)');
    process.exit(1);
  }

  // Test the API key by uploading local profile
  log('Testing API key...');

  const uploadResponse = await fetch(`${REMOTE_URL}/api/hot/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': apiKey,
    },
    body: JSON.stringify(localContext),
  });

  if (!uploadResponse.ok) {
    const error = await uploadResponse.json().catch(() => ({ error: uploadResponse.statusText }));
    log(`Error: Upload failed - ${error.error || uploadResponse.statusText}`);
    process.exit(1);
  }

  log('API key verified and local profile uploaded!');
  log('');
  log('Add this to your shell profile (.bashrc, .zshrc, etc.):');
  log('');
  log(`  export CORDELIA_API_KEY="${apiKey}"`);
  log('');
  log('Then start the sync daemon:');
  log('');
  log(`  npm run sync ${userId}`);
  log('');
  log('Or run it in the background:');
  log('');
  log(`  CORDELIA_API_KEY="${apiKey}" nohup npm run sync ${userId} > sync.log 2>&1 &`);
  log('');

  // Also save to a local .env file for convenience
  const envPath = path.join(import.meta.dirname, '..', '.env.sync');
  fs.writeFileSync(envPath, `CORDELIA_API_KEY=${apiKey}\n`);
  log(`API key also saved to ${envPath}`);
}

try {
  await main();
} catch (error) {
  log(`Fatal error: ${(error as Error).message}`);
  process.exit(1);
}
