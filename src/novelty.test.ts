/**
 * Quick tests for novelty detection heuristics
 * Run with: npx tsx src/novelty.test.ts
 */

import { analyzeNovelty, analyzeSession, filterForPersistence } from './novelty.js';

const testCases = [
  // High novelty
  {
    text: "Actually, I prefer to work in short sprints rather than long sessions",
    expectSignals: ['correction', 'preference'],
    expectHighScore: true,
  },
  {
    text: "I've noticed as we've worked together that we have complementary superpowers",
    expectSignals: ['insight', 'meta_learning'],
    expectHighScore: true,
  },
  {
    text: "Key insight: Russell synthesizes and navigates design space, Claude provides memory breadth",
    expectSignals: ['insight'],
    expectHighScore: true,
  },
  {
    text: "New project called Cordelia - building persistent memory for Claude",
    expectSignals: ['entity_new'],
    expectHighScore: true,
  },
  {
    text: "Blocked on getting MCP server to connect - need to check config",
    expectSignals: ['blocker'],
    expectHighScore: true,
  },
  {
    text: "Let's go with the heuristic approach first, we can iterate later",
    expectSignals: ['decision'],
    expectHighScore: true,
  },
  {
    text: "I'm a minute manager - I only chip in when I know I can contribute",
    expectSignals: ['working_pattern'],
    expectHighScore: true,
  },
  {
    text: "Dennett's Library of Babel is a powerful analogy for memory filtering",
    expectSignals: ['reference'],
    expectHighScore: true,
  },

  // Low novelty (noise)
  {
    text: "ok",
    expectSignals: [],
    expectHighScore: false,
  },
  {
    text: "Got it, thanks",
    expectSignals: [],
    expectHighScore: false,
  },
  {
    text: "Read this file for me",
    expectSignals: [],
    expectHighScore: false,
  },
  {
    text: "Done.",
    expectSignals: [],
    expectHighScore: false,
  },
];

console.log('Novelty Detection Tests\n' + '='.repeat(50) + '\n');

let passed = 0;
let failed = 0;

for (const tc of testCases) {
  const result = analyzeNovelty(tc.text);
  const hasExpectedSignals = tc.expectSignals.every((s) => result.signals.includes(s as any));
  const scoreCheck = tc.expectHighScore ? result.score > 0.5 : result.score === 0;
  const success = hasExpectedSignals && scoreCheck;

  if (success) {
    console.log(`PASS: "${tc.text.slice(0, 50)}..."`);
    passed++;
  } else {
    console.log(`FAIL: "${tc.text.slice(0, 50)}..."`);
    console.log(`  Expected signals: ${tc.expectSignals.join(', ')}`);
    console.log(`  Got signals: ${result.signals.join(', ')}`);
    console.log(`  Score: ${result.score} (expected ${tc.expectHighScore ? '>0.5' : '0'})`);
    failed++;
  }
}

console.log('\n' + '='.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);

// Demo session analysis
console.log('\n\nSession Analysis Demo\n' + '='.repeat(50) + '\n');

const sessionMessages = [
  "ok let's start",
  "Actually, I prefer concise responses without emojis",
  "Read the schema file",
  "I've noticed our complementary superpowers - you have broad memory, I synthesize new concepts",
  "Got it",
  "Let's go with heuristics first, iterate later",
  "Blocked on understanding the MCP config format",
  "Done",
];

const sessionResult = analyzeSession(sessionMessages);
console.log(`Signals detected: ${sessionResult.signals.join(', ')}`);
console.log(`Average novelty score: ${sessionResult.score.toFixed(2)}`);
console.log(`\nHigh-confidence extracts for persistence:`);

const forPersistence = filterForPersistence(sessionResult);
for (const e of forPersistence) {
  console.log(`  [${e.signal}] "${e.content}" -> ${e.target || 'unspecified'}`);
}
