/**
 * Project Cordelia - Three-Domain Memory Model
 *
 * Domain classification for L2 memories:
 *   value      - permanent, foundational (preferences, entities, references)
 *   procedural - usage-based lifecycle (corrections, patterns, updates)
 *   interrupt  - time-based TTL (decisions, blockers, sessions)
 *
 * Domain is edge-only metadata -- never in encrypted blob, never on wire.
 */

import type { NoveltySignal } from './novelty.js';

// =============================================================================
// Domain Types & Constants
// =============================================================================

export type MemoryDomain = 'value' | 'procedural' | 'interrupt';

/** Interrupt items expire after 3 days (259200 seconds). */
export const INTERRUPT_TTL_SECONDS = 259200;

/** Max procedural items before FIFO eviction by lowest access_count. */
export const PROCEDURAL_CAP = 100;

// =============================================================================
// Signal-to-Domain Classification
// =============================================================================

/**
 * Map novelty signals to memory domains.
 * Insight/meta_learning default to procedural but promote to value at high confidence.
 */
const SIGNAL_DOMAIN_MAP: Record<NoveltySignal, MemoryDomain> = {
  preference: 'value',
  entity_new: 'value',
  reference: 'value',
  correction: 'procedural',
  working_pattern: 'procedural',
  entity_update: 'procedural',
  insight: 'procedural',
  meta_learning: 'procedural',
  decision: 'interrupt',
  blocker: 'interrupt',
};

/**
 * Classify a novelty signal into a memory domain.
 * High-confidence insights/meta_learnings promote to value.
 */
export function classifyDomain(signal: NoveltySignal, confidence: number): MemoryDomain {
  const base = SIGNAL_DOMAIN_MAP[signal];
  if ((signal === 'insight' || signal === 'meta_learning') && confidence >= 0.85) {
    return 'value';
  }
  return base;
}

// =============================================================================
// TTL Helpers
// =============================================================================

/**
 * Compute interrupt TTL expiry: 3 days from now as ISO string.
 */
export function computeInterruptTtl(): string {
  return new Date(Date.now() + INTERRUPT_TTL_SECONDS * 1000).toISOString();
}

// =============================================================================
// Type-based Domain Inference
// =============================================================================

/**
 * Infer domain from item type when no explicit domain is provided.
 * Conservative: defaults to procedural rather than guessing value.
 */
export function inferDomainFromType(
  itemType: 'entity' | 'session' | 'learning',
  learningSubtype?: string,
): MemoryDomain {
  switch (itemType) {
    case 'session':
      return 'interrupt';
    case 'learning':
      if (learningSubtype === 'principle') return 'value';
      return 'procedural';
    case 'entity':
      return 'procedural';
    default:
      return 'procedural';
  }
}

// =============================================================================
// L1 Size Budget Enforcement
// =============================================================================

/** Context window size in tokens (configurable via env, default 200K). */
export const CONTEXT_WINDOW = parseInt(process.env.CORDELIA_CONTEXT_WINDOW || '200000', 10);

/** Approximate bytes-per-token for JSON content (~4 bytes/token for structured JSON). */
const BYTES_PER_TOKEN = 4;

/** L1 total budget: 2% of context window. */
const L1_TOTAL_PERCENT = 0.02;

/** Per-section budgets as fraction of L1 total. */
export const L1_BUDGET_FRACTIONS = {
  identity: 0.30,
  prefs: 0.08,
  delegation: 0.08,
  active: 0.30,
  ephemeral: 0.24,
} as const;

export interface L1Budgets {
  total: number;
  sections: Record<string, number>;
}

/**
 * Compute L1 byte budgets from context window size.
 */
export function getL1Budgets(): L1Budgets {
  const totalBytes = Math.floor(CONTEXT_WINDOW * L1_TOTAL_PERCENT * BYTES_PER_TOKEN);
  return {
    total: totalBytes,
    sections: Object.fromEntries(
      Object.entries(L1_BUDGET_FRACTIONS).map(([k, v]) => [k, Math.floor(totalBytes * v)])
    ),
  };
}

export interface L1BudgetViolation {
  section: string;
  actual: number;
  budget: number;
}

/**
 * Check an L1 object against size budgets.
 * Returns ok:true or a list of violations with actual vs budget sizes.
 */
export function checkL1Budget(
  l1: Record<string, unknown>,
): { ok: true } | { ok: false; violations: L1BudgetViolation[]; actual: Record<string, number> } {
  const budgets = getL1Budgets();
  const violations: L1BudgetViolation[] = [];
  const actual: Record<string, number> = {};

  let totalSize = 0;

  for (const [section, budget] of Object.entries(budgets.sections)) {
    const sectionData = l1[section];
    if (sectionData === undefined) {
      actual[section] = 0;
      continue;
    }
    const size = Buffer.byteLength(JSON.stringify(sectionData), 'utf-8');
    actual[section] = size;
    totalSize += size;
    if (size > budget) {
      violations.push({ section, actual: size, budget });
    }
  }

  // Account for keys not in budget sections (version, updated_at, etc.)
  const fullSize = Buffer.byteLength(JSON.stringify(l1), 'utf-8');
  actual['_total'] = fullSize;

  if (fullSize > budgets.total) {
    violations.push({ section: '_total', actual: fullSize, budget: budgets.total });
  }

  if (violations.length > 0) {
    return { ok: false, violations, actual };
  }
  return { ok: true };
}
