/**
 * Tests for src/domain.ts - Three-Domain Memory Model
 *
 * Pure function tests: classification, TTL computation, inference, L1 budget.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  classifyDomain,
  computeInterruptTtl,
  inferDomainFromType,
  checkL1Budget,
  getL1Budgets,
  INTERRUPT_TTL_SECONDS,
  PROCEDURAL_CAP,
} from './domain.js';

describe('classifyDomain', () => {
  it('maps preference to value', () => {
    assert.strictEqual(classifyDomain('preference', 0.8), 'value');
  });

  it('maps entity_new to value', () => {
    assert.strictEqual(classifyDomain('entity_new', 0.7), 'value');
  });

  it('maps reference to value', () => {
    assert.strictEqual(classifyDomain('reference', 0.9), 'value');
  });

  it('maps correction to procedural', () => {
    assert.strictEqual(classifyDomain('correction', 0.9), 'procedural');
  });

  it('maps working_pattern to procedural', () => {
    assert.strictEqual(classifyDomain('working_pattern', 0.8), 'procedural');
  });

  it('maps entity_update to procedural', () => {
    assert.strictEqual(classifyDomain('entity_update', 0.7), 'procedural');
  });

  it('maps decision to interrupt', () => {
    assert.strictEqual(classifyDomain('decision', 0.8), 'interrupt');
  });

  it('maps blocker to interrupt', () => {
    assert.strictEqual(classifyDomain('blocker', 0.9), 'interrupt');
  });

  it('promotes insight to value at high confidence', () => {
    assert.strictEqual(classifyDomain('insight', 0.85), 'value');
    assert.strictEqual(classifyDomain('insight', 0.9), 'value');
  });

  it('keeps insight as procedural at lower confidence', () => {
    assert.strictEqual(classifyDomain('insight', 0.84), 'procedural');
    assert.strictEqual(classifyDomain('insight', 0.5), 'procedural');
  });

  it('promotes meta_learning to value at high confidence', () => {
    assert.strictEqual(classifyDomain('meta_learning', 0.85), 'value');
  });

  it('keeps meta_learning as procedural at lower confidence', () => {
    assert.strictEqual(classifyDomain('meta_learning', 0.7), 'procedural');
  });
});

describe('computeInterruptTtl', () => {
  it('returns ISO string ~3 days from now', () => {
    const before = Date.now();
    const ttl = computeInterruptTtl();
    const after = Date.now();

    const ttlTime = new Date(ttl).getTime();
    assert.ok(ttlTime >= before + INTERRUPT_TTL_SECONDS * 1000);
    assert.ok(ttlTime <= after + INTERRUPT_TTL_SECONDS * 1000);
  });

  it('returns valid ISO 8601 string', () => {
    const ttl = computeInterruptTtl();
    assert.strictEqual(new Date(ttl).toISOString(), ttl);
  });
});

describe('inferDomainFromType', () => {
  it('infers session as interrupt', () => {
    assert.strictEqual(inferDomainFromType('session'), 'interrupt');
  });

  it('infers learning/principle as value', () => {
    assert.strictEqual(inferDomainFromType('learning', 'principle'), 'value');
  });

  it('infers learning/pattern as procedural', () => {
    assert.strictEqual(inferDomainFromType('learning', 'pattern'), 'procedural');
  });

  it('infers learning/insight as procedural', () => {
    assert.strictEqual(inferDomainFromType('learning', 'insight'), 'procedural');
  });

  it('infers learning without subtype as procedural', () => {
    assert.strictEqual(inferDomainFromType('learning'), 'procedural');
  });

  it('infers entity as procedural (conservative)', () => {
    assert.strictEqual(inferDomainFromType('entity'), 'procedural');
  });
});

describe('constants', () => {
  it('INTERRUPT_TTL_SECONDS is 3 days', () => {
    assert.strictEqual(INTERRUPT_TTL_SECONDS, 259200);
  });

  it('PROCEDURAL_CAP defaults to 100', () => {
    assert.strictEqual(PROCEDURAL_CAP, 100);
  });
});

describe('getL1Budgets', () => {
  it('returns total and section budgets', () => {
    const budgets = getL1Budgets();
    assert.ok(budgets.total > 0);
    assert.ok(budgets.sections.identity > 0);
    assert.ok(budgets.sections.active > 0);
    assert.ok(budgets.sections.prefs > 0);
    assert.ok(budgets.sections.delegation > 0);
    assert.ok(budgets.sections.ephemeral > 0);
  });

  it('section budgets sum to approximately total', () => {
    const budgets = getL1Budgets();
    const sectionSum = Object.values(budgets.sections).reduce((a, b) => a + b, 0);
    assert.ok(sectionSum <= budgets.total);
    assert.ok(sectionSum > budgets.total * 0.9);
  });
});

describe('checkL1Budget', () => {
  it('returns ok for small L1 objects', () => {
    const l1 = {
      version: 1,
      updated_at: '2026-01-01T00:00:00.000Z',
      identity: { id: 'test', name: 'Test' },
      active: { focus: 'testing' },
      prefs: { emoji: false },
      delegation: { allowed: true },
      ephemeral: { session_count: 1 },
    };
    const result = checkL1Budget(l1);
    assert.strictEqual(result.ok, true);
  });

  it('rejects oversized section', () => {
    const budgets = getL1Budgets();
    const bigString = 'x'.repeat(budgets.sections.identity + 100);
    const l1 = {
      version: 1,
      updated_at: '2026-01-01T00:00:00.000Z',
      identity: { id: 'test', name: bigString },
      active: { focus: 'testing' },
      prefs: { emoji: false },
      delegation: { allowed: true },
      ephemeral: { session_count: 1 },
    };
    const result = checkL1Budget(l1);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.ok(result.violations.some((v) => v.section === 'identity'));
    }
  });

  it('rejects oversized total', () => {
    const budgets = getL1Budgets();
    const pad = Math.floor(budgets.total / 3);
    const bigStr = 'y'.repeat(pad);
    const l1 = {
      version: 1,
      updated_at: '2026-01-01T00:00:00.000Z',
      identity: { id: bigStr },
      active: { focus: bigStr },
      prefs: { emoji: false, data: bigStr },
      delegation: { allowed: true },
      ephemeral: { session_count: 1 },
    };
    const result = checkL1Budget(l1);
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.ok(result.violations.some((v) => v.section === '_total'));
    }
  });

  it('includes actual sizes in violation response', () => {
    const budgets = getL1Budgets();
    const bigString = 'z'.repeat(budgets.sections.identity + 100);
    const l1 = {
      version: 1,
      updated_at: '2026-01-01T00:00:00.000Z',
      identity: { id: 'test', name: bigString },
      active: {},
      prefs: {},
      delegation: {},
      ephemeral: {},
    };
    const result = checkL1Budget(l1);
    if (!result.ok) {
      assert.ok(result.actual);
      assert.strictEqual(typeof result.actual.identity, 'number');
      assert.ok(result.actual.identity > 0);
    }
  });
});
