/**
 * Embeddings utility tests
 *
 * Tests for extractStringValues and getEmbeddableText, ensuring
 * the details field is included in searchable/embeddable text.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { extractStringValues, getEmbeddableText } from './embeddings.js';

describe('extractStringValues', () => {
  it('extracts from flat string', () => {
    assert.deepStrictEqual(extractStringValues('hello'), ['hello']);
  });

  it('extracts from array of strings', () => {
    assert.deepStrictEqual(extractStringValues(['a', 'b', 'c']), ['a', 'b', 'c']);
  });

  it('extracts from flat object', () => {
    const result = extractStringValues({ foo: 'bar', baz: 'qux' });
    assert.deepStrictEqual(result, ['bar', 'qux']);
  });

  it('extracts from nested object', () => {
    const result = extractStringValues({
      level1: 'top',
      nested: { level2: 'deep', deeper: { level3: 'deepest' } },
    });
    assert.ok(result.includes('top'));
    assert.ok(result.includes('deep'));
    assert.ok(result.includes('deepest'));
  });

  it('extracts from mixed arrays and objects', () => {
    const result = extractStringValues({
      tags: ['alpha', 'beta'],
      info: { note: 'gamma' },
    });
    assert.ok(result.includes('alpha'));
    assert.ok(result.includes('beta'));
    assert.ok(result.includes('gamma'));
  });

  it('skips non-string primitives', () => {
    const result = extractStringValues({ num: 42, bool: true, nil: null, str: 'kept' });
    assert.deepStrictEqual(result, ['kept']);
  });

  it('returns empty for undefined', () => {
    assert.deepStrictEqual(extractStringValues(undefined), []);
  });
});

describe('getEmbeddableText', () => {
  it('includes details field in output', () => {
    const text = getEmbeddableText({
      name: 'Connectionist Models',
      summary: 'Neural network concepts',
      details: {
        hardware: 'Trained ANNs on 386DX33',
        location: 'Manchester 1993',
      },
    });
    assert.ok(text.includes('386DX33'), 'should contain hardware detail');
    assert.ok(text.includes('Manchester 1993'), 'should contain location detail');
    assert.ok(text.includes('Connectionist Models'), 'should contain name');
    assert.ok(text.includes('Neural network concepts'), 'should contain summary');
  });

  it('works without details', () => {
    const text = getEmbeddableText({
      name: 'Test',
      summary: 'A test entity',
    });
    assert.ok(text.includes('Test'));
    assert.ok(text.includes('A test entity'));
  });

  it('handles empty details object', () => {
    const text = getEmbeddableText({
      name: 'Test',
      details: {},
    });
    assert.ok(text.includes('Test'));
    // Empty details should not add trailing separator
    assert.ok(!text.endsWith('. '));
  });

  it('handles nested details', () => {
    const text = getEmbeddableText({
      name: 'Entity',
      details: {
        hinton_example: 'Which president was an ex movie actor, married to Nancy?',
        key_property: 'Content-addressable retrieval tolerates noisy input',
      },
    });
    assert.ok(text.includes('movie actor'), 'should contain nested detail');
    assert.ok(text.includes('Content-addressable'), 'should contain nested detail');
  });

  it('places details before tags', () => {
    const text = getEmbeddableText({
      name: 'Entity',
      details: { info: 'detail-content' },
      tags: ['tag1', 'tag2'],
    });
    const detailIdx = text.indexOf('detail-content');
    const tagIdx = text.indexOf('tag1');
    assert.ok(detailIdx < tagIdx, 'details should appear before tags');
  });
});
