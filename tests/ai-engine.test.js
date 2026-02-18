const test = require('node:test');
const assert = require('node:assert/strict');

const { generateHintBundle } = require('../server/ai-engine');

test('generateHintBundle returns matrix and sentence positions', () => {
  const bundle = generateHintBundle('Apple', 5);

  assert.equal(bundle.word.toLowerCase(), 'apple');
  assert.equal(bundle.matrixConfig.size, 5);
  assert.equal(bundle.matrixConfig.matrix.length, 5);
  assert.ok(bundle.sentence.endsWith('.'));
  assert.equal(bundle.sentencePositions.length, 5);
});
