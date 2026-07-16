import { test } from 'node:test';
import assert from 'node:assert/strict';
import { progressBar, formatETA } from '../src/client/UI.js';

const cells = (s) => s.replace(/\{[^{}]*\}/g, '');

test('0% renders an all-empty bar', () => {
  const out = cells(progressBar(0, 0, 10));
  assert.equal(out, '░'.repeat(10));
});

test('100% renders an all-filled solid bar', () => {
  const out = cells(progressBar(100, 0, 10));
  assert.equal(out, '█'.repeat(10));
  assert.match(progressBar(100, 5, 10), /\{green-fg\}/);
  assert.doesNotMatch(progressBar(100, 5, 10), /#ffffff/); // no shimmer when done
});

test('50% fills half the bar', () => {
  const out = cells(progressBar(50, 0, 10));
  assert.equal(out.split('█').length - 1, 5);
  assert.equal(out.split('░').length - 1, 5);
});

test('out-of-range percents are clamped', () => {
  assert.equal(cells(progressBar(-20, 0, 8)), '░'.repeat(8));
  assert.equal(cells(progressBar(250, 0, 8)), '█'.repeat(8));
});

test('shimmer highlights a moving band within the filled region', () => {
  // At 100% filled, a shimmer at pos 0 lights cells 0..1 white.
  const lit = progressBar(80, 0, 10);
  assert.match(lit, /#ffffff/, 'a bright shimmer cell is present mid-transfer');
});

test('formatETA needs enough signal', () => {
  assert.equal(formatETA(100, 50), ''); // too early (<600ms)
  assert.equal(formatETA(5000, 0), ''); // 0% — unknown
  assert.equal(formatETA(5000, 100), ''); // done
});

test('formatETA estimates remaining seconds', () => {
  // 1000ms elapsed at 50% → ~1000ms remaining → ~1s.
  assert.equal(formatETA(1000, 50), '~1s restantes');
  // 30s elapsed at 25% → 90s remaining → 2m (ceil).
  assert.equal(formatETA(30000, 25), '~2m restantes');
});
