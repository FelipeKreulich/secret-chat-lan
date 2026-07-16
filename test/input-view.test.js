import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inputView } from '../src/client/UI.js';

const strip = (s) => s.replace(/\{[^{}]*\}/g, '');
const linesOf = (v, c, m) => strip(inputView(v, c, m).content).split('\n');

test('empty input is one line, height 3', () => {
  const { content, height } = inputView('', 0);
  assert.equal(height, 3);
  assert.equal(strip(content).split('\n').length, 1);
});

test('single line stays height 3 and shows the text', () => {
  const { content, height } = inputView('ola', 3);
  assert.equal(height, 3);
  assert.equal(strip(content).trim(), 'ola');
});

test('newlines produce multiple lines and grow the height', () => {
  const { content, height } = inputView('a\nb\nc', 0);
  assert.equal(height, 5); // 3 text lines + 2 borders
  assert.deepEqual(strip(content).split('\n'), [' a', ' b', ' c']);
});

test('the cursor sits on the right line', () => {
  // cursor after "a\n" → start of the second line
  const { content } = inputView('a\nb', 2);
  const lines = content.split('\n');
  assert.doesNotMatch(lines[0], /\{inverse\}/, 'first line has no cursor');
  assert.match(lines[1], /\{inverse\}/, 'second line carries the cursor');
});

test('a real character under the cursor is highlighted, not duplicated', () => {
  const { content } = inputView('abc', 1); // cursor on "b"
  assert.match(content, /\{inverse\}b\{\/inverse\}/);
  assert.equal(strip(content).trim(), 'abc'); // no char lost or doubled
});

test('windowing keeps the cursor line visible and caps the height', () => {
  const value = Array.from({ length: 12 }, (_, i) => `l${i}`).join('\n');
  const cursorAtEnd = value.length;
  const { content, height } = inputView(value, cursorAtEnd, 8);
  const lines = strip(content).split('\n');
  assert.equal(height, 10); // 8 lines + 2 borders (capped)
  assert.equal(lines.length, 8);
  assert.equal(lines[lines.length - 1].trim(), 'l11'); // cursor line visible
});
