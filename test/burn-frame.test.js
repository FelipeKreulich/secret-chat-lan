import { test } from 'node:test';
import assert from 'node:assert/strict';
import { burnFrame } from '../src/client/UI.js';

// Strip blessed color tags to inspect the raw glyphs a frame renders.
const glyphs = (s) => s.replace(/\{[^{}]*\}/g, '');

test('front at 0 leaves the text intact', () => {
  assert.equal(glyphs(burnFrame('hello', 0)), 'hello');
});

test('a fully-passed front burns everything to spaces', () => {
  const out = glyphs(burnFrame('hello', 5 + 5)); // len + BURN_TAIL
  assert.equal(out, '     ');
  assert.ok(!/[a-z]/.test(out), 'no original letters remain');
});

test('mid-burn shows flame/ember glyphs and keeps the unburned tail', () => {
  const out = glyphs(burnFrame('abcdefgh', 3));
  // Leading positions have been consumed into fire/ash glyphs...
  assert.match(out, /[▓▒░·]/);
  // ...while the far end still shows original characters.
  assert.match(out, /gh$/);
});

test('the flame front sweeps left→right over time', () => {
  const early = glyphs(burnFrame('abcdefgh', 1));
  const late = glyphs(burnFrame('abcdefgh', 5));
  const intact = (s) => (s.match(/[a-z]/g) || []).length;
  assert.ok(intact(late) < intact(early), 'more of the text is consumed later');
});

test('escapes tag-breaking characters when intact', () => {
  // A literal brace must be escaped so it can't leak as a blessed tag.
  const out = burnFrame('a{b}c', 0);
  assert.ok(out.includes('{open}'), 'brace escaped via blessed.escape');
  assert.ok(!out.includes('{b}'), 'raw {b} tag does not appear');
});

test('empty string yields an empty frame', () => {
  assert.equal(burnFrame('', 3), '');
});
