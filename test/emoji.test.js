import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { applyShortcodes, shortcodeSuggestions } from '../src/shared/emoji.js';

describe('Emoji shortcodes', () => {
  test('replaces a known shortcode', () => {
    assert.equal(applyShortcodes('go :rocket:'), 'go 🚀');
  });

  test('replaces several in the same message', () => {
    assert.equal(applyShortcodes(':fire: and :100:'), '🔥 and 💯');
  });

  test('keeps an unknown shortcode intact', () => {
    assert.equal(applyShortcodes('no :doesnotexist: here'), 'no :doesnotexist: here');
  });

  test('leaves text without shortcodes untouched', () => {
    const text = 'normal message, even with : loose colons';
    assert.equal(applyShortcodes(text), text);
  });

  test('a time like 10:30 does not become an emoji', () => {
    assert.equal(applyShortcodes('meeting at 10:30:00 ok'), 'meeting at 10:30:00 ok');
  });

  test('suggestions filter by prefix', () => {
    const s = shortcodeSuggestions(':s');
    assert.ok(s.includes(':smile:'));
    assert.ok(s.includes(':sad:'));
    assert.ok(!s.includes(':fire:'));
  });
});
