import { test } from 'node:test';
import assert from 'node:assert/strict';
import { THEMES, setTheme, getThemeName, nickPalette, themeNames } from '../src/shared/themes.js';

test('defaults to neon', () => {
  setTheme('neon');
  assert.equal(getThemeName(), 'neon');
  assert.deepEqual(nickPalette(), THEMES.neon);
});

test('setTheme switches to a known theme and returns the active name', () => {
  assert.equal(setTheme('matrix'), 'matrix');
  assert.equal(getThemeName(), 'matrix');
  assert.deepEqual(nickPalette(), THEMES.matrix);
  setTheme('neon'); // restore
});

test('setTheme ignores unknown names (and prototype keys)', () => {
  setTheme('neon');
  assert.equal(setTheme('does-not-exist'), 'neon');
  assert.equal(setTheme('__proto__'), 'neon');
  assert.equal(setTheme(42), 'neon');
  assert.equal(getThemeName(), 'neon');
});

test('every theme is a non-empty palette', () => {
  for (const name of themeNames()) {
    assert.ok(Array.isArray(THEMES[name]) && THEMES[name].length > 0, name);
  }
});
