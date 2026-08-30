import { test } from 'node:test';
import assert from 'node:assert/strict';
import { glyphWidth, wrapTagged } from '../src/client/UI.js';

const plain = (tagged) => tagged.replace(/\{[^{}]*\}/g, '');
const cells = (tagged) => {
  let width = 0;
  for (const chr of plain(tagged)) {
    width += glyphWidth(chr.codePointAt(0));
  }
  return width;
};

test('glyphWidth counts terminal cells, not code units', () => {
  assert.equal(glyphWidth('a'.codePointAt(0)), 1);
  assert.equal(glyphWidth('🦊'.codePointAt(0)), 2, 'emoji');
  assert.equal(glyphWidth('世'.codePointAt(0)), 2, 'CJK');
  assert.equal(glyphWidth('✅'.codePointAt(0)), 2, 'emoji presentation by default');
  assert.equal(glyphWidth(0x200d), 0, 'zero-width joiner');
  assert.equal(glyphWidth(0xfe0f), 0, 'variation selector');

  // These are drawn as one cell. Counting them as two put every line that
  // carried one — a read receipt, a mention rule, a reply arrow — short of
  // where it was aimed.
  for (const chr of '✓✗▎✦↩·') {
    assert.equal(glyphWidth(chr.codePointAt(0)), 1, `${chr} is one cell`);
  }
});

test('wrapping breaks on words and respects the limit', () => {
  const lines = wrapTagged('the quick brown fox jumps over the lazy dog', 16);
  assert.deepEqual(lines, ['the quick brown', 'fox jumps over', 'the lazy dog']);
  for (const line of lines) {
    assert.ok(cells(line) <= 16, `"${line}" fits`);
  }
});

test('a word longer than the line is cut where it stands', () => {
  const lines = wrapTagged('supercalifragilisticexpialidocious', 10);
  assert.deepEqual(lines, ['supercalif', 'ragilistic', 'expialidoc', 'ious']);
  assert.equal(lines.join(''), 'supercalifragilisticexpialidocious', 'nothing is lost');
});

test('tags survive a break: closed at the end, reopened after it', () => {
  const lines = wrapTagged('{bold}the quick{/bold} brown {cyan-fg}fox jumps{/cyan-fg} over', 14);
  assert.deepEqual(lines, [
    '{bold}the quick{/bold}',
    'brown {cyan-fg}fox{/cyan-fg}',
    '{cyan-fg}jumps{/cyan-fg} over',
  ]);
  // The visible text is untouched and every line closes what it opened.
  assert.equal(lines.map(plain).join(' '), 'the quick brown fox jumps over');
  for (const line of lines) {
    const opens = (line.match(/\{(?!\/)[^{}]*\}/g) || []).length;
    const closes = (line.match(/\{\/[^{}]*\}/g) || []).length;
    assert.equal(opens, closes, `"${line}" is balanced`);
  }
});

test('tags do not count towards the width', () => {
  const tagged = '{#7b2dff-fg}{bold}aaa bbb ccc{/bold}{/#7b2dff-fg}';
  const lines = wrapTagged(tagged, 7);
  assert.deepEqual(lines.map(plain), ['aaa bbb', 'ccc']);
});

test('newlines in the source start new lines (fenced code, tables)', () => {
  const lines = wrapTagged('one\ntwo three four five', 9);
  assert.deepEqual(lines, ['one', 'two three', 'four five']);
});

test('wide glyphs are measured as two cells', () => {
  assert.deepEqual(wrapTagged('🦊🦊🦊🦊🦊🦊', 6), ['🦊🦊🦊', '🦊🦊🦊']);
  assert.deepEqual(wrapTagged('ab 🦊🦊 cd', 5), ['ab', '🦊🦊', 'cd']);
});

test('degenerate inputs still return one line', () => {
  assert.deepEqual(wrapTagged('', 10), ['']);
  assert.deepEqual(wrapTagged('{bold}abc{/bold}', 10), ['{bold}abc{/bold}']);
  assert.equal(wrapTagged('a b c', 0).length > 0, true, 'a zero width is clamped, not fatal');
  assert.equal(wrapTagged('a b c', -5).length > 0, true);
});

test('escaped braces occupy a cell even though they look like tags', () => {
  // blessed.escape turns a literal { into {open} and } into {close}. Those look
  // like tags but are drawn, so they have to be measured — treating them as
  // zero-width would let a line of braces run past the wrap point.
  const unescape = (l) => l.replace(/\{open\}/g, '{').replace(/\{close\}/g, '}');
  assert.deepEqual(wrapTagged('{open}aaa{close} bbb', 5).map(unescape), ['{aaa}', 'bbb']);
  const braces = '{open}'.repeat(6);
  assert.deepEqual(wrapTagged(braces, 4).map(unescape), ['{{{{', '{{']);
});
