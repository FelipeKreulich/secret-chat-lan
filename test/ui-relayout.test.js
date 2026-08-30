import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { UI } from '../src/client/UI.js';

// blessed only needs a writable that claims to be a terminal and knows how
// wide it is, so the whole layout can be driven headlessly — no pty, no CI
// difference between "renders" and "renders correctly".
function headless(columns = 100, rows = 40) {
  const output = new PassThrough();
  output.isTTY = true;
  output.columns = columns;
  output.rows = rows;
  output.resume(); // swallow the escape codes

  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => {};

  const ui = new UI('felipe', { input, output });
  return {
    ui,
    resize(to) {
      output.columns = to;
      output.emit('resize');
    },
  };
}

const plain = (line) => String(line).replace(/\{[^{}]*\}/g, '');
const widest = (line) =>
  Math.max(
    ...plain(line)
      .split('\n')
      .map((row) => row.length),
  );

const LONG =
  'esta mensagem tem de ser suficientemente comprida para partir em varias ' +
  'linhas tanto num terminal largo como num estreito, para o teste valer';

let clock;

describe('relayout on resize', () => {
  before(() => {
    // The resize handler is debounced, so a test would otherwise have to sleep
    // through it. Run the timer immediately instead.
    clock = globalThis.setTimeout;
    globalThis.setTimeout = (fn) => {
      fn();
      return { unref() {} };
    };
  });

  after(() => {
    globalThis.setTimeout = clock;
  });

  test('messages are laid out again at the new width', () => {
    const { ui, resize } = headless(100);
    const { lineIndex } = ui.addMessage('ana', LONG);
    const wide = ui.getLine(lineIndex);

    // Before: wrapped for 100 columns, and no line reaches the border.
    assert.ok(wide.includes('\n'), 'a long message wraps');
    assert.ok(widest(wide) < 100, 'nothing reaches the border');
    const wideRows = wide.split('\n').length;

    resize(60);

    const narrow = ui.getLine(lineIndex);
    assert.ok(widest(narrow) < 60, `re-wrapped for 60 columns, got ${widest(narrow)}`);
    assert.ok(narrow.split('\n').length > wideRows, 'a narrower window needs more rows');
    // The text itself is untouched — only where it breaks changed.
    const words = (line) => plain(line).split(/\s+/).filter(Boolean);
    assert.deepEqual(words(narrow), words(wide));

    resize(120);
    assert.ok(
      widest(ui.getLine(lineIndex)) > widest(narrow),
      'and back out again, rather than staying narrow beside newer messages',
    );
    ui.destroy();
  });

  test('a read receipt survives the relayout, still flush right', () => {
    const { ui, resize } = headless(100);
    const { lineIndex } = ui.addMessage('felipe', LONG);
    ui.appendBadge(lineIndex, ui.getLine(lineIndex), '{green-fg}✓✓{/green-fg}');
    assert.ok(plain(ui.getLine(lineIndex)).endsWith('✓✓'));

    resize(60);

    const after = ui.getLine(lineIndex);
    assert.ok(plain(after).endsWith('✓✓'), 'the badge is still there');
    assert.equal(plain(after).match(/✓✓/g).length, 1, 'and there is only one of it');
    assert.ok(widest(after) < 60, 'padded for the new width, not the old one');
    ui.destroy();
  });

  test('an edit is re-wrapped; a deleted message stays deleted', () => {
    const { ui, resize } = headless(100);
    const first = ui.addMessage('felipe', 'curta');
    const second = ui.addMessage('ana', 'outra');

    ui.replaceMessageText(first.lineIndex, 'felipe', LONG, first.render.opts);
    ui.removeLine(second.lineIndex);

    resize(60);

    const edited = ui.getLine(first.lineIndex);
    assert.ok(plain(edited).includes('(edited)'), 'still marked as edited');
    assert.ok(widest(edited) < 60, 're-wrapped at the new width');
    assert.equal(ui.getLine(second.lineIndex), null, 'a removed entry is not resurrected');
    ui.destroy();
  });

  test('notices are laid out again too', () => {
    const { ui, resize } = headless(100);
    ui.addErrorMessage(`WARNING: ${LONG}`);
    const lineIndex = 0;
    assert.ok(widest(ui.getLine(lineIndex)) < 100);

    resize(60);
    assert.ok(widest(ui.getLine(lineIndex)) < 60, 'an error wraps for the new width');
    ui.destroy();
  });

  test('an image preview is left exactly as it was drawn', () => {
    // Half-block pixels are laid out for the width they were rendered at.
    // Re-wrapping them would shred the picture, so they carry no recipe.
    const { ui, resize } = headless(100);
    const art = '▀'.repeat(70);
    ui.addImagePreview([art, art]);
    const before = ui.getLine(0);

    resize(60);
    assert.equal(ui.getLine(0), before);
    ui.destroy();
  });

  test('an inactive buffer is laid out again as well', () => {
    // Otherwise the drift is merely postponed to the next Alt+N.
    const { ui, resize } = headless(100);
    ui.setRoom('general');
    ui.toBuffer('dev', () => ui.addMessage('ana', LONG));

    resize(60);
    ui.switchBuffer('dev');

    // Find the message itself rather than trusting an index: the buffer also
    // holds a day separator, and asserting on that would pass by accident.
    let line = null;
    for (let i = 0; ; i++) {
      const candidate = ui.getLine(i);
      if (candidate === null && i > 10) break;
      if (candidate && plain(candidate).includes('suficientemente')) {
        line = candidate;
        break;
      }
      if (i > 20) break;
    }
    assert.ok(line, 'the message is in the buffer that came back');
    assert.ok(line.includes('\n'), 'and it is still wrapped');
    assert.ok(widest(line) < 60, 'at the new width');
    ui.destroy();
  });
});
