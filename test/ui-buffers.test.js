import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { UI } from '../src/client/UI.js';

// The same headless terminal the relayout tests use: blessed only needs a
// writable that claims to be a tty and knows how wide it is.
function headless(columns = 100, rows = 40) {
  const output = new PassThrough();
  output.isTTY = true;
  output.columns = columns;
  output.rows = rows;
  output.resume();
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => {};
  return new UI('felipe', { input, output });
}

const plain = (line) => String(line ?? '').replace(/\{[^{}]*\}/g, '');

/** Everything currently drawn in the room on screen, as plain text. */
function visible(ui) {
  const rows = [];
  for (let i = 0; ; i++) {
    const line = ui.getLine(i);
    if (line === null && i > 40) break;
    if (line === undefined) break;
    rows.push(plain(line));
    if (i > 200) break;
  }
  return rows.join('\n');
}

describe('room buffers', () => {
  test('a message for another room is stored, not drawn', () => {
    const ui = headless();
    ui.addMessage('ana', 'visible one');
    ui.toBuffer('dev', () => ui.addMessage('pedrocas', 'hidden one'));

    assert.match(visible(ui), /visible one/);
    assert.doesNotMatch(visible(ui), /hidden one/, 'the other room stayed off screen');
    assert.equal(ui.activeBuffer, 'general', 'and the active room was put back');

    ui.switchBuffer('dev');
    assert.match(visible(ui), /hidden one/, 'it was there all along');
    assert.doesNotMatch(visible(ui), /visible one/);
    ui.destroy();
  });

  test('grouping is per room', () => {
    // A run of messages folds under one header. That run belongs to its room:
    // something arriving in #dev must not break ana's run in #general, and must
    // not fold under her header either.
    const ui = headless();
    ui.addMessage('ana', 'first');
    ui.toBuffer('dev', () => ui.addMessage('ana', 'elsewhere'));
    const { lineIndex } = ui.addMessage('ana', 'second');

    const entry = ui.getLine(lineIndex);
    assert.doesNotMatch(plain(entry), /ana/, 'still folded under the first header');
    ui.destroy();
  });

  test('switching back and forth keeps both rooms', () => {
    const ui = headless();
    ui.addMessage('ana', 'in general');
    ui.switchBuffer('dev');
    ui.addMessage('pedrocas', 'in dev');
    ui.switchBuffer('general');

    assert.match(visible(ui), /in general/);
    assert.doesNotMatch(visible(ui), /in dev/);

    ui.switchBuffer('dev');
    assert.match(visible(ui), /in dev/, 'dev survived the round trip');
    ui.destroy();
  });

  test('a removed entry stays removed, and indexes are not renumbered', () => {
    // Entries are tombstoned to null rather than spliced, because a reaction or
    // a read receipt arriving later still addresses its message by index. What
    // this pins is that the tombstone survives a round trip through storage —
    // not what blessed paints, which is not reachable from here.
    const ui = headless();
    ui.switchBuffer('dev');
    const first = ui.addMessage('ana', 'keep me');
    const second = ui.addMessage('ana', 'burn me');
    ui.removeLine(second.lineIndex);
    ui.switchBuffer('general');
    ui.switchBuffer('dev');

    const drawn = visible(ui);
    assert.match(drawn, /keep me/);
    assert.doesNotMatch(drawn, /burn me/);
    assert.ok(first.lineIndex < second.lineIndex, 'indexes were not renumbered');
    ui.destroy();
  });

  test('clearBuffer empties a stored room without touching the visible one', () => {
    const ui = headless();
    ui.addMessage('ana', 'still here');
    ui.toBuffer('dev', () => ui.addMessage('pedrocas', 'to be cleared'));

    ui.clearBuffer('dev');
    assert.match(visible(ui), /still here/, 'the visible room is untouched');

    ui.switchBuffer('dev');
    assert.doesNotMatch(visible(ui), /to be cleared/);
    ui.destroy();
  });

  test('dropBuffer forgets a room, but never the one on screen', () => {
    const ui = headless();
    ui.addMessage('ana', 'on screen');
    ui.toBuffer('dev', () => ui.addMessage('pedrocas', 'dropped'));

    ui.dropBuffer('dev');
    ui.switchBuffer('dev');
    assert.doesNotMatch(visible(ui), /dropped/, 'dev was forgotten');

    ui.switchBuffer('general');
    ui.dropBuffer('general'); // the room being looked at
    assert.match(visible(ui), /on screen/, 'dropping the active room is refused');
    ui.destroy();
  });

  test('resetBuffers forgets everything and lands in the named room', () => {
    const ui = headless();
    ui.addMessage('ana', 'old world');
    ui.toBuffer('dev', () => ui.addMessage('pedrocas', 'also old'));

    ui.resetBuffers('lobby');
    assert.equal(ui.activeBuffer, 'lobby');
    assert.doesNotMatch(visible(ui), /old world/);
    ui.switchBuffer('dev');
    assert.doesNotMatch(visible(ui), /also old/, 'stored rooms went too');
    ui.destroy();
  });

  test('a stored room is laid out for the width it will be shown at', () => {
    // The formatting pipeline is deliberately the live one, so a room is not
    // laid out differently depending on whether it happened to be visible when
    // the message arrived.
    const ui = headless(100);
    const long =
      'uma mensagem comprida o suficiente para partir em varias linhas e assim ' +
      'provar que a quebra aconteceu tambem no quarto que nao estava a ser visto';
    ui.toBuffer('dev', () => ui.addMessage('ana', long));

    ui.switchBuffer('dev');
    const drawn = visible(ui);
    assert.match(drawn, /uma mensagem comprida/);
    const widest = Math.max(...drawn.split('\n').map((row) => row.length));
    assert.ok(widest < 100, `wrapped while off screen, widest row ${widest}`);
    ui.destroy();
  });
});

describe('panes', () => {
  test('one pane by default, and the panel is opt-in', () => {
    const ui = headless(120);
    assert.deepEqual(ui.panes, ['general']);
    ui.destroy();
  });

  test('several rooms side by side, the first focused', () => {
    const ui = headless(140);
    assert.deepEqual(ui.setPanel(['general', 'dev']), ['general', 'dev']);
    assert.equal(ui.activeBuffer, 'general', 'typing goes to the first');
    ui.destroy();
  });

  test('a visible room updates as messages arrive, without switching to it', () => {
    // The point of the whole feature. Before panes, a message for a room you
    // were not looking at was stored and only drawn when you switched.
    const ui = headless(140);
    ui.setPanel(['general', 'dev']);
    ui.toBuffer('dev', () => ui.addMessage('ana', 'landed in the other pane'));

    assert.equal(ui.activeBuffer, 'general', 'focus did not move');
    ui.focusPane('dev');
    assert.match(visible(ui), /landed in the other pane/);
    ui.destroy();
  });

  test('focus moves where typing goes', () => {
    const ui = headless(140);
    ui.setPanel(['general', 'dev']);
    assert.equal(ui.focusPane('dev'), true);
    assert.equal(ui.activeBuffer, 'dev');
    assert.equal(ui.focusPane('dev'), false, 'already focused');
    assert.equal(ui.focusPane('nowhere'), false, 'not on screen');
    ui.destroy();
  });

  test('switching to a room already on screen focuses it instead of swapping', () => {
    const ui = headless(140);
    ui.setPanel(['general', 'dev']);
    ui.switchBuffer('dev');
    assert.deepEqual(ui.panes, ['general', 'dev'], 'the layout is untouched');
    assert.equal(ui.activeBuffer, 'dev');
    ui.destroy();
  });

  test('switching to a room that is not on screen takes over the focused pane', () => {
    const ui = headless(140);
    ui.setPanel(['general', 'dev']);
    ui.focusPane('dev');
    ui.switchBuffer('lobby');
    assert.deepEqual(ui.panes, ['general', 'lobby'], 'dev gave up its slot');
    assert.equal(ui.activeBuffer, 'lobby');
    ui.destroy();
  });

  test('a narrow terminal refuses to split into unreadable columns', () => {
    const ui = headless(60);
    assert.deepEqual(ui.setPanel(['general', 'dev']), ['general'], 'collapsed to one');
    ui.destroy();
  });

  test('each pane wraps for its own width, not the focused one', () => {
    // Two panes are each about half the window. A message in either has to be
    // wrapped for the column it is drawn in.
    const ui = headless(160);
    ui.setPanel(['general', 'dev']);
    const long =
      'uma mensagem bastante comprida para ter de partir em varias linhas ' +
      'dentro de uma coluna que tem apenas metade da janela disponivel';
    ui.toBuffer('dev', () => ui.addMessage('ana', long));

    ui.focusPane('dev');
    const widest = Math.max(
      ...visible(ui)
        .split('\n')
        .map((r) => r.length),
    );
    assert.ok(widest < 80, `wrapped for its own column, widest ${widest}`);
    ui.destroy();
  });

  test('duplicates and empties are ignored', () => {
    const ui = headless(160);
    assert.deepEqual(ui.setPanel(['dev', 'dev', '', null, 'general']), ['dev', 'general']);
    ui.destroy();
  });

  test('at most three columns', () => {
    const ui = headless(400);
    assert.equal(ui.setPanel(['a', 'b', 'c', 'd', 'e']).length, 3);
    ui.destroy();
  });
});

describe('rebuilding the panel', () => {
  test('opening and closing repeatedly does not crash', () => {
    // blessed's Log defers a scroll-to-bottom to a setImmediate after each line.
    // Destroying the pane before that fires left the callback holding a
    // detached node, and it threw on this.parent.itop — two /panel calls in a
    // row were enough to take the client down.
    const ui = headless(150);
    ui.addMessage('ana', 'something to scroll');
    ui.setPanel(['general', 'dev']);
    ui.addMessage('ana', 'more');
    ui.setPanel(['general']);
    ui.setPanel(['general', 'dev', 'lobby']);
    ui.setPanel(['general']);
    assert.deepEqual(ui.panes, ['general']);
    ui.destroy();
  });

  test('the width thresholds are what the message claims', () => {
    // The advice says about 92 columns for two rooms; if that number drifts the
    // message starts lying, which is how this feature got reported in the first
    // place.
    const narrow = headless(80);
    assert.equal(narrow.setPanel(['a', 'b']).length, 1);
    narrow.destroy();

    const enough = headless(92);
    assert.equal(enough.setPanel(['a', 'b']).length, 2);
    enough.destroy();
  });
});
