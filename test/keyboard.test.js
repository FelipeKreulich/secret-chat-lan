import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import {
  ctrlByte,
  EnhancedInput,
  filterKeys,
  parseEnhancedKey,
  toLegacy,
  KEY_PROTOCOL_ENABLE,
  KEY_PROTOCOL_DISABLE,
} from '../src/client/keyboard.js';

// Run a whole input through the filter and describe what came out: the bytes
// blessed would see, and how many newline requests were raised.
function run(chunks, state = {}) {
  let data = '';
  let newlines = 0;
  let carry = state;
  for (const chunk of [].concat(chunks)) {
    const result = filterKeys(chunk, carry);
    for (const event of result.events) {
      if (event.type === 'newline') {
        newlines++;
      } else {
        data += event.text;
      }
    }
    carry = { pending: result.pending, pasting: result.pasting };
  }
  return { data, newlines, pending: carry.pending };
}

test('the enable and disable sequences are exact inverses', () => {
  assert.equal(KEY_PROTOCOL_ENABLE, '\x1b[>4;1m\x1b[>1u');
  assert.equal(KEY_PROTOCOL_DISABLE, '\x1b[<u\x1b[>4;0m');
});

test('Shift+Enter inserts a newline instead of sending', () => {
  // kitty keyboard protocol
  assert.deepEqual(run('\x1b[13;2u'), { data: '', newlines: 1, pending: '' });
  // xterm modifyOtherKeys
  assert.deepEqual(run('\x1b[27;2;13~'), { data: '', newlines: 1, pending: '' });
  // Alt+Enter, as sent with no protocol negotiated — blessed cannot name this
  // one either, which is why it was broken as a fallback.
  assert.deepEqual(run('\x1b\r'), { data: '', newlines: 1, pending: '' });
  assert.deepEqual(run('\x1b\n'), { data: '', newlines: 1, pending: '' });
  // Ctrl+Enter and Ctrl+Shift+Enter mean the same thing.
  assert.equal(run('\x1b[13;5u').newlines, 1);
  assert.equal(run('\x1b[13;6u').newlines, 1);
});

test('plain Enter still sends', () => {
  assert.deepEqual(run('\r'), { data: '\r', newlines: 0, pending: '' });
  assert.deepEqual(run('\x1b[13;1u'), { data: '\r', newlines: 0, pending: '' });
  assert.deepEqual(run('\x1b[13u'), { data: '\r', newlines: 0, pending: '' });
});

test('typing is passed through untouched', () => {
  assert.deepEqual(run('hello'), { data: 'hello', newlines: 0, pending: '' });
  assert.deepEqual(run('olá 🦊'), { data: 'olá 🦊', newlines: 0, pending: '' });
  assert.equal(run('\x03').data, '\x03', 'Ctrl+C keeps its legacy byte');
  assert.equal(run('\x7f').data, '\x7f');
});

test('sequences blessed already understands are not rewritten', () => {
  assert.equal(run('\x1b[A').data, '\x1b[A', 'arrow up');
  assert.equal(run('\x1b[1;5D').data, '\x1b[1;5D', 'ctrl+left');
  assert.equal(run('\x1b[15~').data, '\x1b[15~', 'F5');
  assert.equal(run('\x1b[<35;10;20M').data, '\x1b[<35;10;20M', 'SGR mouse report');
  assert.equal(run('\x1bOP').data, '\x1bOP', 'F1 in application mode');
  assert.equal(run('\x1b').data, '\x1b', 'a bare Escape is never held back');
});

test('enhanced reports are rewritten to what blessed can parse', () => {
  // The whole point: none of these may reach the composer as literal text.
  assert.equal(run('\x1b[97;5u').data, '\x01', 'Ctrl+A');
  assert.equal(run('\x1b[107;5u').data, '\x0b', 'Ctrl+K opens the palette');
  assert.equal(run('\x1b[99;5u').data, '\x03', 'Ctrl+C still quits');
  assert.equal(run('\x1b[97;2u').data, 'A', 'Shift+A');
  assert.equal(run('\x1b[97u').data, 'a');
  assert.equal(run('\x1b[97;3u').data, '\x1ba', 'Alt+A');
  assert.equal(run('\x1b[27u').data, '\x1b', 'Escape reported through CSI u');
  assert.equal(run('\x1b[9;2u').data, '\x1b[Z', 'Shift+Tab');
  assert.equal(run('\x1b[127u').data, '\x7f', 'Backspace');
  assert.equal(run('\x1b[57414u').data, '\r', 'keypad Enter');
});

test('reports with no legacy encoding are dropped, never typed', () => {
  // Before this shim, blessed emitted `13;2u` as five characters.
  assert.equal(run('\x1b[57358u').data, '', 'Caps Lock');
  assert.equal(run('\x1b[49;5u').data, '', 'Ctrl+1 has no control byte');
  assert.equal(run('a\x1b[57358ub').data, 'ab', 'the surrounding typing survives');
});

test('a report split across two reads is reassembled', () => {
  assert.deepEqual(run(['\x1b[13', ';2u']), { data: '', newlines: 1, pending: '' });
  assert.deepEqual(run(['hi\x1b[', '13;2u!']), { data: 'hi!', newlines: 1, pending: '' });

  // Held bytes are visible as `pending` so the caller can release them if
  // nothing ever completes the sequence.
  const partial = filterKeys('\x1b[13;', {});
  assert.equal(partial.pending, '\x1b[13;');
  assert.deepEqual(partial.events, []);
});

test('pasted text is data, not key chords', () => {
  const paste = '\x1b[200~line one\r\x1b\rline two\x1b[201~';
  assert.deepEqual(run(paste), { data: paste, newlines: 0, pending: '' });

  // …including when the paste spans several reads.
  const split = run(['\x1b[200~aaa', '\x1b\rbbb', '\x1b[201~ccc']);
  assert.equal(split.newlines, 0);
  assert.equal(split.data, '\x1b[200~aaa\x1b\rbbb\x1b[201~ccc');

  // Once the paste ends, chords are chords again.
  assert.equal(run(['\x1b[200~x\x1b[201~', '\x1b[13;2u']).newlines, 1);
});

test('parseEnhancedKey only claims sequences it understands', () => {
  assert.deepEqual(parseEnhancedKey('13;2', 'u'), { code: 13, mods: 1 });
  assert.deepEqual(parseEnhancedKey('13;2:1', 'u'), { code: 13, mods: 1 }, 'event sub-param');
  assert.deepEqual(parseEnhancedKey('97:65;2', 'u'), { code: 97, mods: 1 }, 'shifted sub-param');
  assert.deepEqual(parseEnhancedKey('27;2;13', '~'), { code: 13, mods: 1 });
  assert.equal(parseEnhancedKey('15', '~'), null, 'F5 is not an enhanced report');
  assert.equal(parseEnhancedKey('1;5', 'D'), null, 'ctrl+left is not either');
  assert.equal(parseEnhancedKey('>1', 'u'), null, 'never claims our own request back');
});

test('ctrlByte covers the chords the UI binds', () => {
  assert.equal(ctrlByte(107), '\x0b'); // Ctrl+K — command palette
  assert.equal(ctrlByte(101), '\x05'); // Ctrl+E — emoji picker
  assert.equal(ctrlByte(102), '\x06'); // Ctrl+F — find
  assert.equal(ctrlByte(106), '\n'); // Ctrl+J — newline
  assert.equal(ctrlByte(117), '\x15'); // Ctrl+U — clear line
  assert.equal(ctrlByte(99), '\x03'); // Ctrl+C — quit
  assert.equal(ctrlByte(49), '', 'no legacy byte for Ctrl+1');
});

test('toLegacy never emits printable junk for an unknown key', () => {
  for (let code = 57344; code < 57500; code++) {
    const out = toLegacy(code, 0);
    assert.ok(
      out === '' || /^[\x00-\x1f\x7f\r\t=./*+\-0-9]*$/.test(out),
      `code ${code} produced ${JSON.stringify(out)}`,
    );
  }
});

test('EnhancedInput hands blessed a clean stream and raises newlines', async () => {
  const tty = new PassThrough();
  tty.isTTY = true;
  let raw = null;
  tty.setRawMode = (mode) => {
    raw = mode;
  };

  let newlines = 0;
  const input = new EnhancedInput(tty, () => newlines++);

  const seen = [];
  input.on('data', (chunk) => seen.push(chunk.toString('utf8')));

  // blessed drives raw mode through its input object.
  assert.equal(input.isTTY, true);
  input.setRawMode(true);
  assert.equal(raw, true, 'forwarded to the real tty');

  tty.write(Buffer.from('oi\x1b[13;2utudo bem\r', 'utf8'));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(seen.join(''), 'oitudo bem\r', 'the report never reaches blessed');
  assert.equal(newlines, 1);

  // A character split across two reads survives the round trip.
  const fox = Buffer.from('🦊', 'utf8');
  tty.write(fox.subarray(0, 2));
  tty.write(fox.subarray(2));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(seen.join('').endsWith('🦊'), true, 'no replacement characters');

  input.detach();
  assert.equal(tty.listenerCount('data'), 0);
});
