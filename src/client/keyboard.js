// Keyboard-protocol shim.
//
// Terminals cannot tell Shift+Enter from Enter unless the application asks them
// to: with no protocol negotiated both arrive as a bare `\r`. The two ways to
// ask are the kitty keyboard protocol (`CSI > 1 u`, reported as `CSI 13;2 u`)
// and xterm's modifyOtherKeys (`CSI > 4 ; 1 m`, reported as `CSI 27;2;13 ~`).
//
// Asking is only half of it. blessed's key parser splits input with
//
//   (?:\x1b+)(O|N|\[|\[\[)(?:(\d+)(?:;(\d+))?([~^$])|…|(?:1;)?(\d+)?([a-zA-Z]))
//
// which matches neither a `u` final byte after two parameters nor a `~` after
// three. Both reports fall through to blessed's `/\x1b./` catch-all, so it
// consumes `\x1b[` and emits the rest — `13;2u` — as ordinary characters typed
// into the composer. The same regex is why `\x1b\r` (Alt+Enter) reaches blessed
// with `key.name === undefined`.
//
// So the reports are decoded here, upstream of blessed, on the raw byte stream:
// Enter with a modifier becomes a newline event, every other enhanced report is
// rewritten to the legacy encoding blessed already understands, and anything
// unrecognised is passed through untouched. Nothing new can reach the composer
// as literal text, which is the property that makes enabling a protocol safe.

import { PassThrough } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

const ESC = '\x1b';
const PASTE_START = '\x1b[200~';
const PASTE_END = '\x1b[201~';

// Ask for both protocols. Terminals that implement neither ignore both; ones
// that implement the kitty protocol let it take precedence over modifyOtherKeys.
// Level 1 of modifyOtherKeys is deliberate — level 2 also re-encodes Ctrl+C and
// friends, which is a much larger blast radius for a newline.
export const KEY_PROTOCOL_ENABLE = '\x1b[>4;1m\x1b[>1u';
export const KEY_PROTOCOL_DISABLE = '\x1b[<u\x1b[>4;0m';

// Modifier bits, as reported minus one.
const MOD_SHIFT = 1;
const MOD_ALT = 2;
const MOD_CTRL = 4;

// Kitty's private-use range for keys with no Unicode code point. Under the
// disambiguate flag most of these keep their legacy encoding, but the keypad
// reports through CSI u, so the ones that produce text are mapped back.
const KEYPAD = new Map([
  [57399, '0'],
  [57400, '1'],
  [57401, '2'],
  [57402, '3'],
  [57403, '4'],
  [57404, '5'],
  [57405, '6'],
  [57406, '7'],
  [57407, '8'],
  [57408, '9'],
  [57409, '.'],
  [57410, '/'],
  [57411, '*'],
  [57412, '-'],
  [57413, '+'],
  [57414, '\r'], // KP_ENTER
  [57415, '='],
]);

/**
 * The control byte a Ctrl+<key> chord produces on a legacy terminal, or '' when
 * the chord has no legacy encoding (Ctrl+1, say). Pure, exported for testing.
 */
export function ctrlByte(code) {
  if (code >= 97 && code <= 122) {
    return String.fromCharCode(code - 96); // ctrl+a … ctrl+z
  }
  if (code >= 65 && code <= 90) {
    return String.fromCharCode(code - 64); // ctrl+A … ctrl+Z
  }
  switch (code) {
    case 32: // ctrl+space → NUL
    case 64: // ctrl+@
      return '\x00';
    case 91: // ctrl+[
      return '\x1b';
    case 92: // ctrl+backslash
      return '\x1c';
    case 93: // ctrl+]
      return '\x1d';
    case 94: // ctrl+^
      return '\x1e';
    case 95: // ctrl+_
    case 47: // ctrl+/
      return '\x1f';
    case 63: // ctrl+?
      return '\x7f';
    default:
      return '';
  }
}

/**
 * Rewrite one decoded key report as the bytes a legacy terminal would have
 * sent, so blessed's parser sees input it already knows. Returns '' for reports
 * with no legacy equivalent — dropping them is the point, since letting them
 * through is what types `13;2u` into the composer. Pure, exported for testing.
 *
 * @param {number} code Unicode code point (or a kitty functional key number)
 * @param {number} mods modifier bitmask, already decremented by one
 */
export function toLegacy(code, mods) {
  const shift = !!(mods & MOD_SHIFT);
  const alt = !!(mods & MOD_ALT);
  const ctrl = !!(mods & MOD_CTRL);
  const meta = (s) => (alt ? ESC + s : s);

  switch (code) {
    case 13:
      return meta('\r'); // enter — modified enter is intercepted upstream
    case 27:
      return ESC; // escape carries no modifiers in the legacy encoding
    case 9:
      return shift ? '\x1b[Z' : meta('\t');
    case 8:
    case 127:
      return meta('\x7f'); // backspace
  }

  if (KEYPAD.has(code)) {
    return meta(KEYPAD.get(code));
  }
  // Kitty numbers its functional keys inside the Unicode private-use area, so
  // anything landing there is a key (Caps Lock, media keys, …) rather than a
  // character. Emitting it would put an invisible glyph in the composer.
  if (code >= 0xe000 && code <= 0xf8ff) {
    return '';
  }
  if (code < 32 || code > 0x10ffff) {
    return ''; // control codes we have no encoding for
  }

  if (ctrl) {
    const byte = ctrlByte(code);
    return byte ? meta(byte) : '';
  }
  // Kitty reports the *unshifted* code point plus a shift bit.
  const base = shift && code >= 97 && code <= 122 ? code - 32 : code;
  return meta(String.fromCodePoint(base));
}

// Match a CSI sequence starting at `from`. Returns the parameter string and
// final byte, `null` when the sequence is still incomplete (hold and wait for
// more input), or `false` when it can never become one.
function matchCsi(text, from) {
  let i = from + 2; // past ESC [
  while (i < text.length) {
    const c = text.charCodeAt(i);
    const isParam = (c >= 0x30 && c <= 0x3f) || (c >= 0x20 && c <= 0x2f); // 0-9;:<=>?!"#$%&'()*+,-./
    if (isParam) {
      i++;
      continue;
    }
    if (c >= 0x40 && c <= 0x7e) {
      return { params: text.slice(from + 2, i), final: text[i], end: i + 1 };
    }
    return false; // not a CSI sequence after all
  }
  return null; // ran out of input mid-sequence
}

// Parameters as numbers, taking the first sub-parameter of each (kitty uses
// `code:shifted:base` and `mods:event`, and only the first matters here).
function numericParams(params) {
  return params.split(';').map((p) => {
    const n = Number.parseInt(p.split(':')[0], 10);
    return Number.isNaN(n) ? 0 : n;
  });
}

/**
 * Decode an enhanced key report into `{ code, mods }`, or null if the sequence
 * is not one. Understands the kitty form `CSI <code>[;<mods>] u` and xterm's
 * modifyOtherKeys form `CSI 27;<mods>;<code> ~`. Pure, exported for testing.
 */
export function parseEnhancedKey(params, final) {
  const nums = numericParams(params);
  if (final === 'u' && !params.startsWith('>') && !params.startsWith('<')) {
    const code = nums[0];
    if (!code) {
      return null;
    }
    return { code, mods: Math.max(0, (nums[1] || 1) - 1) };
  }
  if (final === '~' && nums.length === 3 && nums[0] === 27) {
    return { code: nums[2], mods: Math.max(0, (nums[1] || 1) - 1) };
  }
  return null;
}

/** Enter plus any modifier means "new line in the composer", never "send". */
function isNewline(key) {
  return key.code === 13 && (key.mods & (MOD_SHIFT | MOD_ALT | MOD_CTRL)) !== 0;
}

/**
 * Scan a chunk of raw terminal input, splitting it into what blessed should see
 * and the newline requests it never could. Pure and incremental — feed the
 * returned `pending`/`pasting` back in with the next chunk.
 *
 * Bracketed-paste blocks are copied through verbatim: text arriving from the
 * clipboard is data, and a `\x1b\r` inside it is two pasted characters, not a
 * key chord.
 *
 * @returns {{ events: Array<{type: 'data'|'newline', text?: string}>,
 *             pending: string, pasting: boolean }}
 */
export function filterKeys(input, state = {}) {
  const text = (state.pending || '') + input;
  let pasting = !!state.pasting;
  const events = [];
  let out = '';
  let i = 0;

  const flush = () => {
    if (out) {
      events.push({ type: 'data', text: out });
      out = '';
    }
  };

  while (i < text.length) {
    if (pasting) {
      const end = text.indexOf(PASTE_END, i);
      if (end === -1) {
        out += text.slice(i);
        i = text.length;
        break;
      }
      out += text.slice(i, end + PASTE_END.length);
      i = end + PASTE_END.length;
      pasting = false;
      continue;
    }

    if (text[i] !== ESC) {
      let j = i;
      while (j < text.length && text[j] !== ESC) {
        j++;
      }
      out += text.slice(i, j);
      i = j;
      continue;
    }

    if (text.startsWith(PASTE_START, i)) {
      out += PASTE_START;
      i += PASTE_START.length;
      pasting = true;
      continue;
    }

    // Alt+Enter as sent by terminals with no protocol negotiated. blessed
    // cannot name this one either, so it is intercepted here for every
    // terminal, protocol or not.
    if (text.startsWith('\x1b\r', i) || text.startsWith('\x1b\n', i)) {
      flush();
      events.push({ type: 'newline' });
      i += 2;
      continue;
    }

    if (text.startsWith('\x1b[', i)) {
      const csi = matchCsi(text, i);
      if (csi === null) {
        break; // incomplete — hold it for the next chunk
      }
      if (csi === false) {
        out += text[i];
        i++;
        continue;
      }
      const key = parseEnhancedKey(csi.params, csi.final);
      if (!key) {
        out += text.slice(i, csi.end); // arrows, function keys, mouse — untouched
        i = csi.end;
        continue;
      }
      if (isNewline(key)) {
        flush();
        events.push({ type: 'newline' });
      } else {
        out += toLegacy(key.code, key.mods);
      }
      i = csi.end;
      continue;
    }

    out += text[i];
    i++;
  }

  flush();
  return { events, pending: text.slice(i), pasting };
}

/**
 * A stdin stand-in for blessed that has already had the enhanced key reports
 * taken out of it. Pass it as `blessed.screen({ input })`.
 *
 * blessed only needs `data`/`keypress` events plus `setRawMode`, `isRaw` and
 * `pause`/`resume` from its input, so the raw-mode calls are forwarded to the
 * real tty and everything else is an ordinary PassThrough.
 */
export class EnhancedInput extends PassThrough {
  #source;
  #onNewline;
  #onData;
  #decoder = new StringDecoder('utf8');
  #state = { pending: '', pasting: false };
  #flushTimer = null;

  constructor(source, onNewline) {
    super();
    this.#source = source;
    this.#onNewline = onNewline;
    this.#onData = (chunk) => this.#feed(chunk);
    this.#source.on('data', this.#onData);
  }

  get isTTY() {
    return !!this.#source.isTTY;
  }

  get isRaw() {
    return !!this.#source.isRaw;
  }

  setRawMode(mode) {
    this.#source.setRawMode?.(mode);
    return this;
  }

  /** Stop consuming the tty (used when the screen is torn down). */
  detach() {
    this.#source.removeListener('data', this.#onData);
    if (this.#flushTimer) {
      clearTimeout(this.#flushTimer);
      this.#flushTimer = null;
    }
  }

  #feed(chunk) {
    // Decode through a StringDecoder so a multi-byte character split across two
    // reads is not turned into replacement characters on the way back out.
    const text = Buffer.isBuffer(chunk) ? this.#decoder.write(chunk) : String(chunk);
    if (!text) {
      return;
    }
    const { events, pending, pasting } = filterKeys(text, this.#state);
    this.#state = { pending, pasting };
    for (const event of events) {
      if (event.type === 'newline') {
        this.#onNewline?.();
      } else {
        this.push(Buffer.from(event.text, 'utf8'));
      }
    }
    this.#armFlush();
  }

  // A held partial sequence must never swallow input for good: if nothing
  // completes it, release it as ordinary bytes.
  #armFlush() {
    if (this.#flushTimer) {
      clearTimeout(this.#flushTimer);
      this.#flushTimer = null;
    }
    if (!this.#state.pending) {
      return;
    }
    this.#flushTimer = setTimeout(() => {
      this.#flushTimer = null;
      const held = this.#state.pending;
      this.#state = { pending: '', pasting: this.#state.pasting };
      if (held) {
        this.push(Buffer.from(held, 'utf8'));
      }
    }, 50);
    this.#flushTimer.unref?.();
  }
}
