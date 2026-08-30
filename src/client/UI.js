import blessed from 'blessed';
import { EventEmitter } from 'node:events';
import { shortcodeSuggestions } from '../shared/emoji.js';
import { nickPalette } from '../shared/themes.js';
import { fuzzyFilter } from '../shared/fuzzy.js';
import { EMOJI_MAP } from '../shared/constants.js';
import { EnhancedInput, KEY_PROTOCOL_ENABLE, KEY_PROTOCOL_DISABLE } from './keyboard.js';

const EMOJI_ENTRIES = Object.entries(EMOJI_MAP); // [':name:', '😀']

const NICK_AVATARS = ['😀', '😎', '🤠', '🤖', '👻', '👽', '🦊', '🐼', '🐸', '🦁', '🐙', '🐧'];
const TYPING_DOTS = ['', '.', '..', '...'];
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const INPUT_MAX_LINES = 8; // input box grows up to this many text lines
const MAX_TEXT_WIDTH = 78; // widest a message body is allowed to run
const BODY_WIDTH_RATIO = 0.65; // ...and never more than this share of the window

// Command → one-line description for the Ctrl+K fuzzy command palette.
const COMMAND_INFO = [
  ['/help', 'Show help'],
  ['/tips', 'Show a security/UX tip'],
  ['/users', 'List online users'],
  ['/msg', 'Private message (DM)'],
  ['/reply', 'Reply to the last message'],
  ['/me', 'Third-person action message'],
  ['/topic', 'Show or set the room topic'],
  ['/mentions', 'Recent mentions of you'],
  ['/watch', 'Alert on a keyword in any room'],
  ['/contacts', 'Contact book — aliases for peers'],
  ['/away', 'Mark yourself as away'],
  ['/back', 'Clear away status'],
  ['/status', 'Set a status'],
  ['/join', 'Join a room as a new buffer (Alt+1..9 switches)'],
  ['/leave', 'Leave a room — its buffer closes'],
  ['/create', 'Create a private room with a password'],
  ['/rooms', 'List rooms'],
  ['/room', 'Show the current room'],
  ['/invite', 'Generate an invite with QR'],
  ['/fingerprint', 'Show fingerprint'],
  ['/verify', 'SAS verification code'],
  ['/trust', "Accept a peer's new key"],
  ['/trustlist', 'Trust status'],
  ['/clear', 'Clear the chat'],
  ['/file', 'Send a file'],
  ['/voice', 'Record and send a voice note'],
  ['/play', 'Play the last voice note'],
  ['/img', 'Render a high-resolution image'],
  ['/sound', 'Sound notifications'],
  ['/notify', 'Desktop notifications'],
  ['/search', 'Search history (on disk)'],
  ['/find', 'Find in this room and jump to it'],
  ['/doctor', 'Diagnose why a connection fails'],
  ['/history', 'Recent messages from history'],
  ['/export', 'Export history'],
  ['/backup', 'Back up identity + trust'],
  ['/retention', 'Local history retention'],
  ['/audit', 'Audit events'],
  ['/ephemeral', 'Ephemeral messages'],
  ['/react', 'React to a message'],
  ['/edit', 'Edit the last sent message'],
  ['/delete', 'Delete the last sent message'],
  ['/pin', 'Pin a message'],
  ['/unpin', 'Unpin a message'],
  ['/pins', 'List pinned messages'],
  ['/deniable', 'Deniable mode'],
  ['/receipts', 'Read receipts'],
  ['/cover', 'Cover traffic (anti-metadata)'],
  ['/theme', 'Nick color theme'],
  ['/lock', 'Lock the screen (session passphrase to unlock)'],
  ['/autolock', 'Auto-lock on inactivity'],
  ['/panic', 'Wipe everything from disk and exit (duress)'],
  ['/kick', 'Kick a user (owner)'],
  ['/mute', 'Mute a user (owner)'],
  ['/ban', 'Ban a user (owner)'],
  ['/owner', 'Current room owner'],
  ['/plugins', 'List plugins'],
  ['/quit', 'Quit the chat'],
];

export const COMMANDS = [
  '/help',
  '/tips',
  '/nick',
  '/users',
  '/fingerprint',
  '/verify',
  '/verify-confirm',
  '/trust',
  '/trustlist',
  '/clear',
  '/file',
  '/voice',
  '/play',
  '/accept',
  '/reject',
  '/img',
  '/sound',
  '/msg',
  '/reply',
  '/me',
  '/mentions',
  '/watch',
  '/contacts',
  '/away',
  '/back',
  '/autoaway',
  '/status',
  '/notify',
  '/dnd',
  '/join',
  '/leave',
  '/topic',
  '/create',
  '/rooms',
  '/room',
  '/invite',
  '/search',
  '/find',
  '/doctor',
  '/history',
  '/export',
  '/backup',
  '/retention',
  '/audit',
  '/ephemeral',
  '/react',
  '/edit',
  '/delete',
  '/pin',
  '/unpin',
  '/pins',
  '/deniable',
  '/receipts',
  '/cover',
  '/theme',
  '/lock',
  '/autolock',
  '/panic',
  '/kick',
  '/mute',
  '/ban',
  '/owner',
  '/plugins',
  '/quit',
];
const NICK_COMMANDS = [
  '/fingerprint',
  '/verify',
  '/verify-confirm',
  '/trust',
  '/msg',
  '/kick',
  '/mute',
  '/ban',
];

function nickHash(nickname) {
  let hash = 0;
  for (let i = 0; i < nickname.length; i++) {
    hash = ((hash << 5) - hash + nickname.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

function nickColor(nickname) {
  const palette = nickPalette();
  return palette[nickHash(nickname) % palette.length];
}

// Deterministic avatar per nick — emojis can't be color-tinted in the
// terminal, so the visual identity comes from the variety of the emoji itself
function nickAvatar(nickname) {
  return NICK_AVATARS[nickHash(nickname) % NICK_AVATARS.length];
}

function time() {
  return new Date().toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  });
}

// Inline markdown for a single line: `code`, **bold**, *italic*, links.
function renderInline(text) {
  // Collect all markdown spans with their positions
  const spans = [];

  // Inline code: `code`
  for (const m of text.matchAll(/`([^`]+)`/g)) {
    spans.push({ start: m.index, end: m.index + m[0].length, inner: m[1], tag: 'yellow-fg' });
  }

  // Bold: **text**
  for (const m of text.matchAll(/\*\*([^*]+)\*\*/g)) {
    // Skip if overlaps with an existing span (inside code)
    if (spans.some((s) => m.index >= s.start && m.index < s.end)) {
      continue;
    }
    spans.push({ start: m.index, end: m.index + m[0].length, inner: m[1], tag: 'bold' });
  }

  // Italic: *text* (not preceded/followed by *)
  for (const m of text.matchAll(/(?<!\*)\*([^*]+)\*(?!\*)/g)) {
    if (spans.some((s) => m.index >= s.start && m.index < s.end)) {
      continue;
    }
    spans.push({ start: m.index, end: m.index + m[0].length, inner: m[1], tag: 'underline' });
  }

  // Links: http(s):// … — highlighted cyan + underline.
  for (const m of text.matchAll(/https?:\/\/[^\s]+/g)) {
    if (spans.some((s) => m.index >= s.start && m.index < s.end)) {
      continue;
    }
    spans.push({
      start: m.index,
      end: m.index + m[0].length,
      inner: m[0],
      open: '{cyan-fg}{underline}',
      close: '{/underline}{/cyan-fg}',
    });
  }

  if (spans.length === 0) {
    return blessed.escape(text);
  }

  // Sort by position
  spans.sort((a, b) => a.start - b.start);

  // Build result: escape plain segments, apply tags to markdown segments
  let result = '';
  let pos = 0;
  for (const span of spans) {
    if (span.start > pos) {
      result += blessed.escape(text.slice(pos, span.start));
    }
    const open = span.open ?? `{${span.tag}}`;
    const close = span.close ?? `{/${span.tag}}`;
    result += `${open}${blessed.escape(span.inner)}${close}`;
    pos = span.end;
  }
  if (pos < text.length) {
    result += blessed.escape(text.slice(pos));
  }

  return result;
}

// A markdown table separator row, e.g. |---|:--:|.
function isTableSeparator(line) {
  return /^\s*\|?[\s:|-]+\|[\s:|-]*$/.test(line) && line.includes('-');
}

function splitRow(line) {
  return line
    .trim()
    .replace(/^\||\|$/g, '')
    .split('|')
    .map((c) => c.trim());
}

// Render a buffered block of pipe-lines. If it's a real table (has a separator
// row) align the columns; otherwise fall back to inline rendering per line.
function renderTable(lines) {
  const sepIdx = lines.findIndex(isTableSeparator);
  if (sepIdx < 1) {
    return lines.map(renderInline); // not a table — just piped text
  }
  const header = splitRow(lines[sepIdx - 1]);
  const bodyRows = lines.filter((l, i) => i !== sepIdx && i !== sepIdx - 1).map(splitRow);
  const cols = header.length;
  const widths = header.map((h, c) =>
    Math.max(h.length, ...bodyRows.map((r) => (r[c] || '').length)),
  );
  const pad = (cells) =>
    ' ' +
    cells
      .slice(0, cols)
      .map((cell, c) => (cell || '').padEnd(widths[c]))
      .join('  ');
  const out = [`{bold}{cyan-fg}${blessed.escape(pad(header))}{/cyan-fg}{/bold}`];
  out.push(`{#666666-fg}${blessed.escape(pad(widths.map((w) => '─'.repeat(w))))}{/#666666-fg}`);
  for (const row of bodyRows) {
    out.push(blessed.escape(pad(row)));
  }
  return out;
}

// Block-aware markdown: fenced ``` code blocks and | tables | on top of the
// inline formatting. Multi-line messages are processed line by line.
export function renderMarkdown(text) {
  if (!text.includes('\n')) {
    return renderInline(text); // single line — the common, fast path
  }
  const lines = text.split('\n');
  const out = [];
  let inCode = false;
  let tableBuf = [];
  const flushTable = () => {
    if (tableBuf.length) {
      out.push(...renderTable(tableBuf));
      tableBuf = [];
    }
  };

  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      flushTable();
      inCode = !inCode;
      out.push(`{#666666-fg}${blessed.escape(line)}{/#666666-fg}`);
      continue;
    }
    if (inCode) {
      out.push(`{#7fdbca-fg}${blessed.escape(line)}{/#7fdbca-fg}`); // code — no inline md
      continue;
    }
    if (line.includes('|')) {
      tableBuf.push(line);
      continue;
    }
    flushTable();
    out.push(renderInline(line));
  }
  flushTable();
  return out.join('\n');
}

/**
 * Find `query` in rendered chat lines, returning where each hit is plus a
 * readable preview. Blessed tags are stripped before matching so a search for
 * "fg" never matches colour markup, and the preview is centred on the hit
 * instead of always showing the start of a long line. Pure — exported for
 * testing.
 *
 * @returns {Array<{ lineIndex: number, preview: string }>} newest last
 */
export function findInLines(lines, query, maxHits = 200) {
  const needle = String(query || '')
    .trim()
    .toLowerCase();
  if (!needle || !Array.isArray(lines)) {
    return [];
  }
  const hits = [];
  for (let i = 0; i < lines.length && hits.length < maxHits; i++) {
    const plain = String(lines[i]).replace(/\{[^{}]*\}/g, '');
    const at = plain.toLowerCase().indexOf(needle);
    if (at === -1) {
      continue;
    }
    const start = Math.max(0, at - 24);
    // An entry is a whole message block now, so the slice can straddle a line
    // break — flatten it, or the picker's rows would run into each other.
    const slice = plain
      .slice(start, start + 76)
      .replace(/\s+/g, ' ')
      .trim();
    hits.push({
      lineIndex: i,
      preview: `${start > 0 ? '…' : ''}${blessed.escape(slice)}`,
    });
  }
  return hits;
}

// Code points that occupy two terminal cells: the East Asian Wide/Fullwidth
// blocks plus the handful of BMP symbols with emoji presentation by default.
// Listing them beats "everything in 0x2600–0x27bf is wide", which counted ✓, ✗,
// ▎, ✦ and ↩ as two cells each and left every line carrying one a few columns
// short of where it was aimed.
const WIDE_RANGES = [
  [0x1100, 0x115f],
  [0x231a, 0x231b],
  [0x2329, 0x232a],
  [0x23e9, 0x23ec],
  [0x23f0, 0x23f0],
  [0x23f3, 0x23f3],
  [0x25fd, 0x25fe],
  [0x2614, 0x2615],
  [0x2648, 0x2653],
  [0x267f, 0x267f],
  [0x2693, 0x2693],
  [0x26a1, 0x26a1],
  [0x26aa, 0x26ab],
  [0x26bd, 0x26be],
  [0x26c4, 0x26c5],
  [0x26ce, 0x26ce],
  [0x26d4, 0x26d4],
  [0x26ea, 0x26ea],
  [0x26f2, 0x26f3],
  [0x26f5, 0x26f5],
  [0x26fa, 0x26fa],
  [0x26fd, 0x26fd],
  [0x2705, 0x2705],
  [0x270a, 0x270b],
  [0x2728, 0x2728],
  [0x274c, 0x274c],
  [0x274e, 0x274e],
  [0x2753, 0x2755],
  [0x2757, 0x2757],
  [0x2795, 0x2797],
  [0x27b0, 0x27b0],
  [0x27bf, 0x27bf],
  [0x2e80, 0x303e],
  [0x3041, 0x4dbf],
  [0x4e00, 0xa4cf],
  [0xac00, 0xd7a3],
  [0xf900, 0xfaff],
  [0xfe10, 0xfe19],
  [0xfe30, 0xfe6f],
  [0xff00, 0xff60],
  [0xffe0, 0xffe6],
];

/**
 * Visible width of one code point, in terminal cells. Shared by the wrapper and
 * the alignment helpers so a line is measured the same way wherever it is
 * measured. Pure and exported for testing.
 */
export function glyphWidth(codePoint) {
  // Combining marks, variation selectors and the zero-width joiner ride along
  // with the glyph before them.
  if (
    (codePoint >= 0x0300 && codePoint <= 0x036f) ||
    (codePoint >= 0xfe00 && codePoint <= 0xfe0f) ||
    codePoint === 0x200d
  ) {
    return 0;
  }
  if (codePoint > 0xffff) {
    return 2; // emoji and the astral CJK planes
  }
  for (const [lo, hi] of WIDE_RANGES) {
    if (codePoint >= lo && codePoint <= hi) {
      return 2;
    }
  }
  return 1;
}

// Split a blessed-tagged string into zero-width tag tokens and one-glyph text
// tokens. `{open}`/`{close}` are blessed's escapes for literal braces, so they
// look like tags but occupy a cell.
function tokenizeTagged(text) {
  const tokens = [];
  const pushText = (chunk) => {
    for (const chr of chunk) {
      tokens.push({ text: chr, width: glyphWidth(chr.codePointAt(0)) });
    }
  };
  let pos = 0;
  for (const match of String(text).matchAll(/\{[^{}]*\}/g)) {
    pushText(String(text).slice(pos, match.index));
    const inner = match[0].slice(1, -1);
    if (inner === 'open' || inner === 'close') {
      tokens.push({ text: match[0], width: 1 });
    } else {
      tokens.push({ text: match[0], width: 0, tag: inner });
    }
    pos = match.index + match[0].length;
  }
  pushText(String(text).slice(pos));
  return tokens;
}

// The stack of open tags after each token, so a line can be cut anywhere and
// still be closed and reopened correctly.
function tagStacks(tokens) {
  const stacks = [];
  let open = [];
  for (const token of tokens) {
    if (token.tag) {
      if (token.tag.startsWith('/')) {
        const name = token.tag.slice(1);
        const at = open.lastIndexOf(name);
        open = at === -1 ? open.slice(0, -1) : open.filter((_, i) => i !== at);
      } else {
        open = [...open, token.tag];
      }
    }
    stacks.push(open);
  }
  return stacks;
}

function sliceTagged(tokens, stacks, from, to) {
  const opens = (from === 0 ? [] : stacks[from - 1]).map((t) => `{${t}}`).join('');
  const closes = (to === 0 ? [] : stacks[to - 1])
    .map((t) => `{/${t}}`)
    .reverse()
    .join('');
  let body = '';
  for (let i = from; i < to; i++) {
    body += tokens[i].text;
  }
  return opens + body + closes;
}

/**
 * Word-wrap a string that already carries blessed tags.
 *
 * Wrapping after the markdown pass rather than before it is deliberate: a
 * `**bold**` span that straddles the wrap point would otherwise be split into
 * two halves that no longer match, and the asterisks would show. The price is
 * that tags have to be handled properly — they are zero-width, must never be
 * cut in half, and blessed carries its attribute stack across the whole
 * content, so a tag left open at a break would bleed into the next line's
 * gutter. Every open tag is therefore closed at the break and reopened after it.
 *
 * Pure and exported for testing.
 *
 * @returns {string[]} one tagged string per visual line, never empty
 */
export function wrapTagged(tagged, width) {
  const limit = Math.max(4, Math.floor(width) || 4);
  const lines = [];
  for (const paragraph of String(tagged).split('\n')) {
    const tokens = tokenizeTagged(paragraph);
    const stacks = tagStacks(tokens);
    let start = 0;
    let used = 0;
    let lastSpace = -1;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token.width === 0) {
        continue;
      }
      if (token.text === ' ') {
        lastSpace = i;
      }
      if (used + token.width <= limit || used === 0) {
        used += token.width;
        continue;
      }
      // Break before this glyph, at the last space if the line has one — a word
      // longer than the whole line is cut where it stands instead.
      const cut = lastSpace > start ? lastSpace : i;
      lines.push(sliceTagged(tokens, stacks, start, cut));
      start = lastSpace > start ? lastSpace + 1 : i;
      used = 0;
      for (let j = start; j <= i; j++) {
        used += tokens[j].width;
      }
      lastSpace = -1;
    }
    lines.push(sliceTagged(tokens, stacks, start, tokens.length));
  }
  return lines;
}

// Sanitizes pasted text while PRESERVING its line structure — the input box is
// multi-line and fenced code blocks render in markdown, so pasted code must
// keep its newlines. Normalizes CRLF/CR, turns tabs into spaces and strips the
// remaining control chars (incl. stray paste markers). Pure and exported for
// testing.
export function cleanPaste(raw) {
  return (
    raw
      // eslint-disable-next-line no-control-regex
      .replace(/\x1b\[20[01]~/g, '')
      .replace(/\r\n?/g, '\n')
      .replace(/\t/g, '  ')
      // eslint-disable-next-line no-control-regex
      .replace(/[\x00-\x09\x0b-\x1f\x7f]/g, '')
  );
}

// Builds the rendered content of the (possibly multi-line) input box with an
// inverse cursor cell, windowed so the cursor line is always visible. Pure and
// exported for testing. Returns { content, height } (height includes borders).
export function inputView(value, cursorPos, maxLines = 8) {
  const segments = value.split('\n');
  const built = [];
  let lineStart = 0;
  let cursorLine = 0;

  for (let li = 0; li < segments.length; li++) {
    const seg = segments[li];
    const segEnd = lineStart + seg.length; // flat offset just before the '\n'
    if (cursorPos >= lineStart && cursorPos <= segEnd) {
      cursorLine = li;
      const col = cursorPos - lineStart;
      // grapheme under the cursor (extend across a surrogate pair)
      let cur = seg.slice(col, col + 1);
      const code = seg.charCodeAt(col);
      if (code >= 0xd800 && code <= 0xdbff && col + 1 < seg.length) {
        cur = seg.slice(col, col + 2);
      }
      const cursorCell = cur === '' ? ' ' : cur;
      const before = blessed.escape(seg.slice(0, col));
      const after = blessed.escape(seg.slice(col + (cur === '' ? 0 : cur.length)));
      built.push(` ${before}{inverse}${blessed.escape(cursorCell)}{/inverse}${after}`);
    } else {
      built.push(` ${blessed.escape(seg)}`);
    }
    lineStart = segEnd + 1; // skip the '\n'
  }

  let lines = built;
  if (built.length > maxLines) {
    let start = Math.max(0, cursorLine - maxLines + 1);
    if (start + maxLines > built.length) {
      start = built.length - maxLines;
    }
    lines = built.slice(start, start + maxLines);
  }

  const height = Math.min(Math.max(segments.length, 1), maxLines) + 2; // + borders
  return { content: lines.join('\n'), height };
}

// Extra frames appended after the flame reaches the last glyph so the tail
// (hot → ember → ash → gone) finishes burning out.
const BURN_TAIL = 5;

// One glyph of the burn animation. `phase` is how many frames the flame front
// has passed this position: <0 still intact, then it heats up and cools to ash.
function burnGlyph(ch, phase) {
  if (phase <= 0) {
    return blessed.escape(ch);
  }
  if (phase < 1) {
    return '{#ffd000-fg}▓{/#ffd000-fg}'; // ignite
  }
  if (phase < 2) {
    return '{#ff8c00-fg}▓{/#ff8c00-fg}'; // burning
  }
  if (phase < 3) {
    return '{#ff2b00-fg}▒{/#ff2b00-fg}'; // hottest
  }
  if (phase < 4) {
    return '{#7a2b00-fg}░{/#7a2b00-fg}'; // ember
  }
  if (phase < BURN_TAIL) {
    return '{#555555-fg}·{/#555555-fg}'; // ash
  }
  return ' '; // gone
}

// Builds one frame of the burn effect for a tag-free string, given how far the
// flame front has advanced. Exported for testing.
export function burnFrame(text, front) {
  const chars = [...text];
  let out = '';
  for (let i = 0; i < chars.length; i++) {
    out += burnGlyph(chars[i], front - i);
  }
  return out;
}

// A blessed-tagged progress bar. `shimmerPos` moves a 2-cell bright band along
// the filled region; at 100% the whole bar goes solid green. Exported for
// testing.
export function progressBar(pct, shimmerPos = 0, width = 24) {
  const p = Math.max(0, Math.min(100, pct));
  const done = p >= 100;
  const filled = Math.round((p / 100) * width);
  let bar = '';
  for (let i = 0; i < width; i++) {
    if (i < filled) {
      const lit = !done && ((shimmerPos % width) - i + width) % width < 2;
      const color = done ? 'green' : lit ? '#ffffff' : '#00b8ff';
      bar += `{${color}-fg}█{/${color}-fg}`;
    } else {
      bar += '{#333333-fg}░{/#333333-fg}';
    }
  }
  return bar;
}

// Estimates remaining time from elapsed ms and percent done. Returns '' when
// there isn't enough signal yet (too early, at the ends). Exported for testing.
export function formatETA(elapsedMs, pct) {
  if (pct <= 0 || pct >= 100 || elapsedMs < 600) {
    return '';
  }
  const remaining = Math.max(0, (elapsedMs / pct) * 100 - elapsedMs);
  const secs = Math.ceil(remaining / 1000);
  return secs >= 60 ? `~${Math.ceil(secs / 60)}m remaining` : `~${secs}s remaining`;
}

export class UI extends EventEmitter {
  #screen;
  #header;
  #chatLog;
  #inputBox;
  #nickname;
  #onlineCount;
  #inputValue;
  #cursorPos;
  #lastKeyEvent;
  #typingPeers;
  #typingAnimInterval;
  #typingAnimFrame;
  #soundEnabled;
  #notifyEnabled;
  #keyInput;
  #peerNames;
  #tabState;
  #lines;
  #specs; // per-entry recipe, index-aligned with #lines (null = as-drawn)
  #headerIndicators;
  #scrolledUp;
  #connState;
  #lastMsgDate;
  #lastSender;
  #lastStamp;
  #suppressSeparator;
  #resizeTimer;
  #pasting;
  #pasteBuffer;
  #lastPaste;
  #statusBar;
  #statusFingerprint;
  #statusRoom;
  #connSpinner;
  #spinnerFrame;
  #reconnectFlashTimer;
  #reconnectFlashFrame;
  #reconnectFlashActive;
  #progIndex;
  #progPercent;
  #progText;
  #progStart;
  #shimmerTimer;
  #shimmerPos;
  #unseenCount;
  #unseenMentions;
  #pillTimer;
  #pillFrame;
  #palette;
  #paletteOpen;
  #paletteQuery;
  #emojiPicker;
  #emojiOpen;
  #emojiQuery;
  #locked;
  #lockBox;
  #lockInput;
  #lockError;
  #lockVerify;
  #bufferLines; // Map<room, lines[]> — stored content of INACTIVE buffers
  #bufferSpecs; // Map<room, specs[]> — their recipes, same indexes
  #activeBuffer; // name of the buffer currently on screen
  #redirecting; // true while add* calls are being written to an inactive buffer
  #bufferBar; // [{ room, active, unread, private }] for the status bar
  #topic; // current room topic, shown in the status bar
  #finder; // Ctrl+F scrollback search overlay
  #finderOpen;
  #finderQuery;
  #finderHits; // [{ lineIndex, preview }]
  #finderMark; // line index currently highlighted by a jump

  /**
   * @param {string} nickname
   * @param {{ input?: NodeJS.ReadableStream, output?: NodeJS.WritableStream }} [io]
   *   Streams for blessed to drive instead of the real terminal. The only
   *   reason this exists is tests: with a writable that reports `isTTY` and a
   *   `columns`, the whole layout — wrapping, alignment, relayout on resize —
   *   can be exercised headlessly instead of only by eye.
   */
  constructor(nickname, io = {}) {
    super();
    this.#nickname = nickname;
    this.#onlineCount = 1;
    this.#connState = 'online';
    this.#lastMsgDate = null;
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#suppressSeparator = false;
    this.#resizeTimer = null;
    this.#pasting = false;
    this.#pasteBuffer = '';
    this.#lastPaste = { content: '', time: 0 };
    this.#inputValue = '';
    this.#cursorPos = 0;
    this.#lastKeyEvent = { seq: '', time: 0 };
    this.#typingPeers = new Set();
    this.#soundEnabled = true;
    this.#notifyEnabled = true;
    this.#typingAnimInterval = null;
    this.#typingAnimFrame = 0;
    this.#peerNames = [];
    this.#tabState = { suggestions: [], index: -1, original: '' };
    this.#lines = [];
    this.#specs = [];
    this.#headerIndicators = [];
    this.#scrolledUp = false;
    this.#statusFingerprint = '';
    this.#statusRoom = 'general';
    this.#connSpinner = null;
    this.#spinnerFrame = 0;
    this.#reconnectFlashTimer = null;
    this.#reconnectFlashFrame = 0;
    this.#reconnectFlashActive = false;
    this.#progIndex = null;
    this.#progPercent = 0;
    this.#progText = '';
    this.#progStart = 0;
    this.#shimmerTimer = null;
    this.#shimmerPos = 0;
    this.#unseenCount = 0;
    this.#unseenMentions = 0;
    this.#pillTimer = null;
    this.#pillFrame = 0;
    this.#paletteOpen = false;
    this.#paletteQuery = '';
    this.#emojiOpen = false;
    this.#emojiQuery = '';
    this.#locked = false;
    this.#lockInput = '';
    this.#lockError = false;
    this.#lockVerify = null;
    this.#bufferLines = new Map();
    this.#bufferSpecs = new Map();
    this.#activeBuffer = 'general';
    this.#redirecting = false;
    this.#bufferBar = [];
    this.#topic = null;
    this.#finderOpen = false;
    this.#finderQuery = '';
    this.#finderHits = [];
    this.#finderMark = null;

    // blessed's terminfo parser can't compile the modern Setulc (underline
    // colour) capability that terminals like ghostty ship, so it dumps a
    // compile error when it resets the terminal on exit (e.g. Ctrl+C). Those
    // terminals are xterm-256color-compatible for everything we render — images
    // use their own escape sequences, not blessed — so pin tput to xterm-256color
    // and sidestep the broken capability.
    const term = process.env.TERM || '';

    // Shift+Enter only exists if the terminal is asked for it, and the reports
    // that come back are unparseable by blessed (see ./keyboard.js). The shim
    // takes them off the raw stream before blessed ever sees them; set
    // CIPHERMESH_LEGACY_KEYS=1 to hand blessed the tty untouched.
    this.#keyInput =
      io.input || process.env.CIPHERMESH_LEGACY_KEYS === '1' || !process.stdin.isTTY
        ? null
        : new EnhancedInput(process.stdin, () => this.#onEnhancedNewline());

    this.#screen = blessed.screen({
      smartCSR: true,
      fullUnicode: true, // renders emojis and characters outside the BMP
      title: 'CipherMesh',
      terminal: /ghostty/i.test(term) ? 'xterm-256color' : undefined,
      input: this.#keyInput || io.input || undefined,
      output: io.output || undefined,
    });

    // ── Header ──────────────────────────────────────────
    this.#header = blessed.box({
      parent: this.#screen,
      top: 0,
      left: 0,
      width: '100%',
      height: 3,
      tags: true,
      style: {
        fg: 'white',
        bg: '#1a1a2e',
      },
      content: this.#headerContent(),
    });

    // ── Chat log ────────────────────────────────────────
    this.#chatLog = blessed.log({
      parent: this.#screen,
      top: 3,
      left: 0,
      width: '100%',
      bottom: 4, // leave room for the 1-line status bar above the input
      tags: true,
      scrollable: true,
      alwaysScroll: true,
      scrollbar: {
        style: { bg: 'magenta' },
      },
      border: {
        type: 'line',
      },
      style: {
        border: { fg: 'cyan' },
      },
    });

    // ── Input (plain box, manual keypress) ───────────────
    this.#inputBox = blessed.box({
      parent: this.#screen,
      bottom: 0,
      left: 0,
      width: '100%',
      height: 3,
      tags: true,
      border: {
        type: 'line',
      },
      style: {
        fg: 'white',
        border: { fg: 'green' },
      },
    });

    // ── Status bar (1 line, between chat and input) ──────
    this.#statusBar = blessed.box({
      parent: this.#screen,
      bottom: 3,
      left: 0,
      width: '100%',
      height: 1,
      tags: true,
      style: {
        fg: 'white',
        bg: '#16213e',
      },
      content: this.#statusContent(),
    });

    // ── Command palette (Ctrl+K) ─────────────────────────
    this.#palette = blessed.list({
      parent: this.#screen,
      hidden: true,
      top: 'center',
      left: 'center',
      width: '70%',
      height: '60%',
      tags: true,
      border: { type: 'line' },
      label: ' Commands (Ctrl+K) ',
      style: {
        border: { fg: 'magenta' },
        selected: { bg: 'magenta', fg: 'white' },
        item: { fg: 'white' },
      },
    });

    // ── Scrollback finder (Ctrl+F) ───────────────────────
    this.#finder = blessed.list({
      parent: this.#screen,
      hidden: true,
      top: 'center',
      left: 'center',
      width: '80%',
      height: '55%',
      tags: true,
      border: { type: 'line' },
      label: ' Find in this room (Ctrl+F) ',
      style: {
        border: { fg: 'cyan' },
        selected: { bg: 'cyan', fg: 'black' },
        item: { fg: 'white' },
      },
    });

    // ── Emoji picker (Ctrl+E) ────────────────────────────
    this.#emojiPicker = blessed.list({
      parent: this.#screen,
      hidden: true,
      top: 'center',
      left: 'center',
      width: '50%',
      height: '55%',
      tags: true,
      border: { type: 'line' },
      label: ' Emoji (Ctrl+E) ',
      style: {
        border: { fg: 'yellow' },
        selected: { bg: 'yellow', fg: 'black' },
        item: { fg: 'white' },
      },
    });

    this.#renderInput();

    // ── Single keypress listener with dedup ──────────────
    // blessed on Windows fires every keypress twice through
    // both program and screen pipelines. We listen ONLY on
    // screen level and deduplicate by sequence + timestamp.
    this.#screen.on('keypress', (ch, key) => {
      if (!key) {
        return;
      }

      const now = performance.now();
      const seq = key.sequence || key.full || ch || '';

      // Mouse tracking sequences (ex: \x1b[<35;10;20M) that leak past
      // blessed's parser are not typing — discard
      if (seq.startsWith('\x1b[<') || seq.startsWith('\x1b[M')) {
        return;
      }

      // Normally the shim has already turned these into a newline upstream. This
      // is the CIPHERMESH_LEGACY_KEYS path, where a terminal configured by hand
      // to emit \x1b[13;2u (VS Code's sendSequence, say) still works — blessed
      // only delivers them intact when it happens to keep the sequence whole.
      if (seq === '\x1b[13;2u' || seq === '\x1b[27;2;13~') {
        this.#insertNewline();
        return;
      }

      // Bracketed paste: insert the whole pasted block atomically (avoids the
      // double-pipeline duplicating a paste that spans the 25ms dedup window).
      if (this.#handlePaste(seq)) {
        return;
      }

      // Same raw sequence within 25ms = duplicate from blessed
      if (seq === this.#lastKeyEvent.seq && now - this.#lastKeyEvent.time < 25) {
        return;
      }
      this.#lastKeyEvent = { seq, time: now };

      // Locked screen swallows everything except the passphrase entry.
      if (this.#locked) {
        this.#handleLockKey(ch, key);
        return;
      }

      if (this.#paletteOpen) {
        this.#handlePaletteKey(ch, key);
        return;
      }

      if (this.#emojiOpen) {
        this.#handleEmojiKey(ch, key);
        return;
      }

      if (this.#finderOpen) {
        this.#handleFinderKey(ch, key);
        return;
      }

      this.#handleKey(ch, key);
    });

    // Dragging a window edge fires this continuously, and a rebuild touches
    // every entry in every buffer, so only the size it settles on is drawn.
    this.#screen.on('resize', () => {
      if (this.#resizeTimer) {
        clearTimeout(this.#resizeTimer);
      }
      this.#resizeTimer = setTimeout(() => {
        this.#resizeTimer = null;
        this.#relayout();
      }, 60);
      if (this.#resizeTimer.unref) {
        this.#resizeTimer.unref();
      }
    });

    // Ask the terminal to bracket pasted text with \x1b[200~ … \x1b[201~, and
    // — unless the shim is off — to report modified keys so Shift+Enter can be
    // told apart from Enter. Both requests are ignored by terminals that don't
    // implement them, and both are undone on the way out so the shell that
    // follows us is not left in an enhanced mode it never asked for.
    const enable = '\x1b[?2004h' + (this.#keyInput ? KEY_PROTOCOL_ENABLE : '');
    const restore = (this.#keyInput ? KEY_PROTOCOL_DISABLE : '') + '\x1b[?2004l';
    try {
      this.#screen.program.write(enable);
      // Only when we own the real terminal: an injected output belongs to a
      // test, and an exit hook per instance would both leak listeners and
      // print escape codes into the test log.
      if (!io.output) {
        process.on('exit', () => {
          try {
            process.stdout.write(restore);
          } catch {
            /* ignore */
          }
        });
      }
    } catch {
      /* terminals without bracketed paste just ignore this */
    }

    this.#screen.render();
  }

  #handleKey(ch, key) {
    const name = key.name || '';

    // Ctrl+C — quit
    if (key.ctrl && name === 'c') {
      this.emit('quit');
      return;
    }

    // Ctrl+K — command palette
    if (key.ctrl && name === 'k') {
      this.#openPalette();
      return;
    }

    // Ctrl+E — emoji picker
    if (key.ctrl && name === 'e') {
      this.#openEmoji();
      return;
    }

    // Ctrl+F — find in the current room's scrollback
    if (key.ctrl && name === 'f') {
      this.openFinder();
      return;
    }

    // Tab — autocomplete
    if (name === 'tab') {
      this.#handleTab();
      return;
    }

    // Any non-tab key resets tab cycling
    this.#tabState = { suggestions: [], index: -1, original: '' };

    // Alt+1..9 — switch chat buffer (multi-room)
    if (key.meta && /^[1-9]$/.test(name)) {
      this.emit('buffer-switch', Number(name) - 1);
      return;
    }

    // Alt+Enter / Ctrl+J — insert a newline. blessed's parser has no name for
    // \x1b\r, so the raw sequence is matched too: without it Alt+Enter sent the
    // message, exactly like the Shift+Enter it was documented as a fallback for.
    const seq = key.sequence || '';
    if (
      ((name === 'return' || name === 'enter') && key.meta) ||
      seq === '\x1b\r' ||
      seq === '\x1b\n' ||
      (key.ctrl && name === 'j')
    ) {
      this.#insertNewline();
      return;
    }

    // Enter — submit (newlines inside the message are preserved)
    if (name === 'return' || name === 'enter') {
      const text = this.#inputValue.replace(/^\n+|\n+$/g, '').trim();
      if (text) {
        this.emit('input', text);
      }
      this.#inputValue = '';
      this.#cursorPos = 0;
      this.#renderInput();
      return;
    }

    // Backspace — deletes a whole code point (emojis are surrogate pairs)
    if (name === 'backspace') {
      if (this.#cursorPos > 0) {
        const start = this.#prevCharBoundary(this.#cursorPos);
        this.#inputValue =
          this.#inputValue.slice(0, start) + this.#inputValue.slice(this.#cursorPos);
        this.#cursorPos = start;
      }
      this.emit('activity');
      this.#renderInput();
      return;
    }

    // Delete
    if (name === 'delete') {
      if (this.#cursorPos < this.#inputValue.length) {
        const end = this.#nextCharBoundary(this.#cursorPos);
        this.#inputValue = this.#inputValue.slice(0, this.#cursorPos) + this.#inputValue.slice(end);
      }
      this.#renderInput();
      return;
    }

    // Arrow left
    if (name === 'left') {
      if (this.#cursorPos > 0) {
        this.#cursorPos = this.#prevCharBoundary(this.#cursorPos);
      }
      this.#renderInput();
      return;
    }

    // Arrow right
    if (name === 'right') {
      if (this.#cursorPos < this.#inputValue.length) {
        this.#cursorPos = this.#nextCharBoundary(this.#cursorPos);
      }
      this.#renderInput();
      return;
    }

    // Home
    if (name === 'home') {
      this.#cursorPos = 0;
      this.#renderInput();
      return;
    }

    // End
    if (name === 'end') {
      this.#cursorPos = this.#inputValue.length;
      this.#renderInput();
      return;
    }

    // Ctrl+U — clear line
    if (key.ctrl && name === 'u') {
      this.#inputValue = '';
      this.#cursorPos = 0;
      this.#renderInput();
      return;
    }

    // Page Up / Page Down — scroll chat
    if (name === 'pageup' || name === 'pagedown') {
      const page = Math.max(1, this.#chatLog.height - this.#chatLog.iheight);
      this.#chatLog.scroll(name === 'pageup' ? -page : page);
      this.#screen.render();
      this.#syncScrollState();
      return;
    }

    // Regular character — length 2 = surrogate pair (emoji delivered whole
    // in some terminals; in others it arrives as two halves of length 1)
    const firstCode = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length <= 2 && !key.ctrl && !key.meta && firstCode > 0x1f && firstCode !== 0x7f) {
      this.#inputValue =
        this.#inputValue.slice(0, this.#cursorPos) + ch + this.#inputValue.slice(this.#cursorPos);
      this.#cursorPos += ch.length;
      this.emit('activity');
      this.#renderInput();
    }
  }

  // ── Screen lock ──────────────────────────────────────────────
  // Fullscreen overlay that hides the chat and swallows all input until the
  // session passphrase is re-entered. `verify` is a callback so the passphrase
  // itself never lives in the UI layer.
  showLock(verify) {
    if (this.#locked || typeof verify !== 'function') {
      return;
    }
    this.#locked = true;
    this.#lockVerify = verify;
    this.#lockInput = '';
    this.#lockError = false;
    this.#lockBox = blessed.box({
      parent: this.#screen,
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      tags: true,
      style: { bg: 'black', fg: 'white' },
    });
    this.#lockBox.setFront();
    this.#renderLock();
  }

  get isLocked() {
    return this.#locked;
  }

  #renderLock() {
    if (!this.#lockBox) {
      return;
    }
    const dots = '●'.repeat(Math.min(this.#lockInput.length, 40));
    const error = this.#lockError ? '{red-fg}Wrong passphrase — try again{/red-fg}' : '';
    const pad = '\n'.repeat(Math.max(1, Math.floor((this.#screen.height - 8) / 2)));
    this.#lockBox.setContent(
      `${pad}{center}{bold}🔒  Session locked{/bold}{/center}\n` +
        `{center}{#8888aa-fg}Messages keep arriving encrypted underneath{/#8888aa-fg}{/center}\n\n` +
        `{center}Passphrase: ${dots}{inverse} {/inverse}{/center}\n` +
        `{center}${error}{/center}`,
    );
    this.#screen.render();
  }

  #handleLockKey(ch, key) {
    const name = key.name || '';
    if (key.ctrl && name === 'c') {
      this.emit('quit'); // locking is privacy, not a prison
      return;
    }
    if (name === 'return' || name === 'enter') {
      if (this.#lockVerify(this.#lockInput)) {
        this.#lockBox.destroy();
        this.#lockBox = null;
        this.#locked = false;
        this.#lockVerify = null;
        this.#lockInput = '';
        this.#lockError = false;
        this.#screen.render();
        this.emit('unlocked');
      } else {
        this.#lockError = true;
        this.#lockInput = '';
        this.emit('lock-failed');
        this.#renderLock();
      }
      return;
    }
    if (name === 'backspace') {
      this.#lockInput = this.#lockInput.slice(0, -1);
      this.#renderLock();
      return;
    }
    const code = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length <= 2 && !key.ctrl && !key.meta && code > 0x1f && code !== 0x7f) {
      this.#lockInput += ch;
      this.#renderLock();
    }
  }

  // Bracketed-paste state machine. Returns true when the sequence is part of a
  // paste (start / content / end) and must not be treated as normal keypresses.
  #handlePaste(seq) {
    const START = '\x1b[200~';
    const END = '\x1b[201~';

    if (this.#pasting) {
      const endIdx = seq.indexOf(END);
      if (endIdx !== -1) {
        this.#pasteBuffer += seq.slice(0, endIdx);
        this.#pasting = false;
        const content = this.#pasteBuffer;
        this.#pasteBuffer = '';
        this.#insertPaste(content);
      } else {
        this.#pasteBuffer += seq;
      }
      return true;
    }

    const startIdx = seq.indexOf(START);
    if (startIdx === -1) {
      return false;
    }

    const rest = seq.slice(startIdx + START.length);
    const endIdx = rest.indexOf(END);
    if (endIdx !== -1) {
      this.#insertPaste(rest.slice(0, endIdx)); // whole paste in one sequence
    } else {
      this.#pasting = true;
      this.#pasteBuffer = rest;
    }
    return true;
  }

  #insertPaste(raw) {
    if (this.#locked) {
      return; // no pasting into a locked screen
    }
    const clean = cleanPaste(raw);
    if (!clean) {
      return;
    }
    // Drop a replay of the same paste from the second input pipeline.
    const now = performance.now();
    if (clean === this.#lastPaste.content && now - this.#lastPaste.time < 400) {
      return;
    }
    this.#lastPaste = { content: clean, time: now };

    this.#inputValue =
      this.#inputValue.slice(0, this.#cursorPos) + clean + this.#inputValue.slice(this.#cursorPos);
    this.#cursorPos += clean.length;
    this.emit('activity');
    this.#renderInput();
  }

  // Code-point boundaries — a surrogate pair moves as a whole
  #prevCharBoundary(pos) {
    if (pos <= 1) {
      return 0;
    }
    const code = this.#inputValue.charCodeAt(pos - 1);
    return code >= 0xdc00 && code <= 0xdfff ? pos - 2 : pos - 1;
  }

  #nextCharBoundary(pos) {
    const len = this.#inputValue.length;
    if (pos >= len) {
      return len;
    }
    const code = this.#inputValue.charCodeAt(pos);
    return code >= 0xd800 && code <= 0xdbff && pos + 1 < len ? pos + 2 : pos + 1;
  }

  #renderInput() {
    const { content, height } = inputView(this.#inputValue, this.#cursorPos, INPUT_MAX_LINES);
    this.#applyInputHeight(height);
    this.#inputBox.setContent(content);
    this.#screen.render();
  }

  // Grow/shrink the input box with the number of lines and reflow the status bar
  // and chat log above it.
  #applyInputHeight(height) {
    if (this.#inputBox.height === height) {
      return;
    }
    this.#inputBox.height = height;
    if (this.#statusBar) {
      this.#statusBar.bottom = height;
    }
    this.#chatLog.bottom = height + 1;
  }

  // A newline request lifted off the raw stream by the keyboard shim. Overlays
  // own the keyboard while they are up, so it only reaches the composer.
  #onEnhancedNewline() {
    if (this.#locked || this.#paletteOpen || this.#emojiOpen || this.#finderOpen) {
      return;
    }
    this.#insertNewline();
  }

  #insertNewline() {
    this.#inputValue =
      this.#inputValue.slice(0, this.#cursorPos) + '\n' + this.#inputValue.slice(this.#cursorPos);
    this.#cursorPos += 1;
    this.emit('activity');
    this.#renderInput();
  }

  // ── Command palette (Ctrl+K, fuzzy) ──────────────────
  #openPalette() {
    this.#paletteOpen = true;
    this.#paletteQuery = '';
    this.#refreshPalette();
    this.#palette.show();
    this.#palette.setFront();
    this.#screen.render();
  }

  #closePalette() {
    this.#paletteOpen = false;
    this.#palette.hide();
    this.#screen.render();
  }

  #paletteMatches() {
    return fuzzyFilter(COMMAND_INFO, this.#paletteQuery, (c) => `${c[0]} ${c[1]}`);
  }

  #refreshPalette() {
    const matches = this.#paletteMatches();
    this.#palette.setItems(
      matches.map(([cmd, desc]) => ` {bold}${cmd}{/bold}  {#8888aa-fg}${desc}{/#8888aa-fg}`),
    );
    this.#palette.select(0);
    const q = this.#paletteQuery ? ` › ${this.#paletteQuery}` : '';
    this.#palette.setLabel(` Commands (Ctrl+K)${q} `);
    this.#screen.render();
  }

  #handlePaletteKey(ch, key) {
    const name = key.name || '';
    if (name === 'escape' || (key.ctrl && name === 'c')) {
      this.#closePalette();
      return;
    }
    if (name === 'up' || name === 'down') {
      this.#palette[name === 'up' ? 'up' : 'down'](1);
      this.#screen.render();
      return;
    }
    if (name === 'return' || name === 'enter') {
      const matches = this.#paletteMatches();
      const chosen = matches[this.#palette.selected];
      if (chosen) {
        this.#inputValue = `${chosen[0]} `;
        this.#cursorPos = this.#inputValue.length;
        this.#renderInput();
      }
      this.#closePalette();
      return;
    }
    if (name === 'backspace') {
      this.#paletteQuery = this.#paletteQuery.slice(0, -1);
      this.#refreshPalette();
      return;
    }
    // printable char → extend the query
    const code = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length === 1 && !key.ctrl && !key.meta && code > 0x1f && code !== 0x7f) {
      this.#paletteQuery += ch;
      this.#refreshPalette();
    }
  }

  // ── Scrollback finder (Ctrl+F) ───────────────────────
  // Search what is on screen in THIS room and jump to the hit. Unlike
  // /search (which queries the encrypted history on disk, possibly from other
  // sessions), every result here has a real line to scroll to.

  /** Open the finder, optionally pre-filled (used by /search results). */
  openFinder(query = '') {
    this.#finderOpen = true;
    this.#finderQuery = query;
    this.#refreshFinder();
    this.#finder.show();
    this.#finder.setFront();
    this.#screen.render();
  }

  #closeFinder() {
    this.#finderOpen = false;
    this.#finder.hide();
    this.#screen.render();
  }

  #refreshFinder() {
    this.#finderHits = findInLines(this.#lines, this.#finderQuery);
    this.#finder.setItems(
      this.#finderHits.length > 0
        ? this.#finderHits.map((h) => ` {#8888aa-fg}${h.lineIndex + 1}{/#8888aa-fg}  ${h.preview}`)
        : [
            this.#finderQuery
              ? ' {#8888aa-fg}no match in this room{/#8888aa-fg}'
              : ' {#8888aa-fg}type to search…{/#8888aa-fg}',
          ],
    );
    this.#finder.select(0);
    const q = this.#finderQuery ? ` › ${this.#finderQuery}` : '';
    const n = this.#finderHits.length ? ` — ${this.#finderHits.length} hit(s)` : '';
    this.#finder.setLabel(` Find in this room (Ctrl+F)${q}${n} `);
    this.#screen.render();
  }

  /** Scroll the chat to `lineIndex` and mark it so the eye finds it. */
  jumpToLine(lineIndex) {
    if (lineIndex < 0 || lineIndex >= this.#lines.length) {
      return false;
    }
    this.#clearJumpMark();
    const original = this.#lines[lineIndex];
    this.#finderMark = { lineIndex, original };
    this.#lines[lineIndex] = `{yellow-fg}▶{/yellow-fg}${original}`;
    this.#chatLog.setContent(this.#lines.join('\n'));
    // An entry spans several rows now, so the scroll target is the row the
    // entry starts on, not its index. Put the hit a few rows from the top so
    // its context stays visible.
    let row = 0;
    for (let i = 0; i < lineIndex; i++) {
      if (this.#lines[i] !== null) {
        row += String(this.#lines[i]).split('\n').length;
      }
    }
    this.#chatLog.scrollTo(Math.max(0, row - 3));
    this.#screen.render();
    this.#syncScrollState();
    return true;
  }

  #clearJumpMark() {
    if (!this.#finderMark) {
      return;
    }
    const { lineIndex, original } = this.#finderMark;
    if (this.#lines[lineIndex] !== undefined) {
      this.#lines[lineIndex] = original;
    }
    this.#finderMark = null;
  }

  #handleFinderKey(ch, key) {
    const name = key.name || '';
    if (name === 'escape' || (key.ctrl && name === 'c')) {
      this.#closeFinder();
      return;
    }
    if (name === 'up' || name === 'down') {
      this.#finder[name === 'up' ? 'up' : 'down'](1);
      this.#screen.render();
      return;
    }
    if (name === 'return' || name === 'enter') {
      const hit = this.#finderHits[this.#finder.selected];
      this.#closeFinder();
      if (hit) {
        this.jumpToLine(hit.lineIndex);
      }
      return;
    }
    if (name === 'backspace') {
      this.#finderQuery = this.#finderQuery.slice(0, -1);
      this.#refreshFinder();
      return;
    }
    const code = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length === 1 && !key.ctrl && !key.meta && code > 0x1f && code !== 0x7f) {
      this.#finderQuery += ch;
      this.#refreshFinder();
    }
  }

  // ── Emoji picker (Ctrl+E, fuzzy) ─────────────────────
  #openEmoji() {
    this.#emojiOpen = true;
    this.#emojiQuery = '';
    this.#refreshEmoji();
    this.#emojiPicker.show();
    this.#emojiPicker.setFront();
    this.#screen.render();
  }

  #closeEmoji() {
    this.#emojiOpen = false;
    this.#emojiPicker.hide();
    this.#screen.render();
  }

  #emojiMatches() {
    return fuzzyFilter(EMOJI_ENTRIES, this.#emojiQuery, (e) => e[0]);
  }

  #refreshEmoji() {
    const matches = this.#emojiMatches();
    this.#emojiPicker.setItems(
      matches.map(([code, emoji]) => ` ${emoji}  {#8888aa-fg}${code}{/#8888aa-fg}`),
    );
    this.#emojiPicker.select(0);
    const q = this.#emojiQuery ? ` › ${this.#emojiQuery}` : '';
    this.#emojiPicker.setLabel(` Emoji (Ctrl+E)${q} `);
    this.#screen.render();
  }

  #handleEmojiKey(ch, key) {
    const name = key.name || '';
    if (name === 'escape' || (key.ctrl && name === 'c')) {
      this.#closeEmoji();
      return;
    }
    if (name === 'up' || name === 'down') {
      this.#emojiPicker[name === 'up' ? 'up' : 'down'](1);
      this.#screen.render();
      return;
    }
    if (name === 'return' || name === 'enter') {
      const chosen = this.#emojiMatches()[this.#emojiPicker.selected];
      if (chosen) {
        const emoji = chosen[1];
        this.#inputValue =
          this.#inputValue.slice(0, this.#cursorPos) +
          emoji +
          this.#inputValue.slice(this.#cursorPos);
        this.#cursorPos += emoji.length;
        this.#renderInput();
      }
      this.#closeEmoji();
      return;
    }
    if (name === 'backspace') {
      this.#emojiQuery = this.#emojiQuery.slice(0, -1);
      this.#refreshEmoji();
      return;
    }
    const code = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length === 1 && !key.ctrl && !key.meta && code > 0x1f && code !== 0x7f) {
      this.#emojiQuery += ch;
      this.#refreshEmoji();
    }
  }

  // ── Tab autocomplete ─────────────────────────────────
  #handleTab() {
    if (this.#tabState.suggestions.length === 0) {
      this.#tabState.original = this.#inputValue;
      this.#tabState.suggestions = this.#computeSuggestions(this.#inputValue);
      this.#tabState.index = -1;
    }

    if (this.#tabState.suggestions.length === 0) {
      return;
    }

    this.#tabState.index = (this.#tabState.index + 1) % this.#tabState.suggestions.length;
    this.#inputValue = this.#tabState.suggestions[this.#tabState.index];
    this.#cursorPos = this.#inputValue.length;
    this.#renderInput();
  }

  #computeSuggestions(input) {
    // Emoji shortcode: last token starting with ':' (works in
    // any position, including inside commands like /status)
    const lastSpace = input.lastIndexOf(' ');
    const lastWord = input.slice(lastSpace + 1);
    if (/^:[a-z0-9_+-]+$/.test(lastWord)) {
      const head = input.slice(0, lastSpace + 1);
      return shortcodeSuggestions(lastWord).map((code) => head + code);
    }

    if (!input.startsWith('/')) {
      return [];
    }

    const spaceIdx = input.indexOf(' ');

    // No space yet — autocomplete command name
    if (spaceIdx === -1) {
      const prefix = input.toLowerCase();
      return COMMANDS.filter((cmd) => cmd.startsWith(prefix));
    }

    // Has space — autocomplete nickname argument
    const cmd = input.slice(0, spaceIdx).toLowerCase();
    if (!NICK_COMMANDS.includes(cmd)) {
      return [];
    }

    const partial = input.slice(spaceIdx + 1).toLowerCase();
    return this.#peerNames
      .filter((name) => name.toLowerCase().startsWith(partial))
      .map((name) => `${cmd} ${name}`);
  }

  setPeerNames(names) {
    this.#peerNames = names;
  }

  // ── Typing indicator ──────────────────────────────────
  #updateTypingLabel() {
    if (this.#typingPeers.size === 0) {
      this.#inputBox.setLabel('');
      this.#screen.render();
      return;
    }

    const names = [...this.#typingPeers].join(', ');
    const dots = TYPING_DOTS[this.#typingAnimFrame % TYPING_DOTS.length];
    this.#inputBox.setLabel(` {yellow-fg}${names} typing${dots}{/yellow-fg} `);
    this.#screen.render();
  }

  showTyping(nickname) {
    this.#typingPeers.add(nickname);

    if (!this.#typingAnimInterval) {
      this.#typingAnimFrame = 0;
      this.#updateTypingLabel();
      this.#typingAnimInterval = setInterval(() => {
        this.#typingAnimFrame++;
        this.#updateTypingLabel();
      }, 400);
    } else {
      this.#updateTypingLabel();
    }
  }

  hideTyping(nickname) {
    this.#typingPeers.delete(nickname);

    if (this.#typingPeers.size === 0 && this.#typingAnimInterval) {
      clearInterval(this.#typingAnimInterval);
      this.#typingAnimInterval = null;
      this.#typingAnimFrame = 0;
    }
    this.#updateTypingLabel();
  }

  #headerContent() {
    let dot;
    if (this.#connState === 'reconnecting') {
      // animated braille spinner while reconnecting
      dot = `{yellow-fg}${SPINNER_FRAMES[this.#spinnerFrame % SPINNER_FRAMES.length]}{/yellow-fg}`;
    } else if (this.#connState === 'online' && this.#reconnectFlashActive) {
      // brief green pulse when we come back online
      dot =
        this.#reconnectFlashFrame % 2 === 0
          ? '{#00ff9f-fg}\u25c9{/#00ff9f-fg}'
          : '{green-fg}\u25cf{/green-fg}';
    } else {
      const dotColor = this.#connState === 'online' ? 'green' : 'red';
      dot = `{${dotColor}-fg}\u25cf{/${dotColor}-fg}`;
    }
    const indicators =
      this.#headerIndicators.length > 0
        ? '  ' + this.#headerIndicators.map((i) => i.label).join(' ')
        : '';
    return `  ${dot} {bold}CipherMesh{/bold}  {white-fg}\u2502{/white-fg}  {bold}${this.#nickname}{/bold}${indicators}      {|}  ${dot} ${this.#onlineCount} online  {white-fg}\u2502{/white-fg}  {green-fg}E2E{/green-fg}  `;
  }

  setHeaderIndicator(key, label) {
    this.removeHeaderIndicator(key);
    this.#headerIndicators.push({ key, label });
    this.#updateHeader();
  }

  removeHeaderIndicator(key) {
    this.#headerIndicators = this.#headerIndicators.filter((i) => i.key !== key);
    this.#updateHeader();
  }

  #updateHeader() {
    this.#header.setContent(this.#headerContent());
    this.#screen.render();
  }

  setOnlineCount(count) {
    this.#onlineCount = count;
    this.#updateHeader();
  }

  // 'online' | 'reconnecting' | 'offline' — recolors the header dot.
  setConnectionState(state) {
    const prev = this.#connState;
    this.#connState = state;
    if (state === 'reconnecting') {
      if (!this.#connSpinner) {
        this.#connSpinner = setInterval(() => {
          this.#spinnerFrame++;
          this.#updateHeader();
        }, 120);
        if (this.#connSpinner.unref) {
          this.#connSpinner.unref();
        }
      }
    } else if (this.#connSpinner) {
      clearInterval(this.#connSpinner);
      this.#connSpinner = null;
    }
    // Coming back online after being away → a brief green pulse.
    if (state === 'online' && prev && prev !== 'online') {
      this.#startReconnectFlash();
    }
    this.#updateHeader();
  }

  #startReconnectFlash() {
    if (this.#reconnectFlashTimer) {
      clearInterval(this.#reconnectFlashTimer);
    }
    this.#reconnectFlashActive = true;
    this.#reconnectFlashFrame = 0;
    this.#reconnectFlashTimer = setInterval(() => {
      this.#reconnectFlashFrame++;
      if (this.#reconnectFlashFrame >= 8) {
        clearInterval(this.#reconnectFlashTimer);
        this.#reconnectFlashTimer = null;
        this.#reconnectFlashActive = false;
      }
      this.#updateHeader();
    }, 110);
    if (this.#reconnectFlashTimer.unref) {
      this.#reconnectFlashTimer.unref();
    }
  }

  setNickname(nickname) {
    this.#nickname = nickname;
    this.#updateHeader();
  }

  #statusContent() {
    // Several buffers → an IRC-style bar with unread badges; one → plain room.
    let room;
    if (this.#bufferBar.length > 1) {
      room = this.#bufferBar
        .map((b, i) => {
          const lock = b.private ? '🔒' : '';
          const unread = b.unread > 0 ? `{yellow-fg}•${b.unread}{/yellow-fg}` : '';
          const label = `${i + 1}:${lock}${b.room}${unread}`;
          return b.active
            ? `{inverse}{cyan-fg}[${label}]{/cyan-fg}{/inverse}`
            : `{cyan-fg}[${label}]{/cyan-fg}`;
        })
        .join(' ');
    } else {
      room = `{cyan-fg}#${this.#statusRoom}{/cyan-fg}`;
    }
    // The topic earns its place next to the room name; it is what tells you
    // what a room is FOR. Truncated so it can never push the hints off-screen.
    const topic = this.#topic
      ? `  {#9a9ad0-fg}📋 ${blessed.escape(
          this.#topic.length > 60 ? `${this.#topic.slice(0, 57)}…` : this.#topic,
        )}{/#9a9ad0-fg}`
      : '';
    const fp =
      this.#statusFingerprint && !this.#topic
        ? `   {#8888aa-fg}🔑 ${this.#statusFingerprint}{/#8888aa-fg}`
        : '';
    const hint =
      this.#bufferBar.length > 1
        ? '{#7777aa-fg}Alt+1..9 buffers · Ctrl+K commands · /help{/#7777aa-fg}'
        : '{#7777aa-fg}Tab · Ctrl+K commands · Ctrl+E emoji · PgUp/PgDn scroll · /help · Ctrl+C quit{/#7777aa-fg}';
    return `  ${room}${topic}${fp}      {|}  ${hint}  `;
  }

  #updateStatusBar() {
    if (this.#statusBar) {
      this.#statusBar.setContent(this.#statusContent());
      this.#screen.render();
    }
  }

  /** Set (or clear with null) the topic shown in the status bar. */
  setTopic(text) {
    this.#topic = text || null;
    this.#updateStatusBar();
  }

  setFingerprint(fingerprint) {
    // short prefix of the fingerprint as a persistent identity anchor
    this.#statusFingerprint = (fingerprint || '').slice(0, 17);
    this.#updateStatusBar();
  }

  setRoom(room) {
    this.#statusRoom = room || 'general';
    this.#updateStatusBar();
  }

  // ── Buffers (multi-room, IRC style) ──────────────────────────
  // The active buffer lives in #lines + the chat log; inactive ones are plain
  // line arrays in #bufferLines. All add*() methods target the active buffer —
  // toBuffer() retargets them for one call without touching the screen.

  get activeBuffer() {
    return this.#activeBuffer;
  }

  /**
   * Run `fn` with every add*() call landing in `room`'s stored buffer instead
   * of the screen. Uses proxies so the formatting pipeline (widths, colors,
   * grouping) is exactly the one the live log uses.
   */
  toBuffer(room, fn) {
    if (!room || room === this.#activeBuffer) {
      return fn();
    }
    if (!this.#bufferLines.has(room)) {
      this.#bufferLines.set(room, []);
      this.#bufferSpecs.set(room, []);
    }
    const liveLines = this.#lines;
    const liveSpecs = this.#specs;
    const liveSender = this.#lastSender;
    const liveStamp = this.#lastStamp;
    const liveLog = this.#chatLog;
    const liveScreen = this.#screen;
    this.#lines = this.#bufferLines.get(room);
    this.#specs = this.#bufferSpecs.get(room);
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#redirecting = true;
    this.#chatLog = new Proxy(liveLog, {
      get: (t, p) => (p === 'log' ? () => {} : t[p]),
    });
    this.#screen = new Proxy(liveScreen, {
      get: (t, p) => {
        if (p === 'render') {
          return () => {};
        }
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    try {
      return fn();
    } finally {
      this.#lines = liveLines;
      this.#specs = liveSpecs;
      this.#lastSender = liveSender;
      this.#lastStamp = liveStamp;
      this.#chatLog = liveLog;
      this.#screen = liveScreen;
      this.#redirecting = false;
    }
  }

  /** Bring `room`'s buffer on screen, storing the current one. */
  switchBuffer(room) {
    if (room === this.#activeBuffer) {
      return;
    }
    this.#bufferLines.set(this.#activeBuffer, this.#lines);
    this.#bufferSpecs.set(this.#activeBuffer, this.#specs);
    this.#lines = this.#bufferLines.get(room) || [];
    this.#specs = this.#bufferSpecs.get(room) || [];
    this.#bufferLines.delete(room);
    this.#bufferSpecs.delete(room);
    this.#activeBuffer = room;
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#chatLog.setContent(this.#lines.join('\n'));
    this.#chatLog.setScrollPerc(100);
    this.setRoom(room);
    this.#screen.render();
  }

  /** Forget every buffer and start fresh in `room` (reconnect / legacy switch). */
  resetBuffers(room) {
    this.#bufferLines.clear();
    this.#bufferSpecs.clear();
    this.#activeBuffer = room;
    this.#lines = [];
    this.#specs = [];
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#chatLog.setContent('');
    this.setRoom(room);
    this.#screen.render();
  }

  dropBuffer(room) {
    this.#bufferLines.delete(room);
    this.#bufferSpecs.delete(room);
  }

  clearBuffer(room) {
    if (room === this.#activeBuffer) {
      this.clearChat();
    } else if (this.#bufferLines.has(room)) {
      this.#bufferLines.get(room).length = 0;
      this.#bufferSpecs.get(room)?.splice(0);
    }
  }

  /** Status-bar buffer list: [{ room, active, unread, private }]. */
  setBufferBar(items) {
    this.#bufferBar = Array.isArray(items) ? items : [];
    this.#updateStatusBar();
  }

  // Render a real image inline by briefly leaving the TUI (kitty/iTerm2). Safe
  // best-effort: any keypress or a 30s timeout returns to the chat.
  showRealImage(escapeSeq) {
    let resumed = false;
    let timer = null;
    const onData = () => resume();
    const resume = () => {
      if (resumed) {
        return;
      }
      resumed = true;
      process.stdin.removeListener('data', onData);
      if (timer) {
        clearTimeout(timer);
      }
      try {
        this.#screen.enter();
        this.#screen.render();
      } catch {
        /* ignore */
      }
    };

    try {
      this.#screen.leave();
      process.stdout.write(
        `\n${escapeSeq}\n\n  [high-resolution image — press Enter to return to chat]\n`,
      );
      process.stdin.on('data', onData);
      timer = setTimeout(resume, 30_000);
      if (timer.unref) {
        timer.unref();
      }
    } catch {
      resume();
    }
  }

  addMessage(
    nickname,
    text,
    isDM = false,
    ephemeralLabel = null,
    deniable = false,
    mentioned = false,
    trust = 'none',
  ) {
    this.#daySeparator();
    const isSelfNow = nickname === this.#nickname || nickname.includes('\u2192');
    // The sentinel is written as an escape, not typed as a raw byte: a bare
    // NUL anywhere in the source makes this entire file count as binary, and
    // a binary file is skipped by grep and shown without a diff on GitHub.
    const senderKey = isSelfNow ? '\u0000self' : nickname;
    const stamp = time();
    // Runs from one sender collapse under a single header — but only inside the
    // same minute, so folding them never costs the reader a timestamp.
    const opts = {
      isDM,
      ephemeralLabel,
      deniable,
      mentioned,
      trust,
      grouped: this.#lastSender === senderKey && this.#lastStamp === stamp,
      stamp,
    };
    if (!opts.grouped && this.#lines.length > 0 && !this.#suppressSeparator) {
      this.#append('');
    }
    this.#suppressSeparator = false;
    const line = this.#composeMessageLine(nickname, text, opts);

    this.#append(line, { kind: 'message', nickname, text, opts });
    this.#screen.render();
    this.#lastSender = senderKey;
    this.#lastStamp = stamp;
    if (!isSelfNow) {
      this.#noteIncoming(mentioned || isDM);
    }
    return { lineIndex: this.#lines.length - 1, render: { nickname, opts } };
  }

  /**
   * Rewrite an existing message line with new text — used by /edit, so an
   * edited message changes IN PLACE instead of arriving as a separate line the
   * reader has to mentally staple to the original.
   */
  replaceMessageText(lineIndex, nickname, newText, opts) {
    const edited = { ...opts, edited: true };
    this.updateLine(lineIndex, this.#composeMessageLine(nickname, newText, edited), {
      kind: 'message',
      nickname,
      text: newText,
      opts: edited,
    });
  }

  /** Replace a message with a tombstone (used by /delete). */
  tombstoneMessage(lineIndex, nickname) {
    const spec = {
      kind: 'meta',
      marker: '\ud83d\udeab',
      colorTag: '#666666-fg',
      body: `${blessed.escape(nickname)} deleted a message`,
      stamp: time(),
    };
    this.updateLine(lineIndex, this.#recompose(spec), spec);
  }

  // Columns the message body is inset by. The header puts the avatar at the
  // same column, so a message reads as one block: ` HH:MM  ` and `      ▎ `
  // are both eight cells wide.
  static #GUTTER = 8;

  // How wide the text itself may run. Full-terminal lines are hard to read and
  // were what made a long message look like a wall, so the body is capped well
  // short of the window and the remaining columns are left as breathing room
  // (and as the landing strip for a ✓✓ or a reaction).
  #bodyWidth() {
    const inner = (this.#chatLog.width || 80) - (this.#chatLog.iwidth || 2);
    return Math.max(
      12,
      Math.min(MAX_TEXT_WIDTH, Math.round(inner * BODY_WIDTH_RATIO), inner - UI.#GUTTER - 4),
    );
  }

  // Builds a message: a header line naming the sender, then the wrapped body,
  // as one '\n'-joined entry so it stays a single addressable log line.
  // Shared by addMessage and replaceMessageText so an edited message keeps
  // exactly the layout it had instead of drifting into a different shape.
  #composeMessageLine(nickname, text, opts) {
    const {
      isDM = false,
      ephemeralLabel = null,
      deniable = false,
      mentioned = false,
      trust = 'none',
      grouped = false,
      edited = false,
      stamp = time(),
    } = opts || {};

    const color = nickColor(nickname);
    const isSelf = nickname === this.#nickname || nickname.includes('\u2192');
    const tag = isSelf ? 'bold' : `${color}-fg`;
    const avatar = nickAvatar(isSelf ? this.#nickname : nickname);
    const dmLabel = isDM ? ' {magenta-fg}(DM){/magenta-fg}' : '';
    const ephLabel = ephemeralLabel ? ` {yellow-fg}[${ephemeralLabel}]{/yellow-fg}` : '';
    const denLabel = deniable ? ' {magenta-fg}[D]{/magenta-fg}' : '';
    // Trust badge next to the name: check = SAS-verified, cross = key changed.
    const trustGlyph =
      trust === 'verified'
        ? ' {green-fg}✓{/green-fg}'
        : trust === 'mismatch'
          ? ' {red-fg}✗{/red-fg}'
          : '';
    const editedMark = edited ? ' {#8888aa-fg}(edited){/#8888aa-fg}' : '';
    const mentionMark = mentioned && !isSelf ? ' {yellow-fg}\ud83d\udd14{/yellow-fg}' : '';

    // A coloured rule down the left of the body is what tells the messages
    // apart now that they all start at the same column: yellow when the line
    // mentions you, magenta for a DM, the accent for your own, nothing for a
    // plain incoming message.
    const rule = mentioned && !isSelf ? 'yellow' : isDM ? 'magenta' : isSelf ? '#7b2dff' : null;
    const prefix = rule ? `      {${rule}-fg}▎{/${rule}-fg} ` : ' '.repeat(UI.#GUTTER);

    const body = wrapTagged(`${renderMarkdown(text)}${editedMark}`, this.#bodyWidth()).map(
      (segment) => prefix + segment,
    );
    if (grouped) {
      return body.join('\n');
    }
    const header =
      ` {white-fg}${stamp}{/white-fg}  ${avatar} {${tag}}${blessed.escape(nickname)}{/${tag}}` +
      `${trustGlyph}${dmLabel}${ephLabel}${denLabel}${mentionMark}`;
    return [header, ...body].join('\n');
  }

  /**
   * Append one entry to the active buffer.
   *
   * `spec` is the recipe that produced `line`, kept index-aligned with it so a
   * resize can lay the entry out again at the new width. Entries with no recipe
   * — day separators, welcome panels, image previews — keep the string they were
   * given, which for a rendered image is the only correct thing to do.
   */
  #append(line, spec = null) {
    this.#lines.push(line);
    this.#specs.push(spec);
    this.#chatLog.log(line);
    return this.#lines.length - 1;
  }

  /** Rebuild one entry from its recipe, or null if it has none. */
  #recompose(spec) {
    if (!spec) {
      return null;
    }
    const line =
      spec.kind === 'message'
        ? this.#composeMessageLine(spec.nickname, spec.text, spec.opts)
        : spec.kind === 'meta'
          ? this.#composeMeta(spec.marker, spec.colorTag, spec.body, spec.stamp)
          : spec.kind === 'quote'
            ? this.#composeQuote(spec.nickname, spec.excerpt)
            : spec.kind === 'tip'
              ? this.#composeTip(spec.text)
              : null;
    return line === null || !spec.badge ? line : this.#withBadge(line, spec.badge);
  }

  /**
   * Lay every entry out again for the current width.
   *
   * Messages are wrapped and padded when they are composed, so without this a
   * resize left the whole scrollback measured for the old window: narrower, and
   * blessed re-wraps the leftovers into the gutter; wider, and old messages stay
   * narrow beside new ones. Inactive buffers are done too, or switching to one
   * after a resize would show the same drift a moment later.
   */
  #relayout() {
    this.#clearJumpMark(); // its saved "original" is about to be replaced
    const rebuild = (lines, specs) => {
      for (let i = 0; i < lines.length; i++) {
        if (lines[i] === null) {
          continue;
        }
        const line = this.#recompose(specs[i]);
        if (line !== null) {
          lines[i] = line;
        }
      }
    };
    rebuild(this.#lines, this.#specs);
    for (const [room, lines] of this.#bufferLines) {
      rebuild(lines, this.#bufferSpecs.get(room) || []);
    }

    this.#chatLog.setContent(this.#lines.filter((l) => l !== null).join('\n'));
    if (!this.#scrolledUp) {
      this.#chatLog.setScrollPerc(100);
    }
    // A full repaint, not just a render: the old frame's padding leaves cells
    // behind that a diffed update has no reason to touch.
    this.#screen.realloc();
    this.#screen.render();
    this.#syncScrollState();
  }

  // The one-off lines that are not messages — system notices, errors, /me,
  // tombstones. They share the message gutter so the whole log lines up on one
  // column, and they wrap with a hanging indent instead of running past the
  // border the way an unwrapped line did.
  #composeMeta(marker, colorTag, taggedBody, stamp = time()) {
    const lines = wrapTagged(`{${colorTag}}${taggedBody}{/${colorTag}}`, this.#metaWidth());
    const head = ` {white-fg}${stamp}{/white-fg}  {${colorTag}}${marker}{/${colorTag}} `;
    const indent = ' '.repeat(UI.#GUTTER + 2);
    return [head + lines[0], ...lines.slice(1).map((line) => indent + line)].join('\n');
  }

  // Notices are not conversation, so they are not held to the message body's
  // reading width — only to the box. /help's table would otherwise be folded in
  // half on a window with room to spare.
  #metaWidth() {
    const inner = (this.#chatLog.width || 80) - (this.#chatLog.iwidth || 2);
    return Math.max(20, inner - UI.#GUTTER - 4);
  }

  #pushMeta(spec, incoming = true) {
    const lineIndex = this.#append(this.#recompose(spec), spec);
    this.#screen.render();
    if (incoming) {
      this.#noteIncoming();
    }
    return { lineIndex };
  }

  #metaSpec(marker, colorTag, body) {
    return { kind: 'meta', marker, colorTag, body, stamp: time() };
  }

  #daySeparator() {
    const today = new Date().toLocaleDateString('en-US');
    if (this.#lastMsgDate === today) {
      return;
    }
    this.#lastMsgDate = today;
    this.#lastSender = null;
    this.#lastStamp = null;
    const sep = ` {#666666-fg}\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  ${today}  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{/#666666-fg}`;
    this.#append(sep);
  }

  // Visible width of a string with blessed tags (emoji ~2 columns)
  #visibleWidth(tagged) {
    const plain = String(tagged).replace(/\{[^{}]*\}/g, '');
    let width = 0;
    for (const chr of plain) {
      width += glyphWidth(chr.codePointAt(0));
    }
    return width;
  }

  // Hangs a badge (\u2713\u2713, a reaction) off the end of a message, flush right on
  // its last line so it terminates the block instead of running on from the
  // text. `baseLine` is the message as it was drawn, so repeated calls replace
  // the badge rather than stacking copies of it.
  appendBadge(lineIndex, baseLine, badgeTagged) {
    // The recipe rebuilds the message without its badge, so preferring it over
    // the caller's copy is what lets the badge survive a resize: it is stored
    // and re-hung after the entry is laid out again, rather than baked into a
    // string measured for the old width.
    const spec = this.#specs[lineIndex];
    const base = spec ? this.#recompose({ ...spec, badge: null }) : String(baseLine);
    if (spec) {
      spec.badge = badgeTagged;
    }
    this.updateLine(lineIndex, this.#withBadge(base, badgeTagged), spec);
  }

  /** Hang a badge off the last line of an entry, flush right. */
  #withBadge(line, badgeTagged) {
    const segments = String(line).split('\n');
    const last = segments[segments.length - 1];
    // Two columns short of the inner width: one for the scrollbar blessed
    // reserves on the right, one so the badge never lands against the border.
    const avail = (this.#chatLog.width || 80) - (this.#chatLog.iwidth || 2) - 2;
    const gap = avail - this.#visibleWidth(last) - this.#visibleWidth(badgeTagged);
    segments[segments.length - 1] =
      gap > 1 ? last + ' '.repeat(gap) + badgeTagged : `${last} ${badgeTagged}`;
    return segments.join('\n');
  }

  // Third-person action (/me). Rendered as a distinct italic line so it never
  // reads like someone quoting themselves.
  addActionMessage(nickname, text) {
    this.#lastSender = null; // an action breaks message grouping
    this.#lastStamp = null;
    return this.#pushMeta(
      this.#metaSpec(
        '✦',
        'magenta-fg',
        `{bold}${blessed.escape(nickname)}{/bold} ${renderMarkdown(text)}`,
      ),
    );
  }

  addSystemMessage(text) {
    this.#lastSender = null; // interrupts message grouping
    this.#lastStamp = null;
    this.#pushMeta(this.#metaSpec('*', 'white-fg', blessed.escape(text)));
  }

  addErrorMessage(text) {
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#pushMeta(this.#metaSpec('!', 'red-fg', blessed.escape(text)));
  }

  addInfoMessage(text) {
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#pushMeta(this.#metaSpec('\u00b7', 'cyan-fg', blessed.escape(text)), false);
  }

  // A one-line security/UX tip (💡). Plain text — no blessed tags interpreted.
  addTip(text) {
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#append(this.#composeTip(text), { kind: 'tip', text });
    this.#screen.render();
  }

  #composeTip(text) {
    const wrapped = wrapTagged(
      `{#9a9ad0-fg}${blessed.escape(text)}{/#9a9ad0-fg}`,
      this.#metaWidth(),
    );
    const indent = ' '.repeat(3);
    return [
      ` {yellow-fg}💡{/yellow-fg} ${wrapped[0]}`,
      ...wrapped.slice(1).map((l) => indent + l),
    ].join('\n');
  }

  // A framed "getting started" panel for the empty chat. `lines` may contain
  // blessed tags (the caller styles them); the title is escaped.
  addWelcome(title, lines) {
    this.#lastSender = null;
    this.#lastStamp = null;
    const push = (l) => this.#append(l);
    push('');
    push(`  {#7b2dff-fg}╭─{/#7b2dff-fg} {bold}${blessed.escape(title)}{/bold}`);
    for (const l of lines) {
      push(`  {#7b2dff-fg}│{/#7b2dff-fg}  ${l}`);
    }
    push(`  {#7b2dff-fg}╰──────────────────────────────────────────{/#7b2dff-fg}`);
    push('');
    this.#screen.render();
  }

  // The "replying to …" line that precedes a /reply. Indented to the message
  // gutter so it reads as part of the reply that follows it.
  addQuoteLine(nickname, excerpt) {
    if (this.#lines.length > 0) {
      this.#append('');
    }
    this.#append(this.#composeQuote(nickname, excerpt), { kind: 'quote', nickname, excerpt });
    this.#screen.render();
    // The reply that follows belongs to this quote, so it needs its own header
    // (grouping it under an earlier message would strand the quote) but not a
    // second blank line between the two.
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#suppressSeparator = true;
  }

  #composeQuote(nickname, excerpt) {
    const quoted = `↩ ${blessed.escape(nickname)}: "${blessed.escape(excerpt)}"`;
    const indent = ' '.repeat(UI.#GUTTER);
    return wrapTagged(`{#888888-fg}${quoted}{/#888888-fg}`, this.#metaWidth())
      .map((line) => indent + line)
      .join('\n');
  }

  addPlainLines(rawLines) {
    for (const raw of rawLines) {
      this.#append(` ${blessed.escape(raw)}`);
    }
    this.#screen.render();
  }

  // Lines already carry blessed color tags — do not escape
  addImagePreview(taggedLines) {
    for (const raw of taggedLines) {
      // No recipe: half-block pixels are laid out for the width they were
      // rendered at, and re-wrapping them would shred the picture.
      this.#append(` ${raw}`);
    }
    this.#screen.render();
  }

  // blessed's Log wrapper wrongly resets _userScrolled (getScrollPerc runs
  // with the previous frame's layout and returns 100) — without the flag, every
  // new line pulls the view to the bottom. Recompute with the already-rendered layout.
  #syncScrollState() {
    const visible = this.#chatLog.height - this.#chatLog.iheight;
    const canScroll = this.#chatLog.getScrollHeight() > visible;
    const scrolledUp = canScroll && this.#chatLog.getScrollPerc() < 100;
    this.#chatLog._userScrolled = scrolledUp;

    if (scrolledUp !== this.#scrolledUp) {
      this.#scrolledUp = scrolledUp;
      if (!scrolledUp) {
        this.#unseenCount = 0;
        this.#unseenMentions = 0; // back at the bottom — everything is seen
      }
      this.#refreshScrollIndicator();
    }
    this.#scrolledUp = scrolledUp;
  }

  // Count a fresh arrival while the user is reading history, and pulse the
  // "new messages" pill so they know to page down.
  #noteIncoming(important = false) {
    if (this.#redirecting) {
      return; // inactive buffer — its unread badge lives in the buffer bar
    }
    if (this.#scrolledUp) {
      this.#unseenCount++;
      if (important) {
        this.#unseenMentions++;
      }
      this.#refreshScrollIndicator();
    }
  }

  #refreshScrollIndicator() {
    if (!this.#scrolledUp) {
      this.#stopPill();
      this.removeHeaderIndicator('scroll');
      return;
    }
    if (this.#unseenCount > 0) {
      if (!this.#pillTimer && process.stdout.isTTY) {
        this.#pillTimer = setInterval(() => {
          this.#pillFrame++;
          this.#renderPill();
        }, 450);
        if (this.#pillTimer.unref) {
          this.#pillTimer.unref();
        }
      }
      this.#renderPill();
    } else {
      this.#stopPill();
      this.setHeaderIndicator('scroll', '{yellow-fg}[↑ history — PageDown to return]{/yellow-fg}');
    }
  }

  #renderPill() {
    const n = this.#unseenCount;
    const plural =
      (n === 1 ? 'new message' : 'new messages') +
      (this.#unseenMentions > 0 ? `, ${this.#unseenMentions} @you` : '');
    const bright = this.#pillFrame % 2 === 0;
    const label = bright
      ? `{black-fg}{yellow-bg} ↓ ${n} ${plural} — PageDown {/yellow-bg}{/black-fg}`
      : `{yellow-fg}[↓ ${n} ${plural} — PageDown]{/yellow-fg}`;
    this.setHeaderIndicator('scroll', label);
  }

  #stopPill() {
    if (this.#pillTimer) {
      clearInterval(this.#pillTimer);
      this.#pillTimer = null;
    }
  }

  getLine(lineIndex) {
    if (lineIndex < 0 || lineIndex >= this.#lines.length) {
      return null;
    }
    return this.#lines[lineIndex];
  }

  /**
   * Replace one entry.
   *
   * `spec` is the recipe that produced `newLine`. Callers that hand over a
   * string they built some other way — a burn frame, most of all — pass none,
   * and the entry drops out of the resize rebuild rather than being redrawn
   * mid-animation from a recipe that no longer describes what is on screen.
   */
  updateLine(lineIndex, newLine, spec = null) {
    if (lineIndex < 0 || lineIndex >= this.#lines.length) {
      return;
    }
    if (this.#lines[lineIndex] === null) {
      return;
    }
    this.#lines[lineIndex] = newLine;
    this.#specs[lineIndex] = spec;
    const content = this.#lines.filter((l) => l !== null).join('\n');
    this.#chatLog.setContent(content);
    if (!this.#scrolledUp) {
      this.#chatLog.setScrollPerc(100);
    }
    this.#screen.render();
  }

  removeLine(lineIndex) {
    if (lineIndex < 0 || lineIndex >= this.#lines.length) {
      return;
    }
    this.#lines[lineIndex] = null;
    this.#specs[lineIndex] = null;
    const content = this.#lines.filter((l) => l !== null).join('\n');
    this.#chatLog.setContent(content);
    if (!this.#scrolledUp) {
      this.#chatLog.setScrollPerc(100);
    }
    this.#screen.render();
  }

  // Ephemeral messages don't just vanish — they burn. A flame front sweeps the
  // text left→right (ignite → hot → ember → ash → gone), then the line is
  // removed. Non-TTY falls back to an instant removeLine.
  burnLine(lineIndex, onDone) {
    const orig = this.getLine(lineIndex);
    if (orig === null || orig === undefined) {
      onDone?.();
      return null;
    }

    // Strip blessed tags to get the raw glyphs, keeping each line's indent so
    // the flame stays under the text. A message is several lines now, and the
    // front runs through them in order — the block burns top-left to
    // bottom-right rather than every line igniting at once.
    // The frames are not a layout, so the entry leaves the resize rebuild for
    // as long as it is burning; it is removed at the end either way.
    this.#specs[lineIndex] = null;
    const rows = orig.split('\n').map((row) => {
      const plain = row.replace(/\{[^{}]*\}/g, '');
      const lead = (plain.match(/^ */) || [''])[0];
      return { lead, body: plain.slice(lead.length) };
    });
    const len = rows.reduce((total, row) => total + [...row.body].length, 0);

    if (!process.stdout.isTTY || len === 0) {
      this.removeLine(lineIndex);
      onDone?.();
      return null;
    }

    const TOTAL_FRAMES = 16;
    const advance = Math.max(1, (len + BURN_TAIL) / TOTAL_FRAMES);
    let front = 0;

    const timer = setInterval(() => {
      front += advance;
      let consumed = 0;
      const frame = rows.map((row) => {
        const rendered = row.lead + burnFrame(row.body, front - consumed);
        consumed += [...row.body].length;
        return rendered;
      });
      this.updateLine(lineIndex, frame.join('\n'));
      if (front >= len + BURN_TAIL) {
        clearInterval(timer);
        this.removeLine(lineIndex);
        onDone?.();
      }
    }, 45);
    if (timer.unref) {
      timer.unref();
    }
    return timer;
  }

  clearChat() {
    this.#lines = [];
    this.#specs = [];
    this.#lastSender = null;
    this.#lastStamp = null;
    this.#lastMsgDate = null;
    this.#chatLog.setContent('');
    this.#chatLog.setScroll(0);
    this.#syncScrollState();
    // Force a full repaint so no cells from the old (right-aligned, padded)
    // lines are left as artifacts on the screen.
    this.#screen.realloc();
    this.#screen.render();
  }

  // A single, in-place progress line with a moving shimmer and a live ETA.
  // Successive calls update the same line; a new transfer (percent goes
  // backwards, or after a finish) starts a fresh line.
  updateProgress(text, percent) {
    const pct = Math.max(0, Math.min(100, Math.round(percent)));
    const restart = this.#progIndex === null || pct < this.#progPercent;
    if (restart) {
      this.#lines.push('');
      this.#chatLog.log('');
      this.#progIndex = this.#lines.length - 1;
      this.#progStart = Date.now();
      this.#ensureShimmer();
    }
    this.#progPercent = pct;
    this.#progText = text;
    this.#renderProgress();
    if (pct >= 100) {
      this.#progIndex = null;
      this.#stopShimmer();
    }
  }

  // Guaranteed terminator — call when a transfer ends (complete/reject/error)
  // so the bar settles and the shimmer stops even if 100% was never delivered.
  finishProgress() {
    if (this.#progIndex !== null) {
      this.#progPercent = 100;
      this.#renderProgress();
      this.#progIndex = null;
    }
    this.#stopShimmer();
  }

  #ensureShimmer() {
    if (this.#shimmerTimer || !process.stdout.isTTY) {
      return;
    }
    this.#shimmerTimer = setInterval(() => {
      this.#shimmerPos++;
      this.#renderProgress();
    }, 90);
    if (this.#shimmerTimer.unref) {
      this.#shimmerTimer.unref();
    }
  }

  #stopShimmer() {
    if (this.#shimmerTimer) {
      clearInterval(this.#shimmerTimer);
      this.#shimmerTimer = null;
    }
  }

  #renderProgress() {
    if (this.#progIndex === null) {
      return;
    }
    const pct = this.#progPercent;
    const done = pct >= 100;
    const bar = progressBar(pct, this.#shimmerPos);
    const head = done ? '{green-fg}✓{/green-fg}' : '{#00b8ff-fg}⇅{/#00b8ff-fg}';
    const eta = formatETA(Date.now() - this.#progStart, pct);
    const tail = done
      ? '{green-fg}100% complete{/green-fg}'
      : `{white-fg}${pct}%{/white-fg}${eta ? `  {#888888-fg}${eta}{/#888888-fg}` : ''}`;
    const line = ` {white-fg}[${time()}]{/white-fg} ${head} ${blessed.escape(this.#progText)} [${bar}] ${tail}`;
    this.updateLine(this.#progIndex, line);
  }

  // A brief "secure channel" flourish when a peer's E2E link is established:
  // a spark travels between the two nicks, then a lock snaps shut.
  handshakeConnect(peerNickname) {
    const me = blessed.escape(this.#nickname);
    const peer = blessed.escape(peerNickname);
    const label = (mid) =>
      ` {bold}{#00b8ff-fg}${me}{/#00b8ff-fg}{/bold} ${mid} {bold}{#7b2dff-fg}${peer}{/#7b2dff-fg}{/bold}`;
    const done = ` {green-fg}🔒 Secure channel with {bold}${peer}{/bold} — E2E established{/green-fg}`;

    if (!process.stdout.isTTY) {
      this.#lastSender = null;
      this.#lastStamp = null;
      this.#lines.push(done);
      this.#chatLog.log(done);
      this.#screen.render();
      return;
    }

    this.#lastSender = null;
    this.#lastStamp = null;
    this.#lines.push('');
    const idx = this.#lines.length - 1;
    const W = 11;
    const total = W + 6;
    let f = 0;
    const timer = setInterval(() => {
      let mid;
      if (f < W) {
        let track = '';
        for (let i = 0; i < W; i++) {
          if (i === f) {
            track += '{#ffd000-fg}◆{/#ffd000-fg}';
          } else if (i < f) {
            track += '{#00b8ff-fg}─{/#00b8ff-fg}';
          } else {
            track += '{#333333-fg}─{/#333333-fg}';
          }
        }
        mid = track;
      } else {
        const lock = (f - W) % 2 === 0 ? '{#ffd000-fg}🔓{/#ffd000-fg}' : '{green-fg}🔒{/green-fg}';
        mid = `{#00b8ff-fg}═════{/#00b8ff-fg}${lock}{#00b8ff-fg}═════{/#00b8ff-fg}`;
      }
      this.updateLine(idx, label(mid));
      f++;
      if (f >= total) {
        clearInterval(timer);
        this.updateLine(idx, done);
      }
    }, 60);
    if (timer.unref) {
      timer.unref();
    }
  }

  // The mirror of handshakeConnect: the secure link weakens and the lock opens
  // when a peer leaves.
  handshakeDisconnect(peerNickname) {
    const me = blessed.escape(this.#nickname);
    const peer = blessed.escape(peerNickname);
    const label = (mid) =>
      ` {bold}{#00b8ff-fg}${me}{/#00b8ff-fg}{/bold} ${mid} {bold}{#7b2dff-fg}${peer}{/#7b2dff-fg}{/bold}`;
    const done = ` {#888888-fg}🔓 {bold}${peer}{/bold} left — channel closed{/#888888-fg}`;

    if (!process.stdout.isTTY) {
      this.#lastSender = null;
      this.#lastStamp = null;
      this.#lines.push(done);
      this.#chatLog.log(done);
      this.#screen.render();
      return;
    }

    this.#lastSender = null;
    this.#lastStamp = null;
    this.#lines.push('');
    const idx = this.#lines.length - 1;
    const W = 11;
    const mid_i = Math.floor(W / 2);
    const total = W + 6;
    let f = 0;
    const timer = setInterval(() => {
      let mid;
      if (f < W) {
        // The link dims from both ends inward; the lock stays shut for now.
        let track = '';
        for (let i = 0; i < W; i++) {
          if (i === mid_i) {
            track += '{green-fg}🔒{/green-fg}';
          } else {
            const distFromEnd = Math.min(i, W - 1 - i);
            track +=
              distFromEnd < f / 2 ? '{#333333-fg}·{/#333333-fg}' : '{#00b8ff-fg}─{/#00b8ff-fg}';
          }
        }
        mid = track;
      } else {
        // The lock clicks open.
        const lock =
          (f - W) % 2 === 0 ? '{#ffd000-fg}🔓{/#ffd000-fg}' : '{#888888-fg}🔓{/#888888-fg}';
        mid = `{#333333-fg}·····{/#333333-fg}${lock}{#333333-fg}·····{/#333333-fg}`;
      }
      this.updateLine(idx, label(mid));
      f++;
      if (f >= total) {
        clearInterval(timer);
        this.updateLine(idx, done);
      }
    }, 60);
    if (timer.unref) {
      timer.unref();
    }
  }

  // ── Sound notifications ───────────────────────────────
  get soundEnabled() {
    return this.#soundEnabled;
  }

  setSoundEnabled(enabled) {
    this.#soundEnabled = enabled;
  }

  get notifyEnabled() {
    return this.#notifyEnabled;
  }

  setNotifyEnabled(enabled) {
    this.#notifyEnabled = enabled;
  }

  playNotification() {
    if (this.#soundEnabled) {
      process.stdout.write('\x07');
    }
  }

  destroy() {
    if (this.#typingAnimInterval) {
      clearInterval(this.#typingAnimInterval);
    }
    if (this.#connSpinner) {
      clearInterval(this.#connSpinner);
    }
    if (this.#reconnectFlashTimer) {
      clearInterval(this.#reconnectFlashTimer);
    }
    if (this.#resizeTimer) {
      clearTimeout(this.#resizeTimer);
    }
    this.#stopShimmer();
    this.#stopPill();
    if (this.#keyInput) {
      try {
        this.#screen.program.write(KEY_PROTOCOL_DISABLE);
      } catch {
        /* the terminal may already be gone */
      }
      this.#keyInput.detach();
    }
    this.#screen.destroy();
  }
}
