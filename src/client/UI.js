import blessed from 'blessed';
import { EventEmitter } from 'node:events';
import { shortcodeSuggestions } from '../shared/emoji.js';
import { nickPalette } from '../shared/themes.js';
import { fuzzyFilter } from '../shared/fuzzy.js';
import { EMOJI_MAP } from '../shared/constants.js';

const EMOJI_ENTRIES = Object.entries(EMOJI_MAP); // [':name:', '😀']

const NICK_AVATARS = ['😀', '😎', '🤠', '🤖', '👻', '👽', '🦊', '🐼', '🐸', '🦁', '🐙', '🐧'];
const TYPING_DOTS = ['', '.', '..', '...'];
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const INPUT_MAX_LINES = 8; // input box grows up to this many text lines

// Command → one-line description for the Ctrl+K fuzzy command palette.
const COMMAND_INFO = [
  ['/help', 'Show help'],
  ['/users', 'List online users'],
  ['/msg', 'Private message (DM)'],
  ['/reply', 'Reply to the last message'],
  ['/away', 'Mark yourself as away'],
  ['/back', 'Clear away status'],
  ['/status', 'Set a status'],
  ['/join', 'Join a room'],
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
  ['/search', 'Search history'],
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
  '/away',
  '/back',
  '/autoaway',
  '/status',
  '/notify',
  '/dnd',
  '/join',
  '/rooms',
  '/room',
  '/invite',
  '/search',
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
  #peerNames;
  #tabState;
  #lines;
  #headerIndicators;
  #scrolledUp;
  #connState;
  #lastMsgDate;
  #lastSender;
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
  #pillTimer;
  #pillFrame;
  #palette;
  #paletteOpen;
  #paletteQuery;
  #emojiPicker;
  #emojiOpen;
  #emojiQuery;

  constructor(nickname) {
    super();
    this.#nickname = nickname;
    this.#onlineCount = 1;
    this.#connState = 'online';
    this.#lastMsgDate = null;
    this.#lastSender = null;
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
    this.#pillTimer = null;
    this.#pillFrame = 0;
    this.#paletteOpen = false;
    this.#paletteQuery = '';
    this.#emojiOpen = false;
    this.#emojiQuery = '';

    // blessed's terminfo parser can't compile the modern Setulc (underline
    // colour) capability that terminals like ghostty ship, so it dumps a
    // compile error when it resets the terminal on exit (e.g. Ctrl+C). Those
    // terminals are xterm-256color-compatible for everything we render — images
    // use their own escape sequences, not blessed — so pin tput to xterm-256color
    // and sidestep the broken capability.
    const term = process.env.TERM || '';
    this.#screen = blessed.screen({
      smartCSR: true,
      fullUnicode: true, // renders emojis and characters outside the BMP
      title: 'CipherMesh',
      terminal: /ghostty/i.test(term) ? 'xterm-256color' : undefined,
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

      // Shift+Enter arrives as a distinct sequence only under the kitty keyboard
      // protocol (\x1b[13;2u) or xterm modifyOtherKeys (\x1b[27;2;13~). When the
      // terminal sends it, insert a newline instead of submitting.
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

      if (this.#paletteOpen) {
        this.#handlePaletteKey(ch, key);
        return;
      }

      if (this.#emojiOpen) {
        this.#handleEmojiKey(ch, key);
        return;
      }

      this.#handleKey(ch, key);
    });

    // Ask the terminal to bracket pasted text with \x1b[200~ … \x1b[201~.
    try {
      this.#screen.program.write('\x1b[?2004h');
      process.on('exit', () => {
        try {
          process.stdout.write('\x1b[?2004l');
        } catch {
          /* ignore */
        }
      });
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

    // Tab — autocomplete
    if (name === 'tab') {
      this.#handleTab();
      return;
    }

    // Any non-tab key resets tab cycling
    this.#tabState = { suggestions: [], index: -1, original: '' };

    // Alt+Enter / Ctrl+J — insert a newline (reliable across terminals, unlike
    // bare Shift+Enter which most terminals don't distinguish from Enter).
    if (((name === 'return' || name === 'enter') && key.meta) || (key.ctrl && name === 'j')) {
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
    // Strip any stray paste markers and control chars (a message is one line).
    // eslint-disable-next-line no-control-regex
    const clean = raw.replace(/\x1b\[20[01]~/g, '').replace(/[\x00-\x1f\x7f]/g, '');
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
    const room = `{cyan-fg}#${this.#statusRoom}{/cyan-fg}`;
    const fp = this.#statusFingerprint
      ? `   {#8888aa-fg}🔑 ${this.#statusFingerprint}{/#8888aa-fg}`
      : '';
    const hint =
      '{#7777aa-fg}Tab · Ctrl+K commands · Ctrl+E emoji · PgUp/PgDn scroll · /help · Ctrl+C quit{/#7777aa-fg}';
    return `  ${room}${fp}      {|}  ${hint}  `;
  }

  #updateStatusBar() {
    if (this.#statusBar) {
      this.#statusBar.setContent(this.#statusContent());
      this.#screen.render();
    }
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
  ) {
    this.#daySeparator();

    const color = nickColor(nickname);
    const isSelf = nickname === this.#nickname || nickname.includes('\u2192');
    const tag = isSelf ? 'bold' : `${color}-fg`;
    const avatar = nickAvatar(isSelf ? this.#nickname : nickname);
    const dmLabel = isDM ? ' {magenta-fg}(DM){/magenta-fg}' : '';
    const ephLabel = ephemeralLabel ? ` {yellow-fg}[${ephemeralLabel}]{/yellow-fg}` : '';
    const denLabel = deniable ? ' {magenta-fg}[D]{/magenta-fg}' : '';
    const mentionMark = mentioned && !isSelf ? '{yellow-fg}\ud83d\udd14 {/yellow-fg}' : '';

    // Consecutive messages from the same peer collapse the avatar/name into a
    // compact continuation bullet (cleaner layout).
    const grouped = !isSelf && !isDM && this.#lastSender === nickname;
    const core = grouped
      ? `{${tag}}\u00b7{/${tag}} ${renderMarkdown(text)}`
      : `${avatar} {${tag}}${nickname}{/${tag}}${dmLabel}: ${renderMarkdown(text)}`;

    // My own messages on the right (timestamp at the end), others on the left
    const line = isSelf
      ? this.#alignRight(`${core}${ephLabel}${denLabel} {white-fg}[${time()}]{/white-fg}`)
      : ` {white-fg}[${time()}]{/white-fg}${ephLabel}${denLabel} ${mentionMark}${core}`;

    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
    this.#lastSender = isSelf ? ' self' : nickname;
    if (!isSelf) {
      this.#noteIncoming();
    }
    return { lineIndex: this.#lines.length - 1 };
  }

  #daySeparator() {
    const today = new Date().toLocaleDateString('en-US');
    if (this.#lastMsgDate === today) {
      return;
    }
    this.#lastMsgDate = today;
    this.#lastSender = null;
    const sep = ` {#666666-fg}\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500  ${today}  \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500{/#666666-fg}`;
    this.#lines.push(sep);
    this.#chatLog.log(sep);
  }

  // Visible width of a string with blessed tags (emoji ~2 columns)
  #visibleWidth(tagged) {
    const plain = tagged.replace(/\{[^{}]*\}/g, '');
    let width = 0;
    for (const chr of plain) {
      const cp = chr.codePointAt(0);
      width += cp > 0xffff || (cp >= 0x2600 && cp <= 0x27bf) ? 2 : 1;
    }
    return width;
  }

  #alignRight(tagged) {
    const avail = (this.#chatLog.width || 0) - this.#chatLog.iwidth - 2;
    const visible = this.#visibleWidth(tagged);
    if (avail <= visible) {
      return ` ${tagged}`; // doesn't fit on one line \u2014 falls back to normal flow with wrap
    }
    return ' '.repeat(avail - visible) + tagged;
  }

  // Appends a badge (e.g. \u2713\u2713) preserving right alignment:
  // shifts the padding instead of overflowing the width
  appendBadge(lineIndex, baseLine, badgeTagged) {
    const badgeWidth = this.#visibleWidth(badgeTagged) + 1;
    const leading = baseLine.match(/^ +/);
    const line =
      leading && leading[0].length > badgeWidth
        ? `${baseLine.slice(badgeWidth)} ${badgeTagged}`
        : `${baseLine} ${badgeTagged}`;
    this.updateLine(lineIndex, line);
  }

  addSystemMessage(text) {
    this.#lastSender = null; // interrupts message grouping
    const line = ` {white-fg}[${time()}] * ${blessed.escape(text)}{/white-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
    this.#noteIncoming();
  }

  addErrorMessage(text) {
    this.#lastSender = null;
    const line = ` {red-fg}[${time()}] ! ${blessed.escape(text)}{/red-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
    this.#noteIncoming();
  }

  addInfoMessage(text) {
    this.#lastSender = null;
    const line = ` {cyan-fg}[${time()}] ${blessed.escape(text)}{/cyan-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addQuoteLine(nickname, excerpt, alignRight = false) {
    const quoted = `{#888888-fg}↩ ${blessed.escape(nickname)}: "${blessed.escape(excerpt)}"{/#888888-fg}`;
    const line = alignRight ? this.#alignRight(quoted) : `   ${quoted}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addPlainLines(rawLines) {
    for (const raw of rawLines) {
      const line = ` ${blessed.escape(raw)}`;
      this.#lines.push(line);
      this.#chatLog.log(line);
    }
    this.#screen.render();
  }

  // Lines already carry blessed color tags — do not escape
  addImagePreview(taggedLines) {
    for (const raw of taggedLines) {
      const line = ` ${raw}`;
      this.#lines.push(line);
      this.#chatLog.log(line);
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
        this.#unseenCount = 0; // back at the bottom — everything is seen
      }
      this.#refreshScrollIndicator();
    }
    this.#scrolledUp = scrolledUp;
  }

  // Count a fresh arrival while the user is reading history, and pulse the
  // "new messages" pill so they know to page down.
  #noteIncoming() {
    if (this.#scrolledUp) {
      this.#unseenCount++;
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
    const plural = n === 1 ? 'new message' : 'new messages';
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

  updateLine(lineIndex, newLine) {
    if (lineIndex < 0 || lineIndex >= this.#lines.length) {
      return;
    }
    if (this.#lines[lineIndex] === null) {
      return;
    }
    this.#lines[lineIndex] = newLine;
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

    // Strip blessed tags to get the raw glyphs, preserving leading padding
    // (right-aligned self messages) so the flame stays under the text.
    const plain = orig.replace(/\{[^{}]*\}/g, '');
    const lead = (plain.match(/^ */) || [''])[0];
    const body = [...plain.slice(lead.length)];
    const len = body.length;

    const bodyStr = plain.slice(lead.length);
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
      this.updateLine(lineIndex, lead + burnFrame(bodyStr, front));
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
    this.#lastSender = null;
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
      this.#lines.push(done);
      this.#chatLog.log(done);
      this.#screen.render();
      return;
    }

    this.#lastSender = null;
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
      this.#lines.push(done);
      this.#chatLog.log(done);
      this.#screen.render();
      return;
    }

    this.#lastSender = null;
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
    this.#stopShimmer();
    this.#stopPill();
    this.#screen.destroy();
  }
}
