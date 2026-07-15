import blessed from 'blessed';
import { EventEmitter } from 'node:events';
import { shortcodeSuggestions } from '../shared/emoji.js';

const NICK_COLORS = ['cyan', 'green', 'magenta', 'yellow', 'red'];
const NICK_AVATARS = ['😀', '😎', '🤠', '🤖', '👻', '👽', '🦊', '🐼', '🐸', '🦁', '🐙', '🐧'];
const TYPING_DOTS = ['', '.', '..', '...'];

export const COMMANDS = [
  '/help',
  '/users',
  '/fingerprint',
  '/verify',
  '/verify-confirm',
  '/trust',
  '/trustlist',
  '/clear',
  '/file',
  '/sound',
  '/msg',
  '/reply',
  '/away',
  '/back',
  '/status',
  '/notify',
  '/join',
  '/rooms',
  '/room',
  '/invite',
  '/search',
  '/history',
  '/export',
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
  return NICK_COLORS[nickHash(nickname) % NICK_COLORS.length];
}

// Avatar deterministico por nick — emoji nao aceita tint de cor no
// terminal, entao a identidade visual vem da variedade do proprio emoji
function nickAvatar(nickname) {
  return NICK_AVATARS[nickHash(nickname) % NICK_AVATARS.length];
}

function time() {
  return new Date().toLocaleTimeString('pt-BR', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  });
}

function renderMarkdown(text) {
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
    result += `{${span.tag}}${blessed.escape(span.inner)}{/${span.tag}}`;
    pos = span.end;
  }
  if (pos < text.length) {
    result += blessed.escape(text.slice(pos));
  }

  return result;
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

  constructor(nickname) {
    super();
    this.#nickname = nickname;
    this.#onlineCount = 1;
    this.#connState = 'online';
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

    this.#screen = blessed.screen({
      smartCSR: true,
      fullUnicode: true, // renderiza emojis e caracteres fora do BMP
      title: 'CipherMesh',
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
      bottom: 3,
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

      // Same raw sequence within 25ms = duplicate from blessed
      if (seq === this.#lastKeyEvent.seq && now - this.#lastKeyEvent.time < 25) {
        return;
      }
      this.#lastKeyEvent = { seq, time: now };

      this.#handleKey(ch, key);
    });

    this.#screen.render();
  }

  #handleKey(ch, key) {
    const name = key.name || '';

    // Ctrl+C — quit
    if (key.ctrl && name === 'c') {
      this.emit('quit');
      return;
    }

    // Tab — autocomplete
    if (name === 'tab') {
      this.#handleTab();
      return;
    }

    // Any non-tab key resets tab cycling
    this.#tabState = { suggestions: [], index: -1, original: '' };

    // Enter — submit
    if (name === 'return' || name === 'enter') {
      const text = this.#inputValue.trim();
      if (text) {
        this.emit('input', text);
      }
      this.#inputValue = '';
      this.#cursorPos = 0;
      this.#renderInput();
      return;
    }

    // Backspace — apaga um code point inteiro (emojis sao pares surrogate)
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

    // Regular character — length 2 = par surrogate (emoji entregue inteiro
    // em alguns terminais; em outros chega como duas metades de length 1)
    const firstCode = ch ? ch.charCodeAt(0) : 0;
    if (ch && ch.length <= 2 && !key.ctrl && !key.meta && firstCode > 0x1f && firstCode !== 0x7f) {
      this.#inputValue =
        this.#inputValue.slice(0, this.#cursorPos) + ch + this.#inputValue.slice(this.#cursorPos);
      this.#cursorPos += ch.length;
      this.emit('activity');
      this.#renderInput();
    }
  }

  // Limites de code point — par surrogate anda inteiro
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
    const end = this.#nextCharBoundary(this.#cursorPos);
    const before = blessed.escape(this.#inputValue.slice(0, this.#cursorPos));
    const cursorChar = this.#inputValue.slice(this.#cursorPos, end) || ' ';
    const after = blessed.escape(this.#inputValue.slice(end));
    this.#inputBox.setContent(` ${before}{inverse}${blessed.escape(cursorChar)}{/inverse}${after}`);
    this.#screen.render();
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
    // Shortcode de emoji: ultimo token comecando com ':' (funciona em
    // qualquer posicao, inclusive dentro de comandos como /status)
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
    this.#inputBox.setLabel(` {yellow-fg}${names} digitando${dots}{/yellow-fg} `);
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
    const dotColor =
      this.#connState === 'online'
        ? 'green'
        : this.#connState === 'reconnecting'
          ? 'yellow'
          : 'red';
    const dot = `{${dotColor}-fg}\u25cf{/${dotColor}-fg}`;
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
    this.#connState = state;
    this.#updateHeader();
  }

  addMessage(
    nickname,
    text,
    isDM = false,
    ephemeralLabel = null,
    deniable = false,
    mentioned = false,
  ) {
    const color = nickColor(nickname);
    const isSelf = nickname === this.#nickname || nickname.includes('\u2192');
    const tag = isSelf ? 'bold' : `${color}-fg`;
    const avatar = nickAvatar(isSelf ? this.#nickname : nickname);
    const dmLabel = isDM ? ' {magenta-fg}(DM){/magenta-fg}' : '';
    const ephLabel = ephemeralLabel ? ` {yellow-fg}[${ephemeralLabel}]{/yellow-fg}` : '';
    const denLabel = deniable ? ' {magenta-fg}[D]{/magenta-fg}' : '';
    const mentionMark = mentioned && !isSelf ? '{yellow-fg}\ud83d\udd14 {/yellow-fg}' : '';
    const core = `${avatar} {${tag}}${nickname}{/${tag}}${dmLabel}: ${renderMarkdown(text)}`;

    // Minhas mensagens a direita (horario no fim), dos outros a esquerda
    const line = isSelf
      ? this.#alignRight(`${core}${ephLabel}${denLabel} {white-fg}[${time()}]{/white-fg}`)
      : ` {white-fg}[${time()}]{/white-fg}${ephLabel}${denLabel} ${mentionMark}${core}`;

    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
    return { lineIndex: this.#lines.length - 1 };
  }

  // Largura visivel de uma string com tags do blessed (emoji ~2 colunas)
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
      return ` ${tagged}`; // nao cabe numa linha \u2014 cai pro fluxo normal com wrap
    }
    return ' '.repeat(avail - visible) + tagged;
  }

  // Anexa um badge (ex: \u2713\u2713) preservando o alinhamento a direita:
  // desloca o padding em vez de estourar a largura
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
    const line = ` {white-fg}[${time()}] * ${blessed.escape(text)}{/white-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addErrorMessage(text) {
    const line = ` {red-fg}[${time()}] ! ${blessed.escape(text)}{/red-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addInfoMessage(text) {
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

  // blessed's Log wrapper zera _userScrolled indevidamente (getScrollPerc
  // roda com o layout do frame anterior e retorna 100) — sem a flag, cada
  // linha nova puxa a view pro fundo. Recalcula com o layout ja renderizado.
  #syncScrollState() {
    const visible = this.#chatLog.height - this.#chatLog.iheight;
    const canScroll = this.#chatLog.getScrollHeight() > visible;
    const scrolledUp = canScroll && this.#chatLog.getScrollPerc() < 100;
    this.#chatLog._userScrolled = scrolledUp;

    if (scrolledUp !== this.#scrolledUp) {
      if (scrolledUp) {
        this.setHeaderIndicator('scroll', '{yellow-fg}[↑ historico — PageDown volta]{/yellow-fg}');
      } else {
        this.removeHeaderIndicator('scroll');
      }
    }
    this.#scrolledUp = scrolledUp;
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

  clearChat() {
    this.#lines = [];
    this.#chatLog.setContent('');
    this.#syncScrollState();
    this.#screen.render();
  }

  updateProgress(text, percent) {
    const width = 20;
    const filled = Math.round((percent / 100) * width);
    const bar =
      '='.repeat(filled) +
      (filled < width ? '>' : '') +
      ' '.repeat(Math.max(0, width - filled - 1));
    const line = ` {yellow-fg}[${time()}] ${text} [${bar}] ${percent}%{/yellow-fg}`;
    this.#lines.push(line);
    this.#chatLog.log(line);
    this.#screen.render();
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
    this.#screen.destroy();
  }
}
