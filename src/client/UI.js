import blessed from 'blessed';
import { EventEmitter } from 'node:events';

const NICK_COLORS = ['cyan', 'green', 'magenta', 'yellow', 'red'];

function nickColor(nickname) {
  let hash = 0;
  for (let i = 0; i < nickname.length; i++) {
    hash = ((hash << 5) - hash + nickname.charCodeAt(i)) | 0;
  }
  return NICK_COLORS[Math.abs(hash) % NICK_COLORS.length];
}

function time() {
  return new Date().toLocaleTimeString('pt-BR', { hour12: false, hour: '2-digit', minute: '2-digit' });
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

  constructor(nickname) {
    super();
    this.#nickname = nickname;
    this.#onlineCount = 1;
    this.#inputValue = '';
    this.#cursorPos = 0;
    this.#lastKeyEvent = { seq: '', time: 0 };

    this.#screen = blessed.screen({
      smartCSR: true,
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
      mouse: true,
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

      // Same raw sequence within 25ms = duplicate from blessed
      if (seq === this.#lastKeyEvent.seq && (now - this.#lastKeyEvent.time) < 25) {
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

    // Backspace
    if (name === 'backspace') {
      if (this.#cursorPos > 0) {
        this.#inputValue =
          this.#inputValue.slice(0, this.#cursorPos - 1) +
          this.#inputValue.slice(this.#cursorPos);
        this.#cursorPos--;
      }
      this.#renderInput();
      return;
    }

    // Delete
    if (name === 'delete') {
      if (this.#cursorPos < this.#inputValue.length) {
        this.#inputValue =
          this.#inputValue.slice(0, this.#cursorPos) +
          this.#inputValue.slice(this.#cursorPos + 1);
      }
      this.#renderInput();
      return;
    }

    // Arrow left
    if (name === 'left') {
      if (this.#cursorPos > 0) {
        this.#cursorPos--;
      }
      this.#renderInput();
      return;
    }

    // Arrow right
    if (name === 'right') {
      if (this.#cursorPos < this.#inputValue.length) {
        this.#cursorPos++;
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
    if (name === 'pageup') {
      this.#chatLog.scroll(-this.#chatLog.height);
      this.#screen.render();
      return;
    }
    if (name === 'pagedown') {
      this.#chatLog.scroll(this.#chatLog.height);
      this.#screen.render();
      return;
    }

    // Regular character
    if (ch && ch.length === 1 && !key.ctrl && !key.meta) {
      this.#inputValue =
        this.#inputValue.slice(0, this.#cursorPos) +
        ch +
        this.#inputValue.slice(this.#cursorPos);
      this.#cursorPos++;
      this.#renderInput();
    }
  }

  #renderInput() {
    const before = blessed.escape(this.#inputValue.slice(0, this.#cursorPos));
    const cursorChar = this.#inputValue[this.#cursorPos] || ' ';
    const after = blessed.escape(this.#inputValue.slice(this.#cursorPos + 1));
    this.#inputBox.setContent(` ${before}{inverse}${blessed.escape(cursorChar)}{/inverse}${after}`);
    this.#screen.render();
  }

  #headerContent() {
    const dot = '{green-fg}●{/green-fg}';
    return `  ${dot} {bold}CipherMesh{/bold}  {white-fg}│{/white-fg}  {bold}${this.#nickname}{/bold}      {|}  ${dot} ${this.#onlineCount} online  {white-fg}│{/white-fg}  {green-fg}E2E{/green-fg}  `;
  }

  #updateHeader() {
    this.#header.setContent(this.#headerContent());
    this.#screen.render();
  }

  setOnlineCount(count) {
    this.#onlineCount = count;
    this.#updateHeader();
  }

  addMessage(nickname, text) {
    const color = nickColor(nickname);
    const isSelf = nickname === this.#nickname;
    const tag = isSelf ? 'bold' : `${color}-fg`;
    const line = ` {white-fg}[${time()}]{/white-fg} {${tag}}${nickname}{/${tag}}: ${blessed.escape(text)}`;
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addSystemMessage(text) {
    const line = ` {white-fg}[${time()}] * ${blessed.escape(text)}{/white-fg}`;
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addErrorMessage(text) {
    const line = ` {red-fg}[${time()}] ! ${blessed.escape(text)}{/red-fg}`;
    this.#chatLog.log(line);
    this.#screen.render();
  }

  addInfoMessage(text) {
    const line = ` {cyan-fg}[${time()}] ${blessed.escape(text)}{/cyan-fg}`;
    this.#chatLog.log(line);
    this.#screen.render();
  }

  clearChat() {
    this.#chatLog.setContent('');
    this.#screen.render();
  }

  destroy() {
    this.#screen.destroy();
  }
}
