import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import sodium from 'sodium-native';
import { deriveKEK } from './StateManager.js';

const HISTORY_DIR = 'history';
const HISTORY_FILE = 'history.enc.json';
const MAX_ENTRIES = 5000;
const FLUSH_DELAY_MS = 3000;

/**
 * Opt-in encrypted local message history.
 * Whole file is an envelope { salt, nonce, ciphertext } — same scheme as
 * StateManager (Argon2id KEK + XSalsa20-Poly1305). Only active when the
 * user provides a passphrase at startup.
 */
export class HistoryStore {
  #path;
  #kek;
  #salt;
  #entries;
  #flushTimer;
  #open;

  constructor(baseDir = '.ciphermesh') {
    const dir = join(baseDir, HISTORY_DIR);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    this.#path = join(dir, HISTORY_FILE);
    this.#kek = null;
    this.#salt = null;
    this.#entries = [];
    this.#flushTimer = null;
    this.#open = false;
  }

  /**
   * Derive the KEK and decrypt existing history (if any).
   * @returns {boolean} false when the passphrase does not match the file
   */
  open(passphrase) {
    if (!existsSync(this.#path)) {
      const derived = deriveKEK(passphrase);
      this.#kek = derived.kek;
      this.#salt = derived.salt;
      this.#open = true;
      return true;
    }

    try {
      const envelope = JSON.parse(readFileSync(this.#path, 'utf-8'));
      const salt = Buffer.from(envelope.salt, 'base64');
      const nonce = Buffer.from(envelope.nonce, 'base64');
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

      const { kek } = deriveKEK(passphrase, salt);
      const plaintext = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
      const valid = sodium.crypto_secretbox_open_easy(plaintext, ciphertext, nonce, kek);
      if (!valid) {
        sodium.sodium_memzero(kek);
        sodium.sodium_memzero(plaintext);
        return false;
      }

      this.#entries = JSON.parse(plaintext.toString('utf-8'));
      sodium.sodium_memzero(plaintext);
      this.#kek = kek;
      this.#salt = salt;
      this.#open = true;
      return true;
    } catch {
      return false;
    }
  }

  get isOpen() {
    return this.#open;
  }

  get size() {
    return this.#entries.length;
  }

  append({ room, nickname, text, isDM = false }) {
    if (!this.#open) {
      return;
    }
    this.#entries.push({ ts: Date.now(), room, nickname, text, isDM });
    if (this.#entries.length > MAX_ENTRIES) {
      this.#entries.splice(0, this.#entries.length - MAX_ENTRIES);
    }
    this.#scheduleFlush();
  }

  search(term, limit = 50) {
    if (!this.#open || !term) {
      return [];
    }
    const needle = term.toLowerCase();
    const found = this.#entries.filter(
      (e) => e.text.toLowerCase().includes(needle) || e.nickname.toLowerCase().includes(needle),
    );
    return found.slice(-limit);
  }

  recent(count = 20) {
    if (!this.#open) {
      return [];
    }
    return this.#entries.slice(-count);
  }

  /**
   * Export history as PLAINTEXT — .json when the path ends with .json,
   * otherwise a human-readable .txt.
   * @returns {number} entries written
   */
  exportTo(filePath) {
    if (!this.#open) {
      return 0;
    }
    let out;
    if (filePath.toLowerCase().endsWith('.json')) {
      out = JSON.stringify(this.#entries, null, 2);
    } else {
      out =
        this.#entries
          .map((e) => {
            const when = new Date(e.ts).toLocaleString('pt-BR', {
              day: '2-digit',
              month: '2-digit',
              year: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            });
            const dm = e.isDM ? ' (DM)' : '';
            return `[${when}] [#${e.room}]${dm} ${e.nickname}: ${e.text}`;
          })
          .join('\n') + '\n';
    }
    writeFileSync(filePath, out, 'utf-8');
    return this.#entries.length;
  }

  #scheduleFlush() {
    if (this.#flushTimer) {
      return;
    }
    this.#flushTimer = setTimeout(() => {
      this.#flushTimer = null;
      this.flush();
    }, FLUSH_DELAY_MS);
  }

  flush() {
    if (!this.#open) {
      return;
    }
    const plaintext = Buffer.from(JSON.stringify(this.#entries), 'utf-8');
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
    sodium.randombytes_buf(nonce);
    const ciphertext = Buffer.alloc(plaintext.length + sodium.crypto_secretbox_MACBYTES);
    sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, this.#kek);
    sodium.sodium_memzero(plaintext);

    const envelope = {
      salt: this.#salt.toString('base64'),
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    writeFileSync(this.#path, JSON.stringify(envelope), 'utf-8');
  }

  destroy() {
    if (this.#flushTimer) {
      clearTimeout(this.#flushTimer);
      this.#flushTimer = null;
    }
    if (this.#open) {
      this.flush();
      sodium.sodium_memzero(this.#kek);
      this.#kek = null;
      this.#open = false;
    }
  }
}
