import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import sodium from 'sodium-native';

const STATE_DIR = 'state';
const STATE_FILE = 'session-state.enc.json';

export class StateManager {
  #stateDir;
  #statePath;

  constructor(baseDir = '.ciphermesh') {
    this.#stateDir = join(baseDir, STATE_DIR);
    if (!existsSync(this.#stateDir)) {
      mkdirSync(this.#stateDir, { recursive: true });
    }
    this.#statePath = join(this.#stateDir, STATE_FILE);
  }

  /**
   * Derive a 32-byte KEK from a passphrase using Argon2id.
   * @param {string} passphrase
   * @param {Buffer} [salt] - 16 bytes. If omitted, generates a new one.
   * @returns {{ kek: Buffer, salt: Buffer }}
   */
  deriveKEK(passphrase, salt) {
    if (!salt) {
      salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
      sodium.randombytes_buf(salt);
    }
    const kek = sodium.sodium_malloc(32);
    sodium.crypto_pwhash(
      kek,
      Buffer.from(passphrase, 'utf-8'),
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    return { kek, salt };
  }

  /**
   * Encrypt and save state to disk.
   * @param {object} data - Plain object to serialize
   * @param {Buffer} kek - 32-byte key encryption key
   * @param {Buffer} salt - Salt used to derive KEK (stored alongside)
   */
  saveState(data, kek, salt) {
    const plaintext = Buffer.from(JSON.stringify(data), 'utf-8');
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
    sodium.randombytes_buf(nonce);

    const ciphertext = Buffer.alloc(plaintext.length + sodium.crypto_secretbox_MACBYTES);
    sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, kek);
    sodium.sodium_memzero(plaintext);

    const envelope = {
      salt: salt.toString('base64'),
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    writeFileSync(this.#statePath, JSON.stringify(envelope), 'utf-8');
  }

  /**
   * Load and decrypt state from disk.
   * @param {string} passphrase - Used to re-derive the KEK
   * @returns {object|null} Parsed state or null if file missing/corrupt/wrong passphrase
   */
  loadState(passphrase) {
    if (!existsSync(this.#statePath)) {
      return null;
    }

    try {
      const envelope = JSON.parse(readFileSync(this.#statePath, 'utf-8'));
      const salt = Buffer.from(envelope.salt, 'base64');
      const nonce = Buffer.from(envelope.nonce, 'base64');
      const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

      const { kek } = this.deriveKEK(passphrase, salt);
      const plaintext = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
      const valid = sodium.crypto_secretbox_open_easy(plaintext, ciphertext, nonce, kek);
      sodium.sodium_memzero(kek);

      if (!valid) {
        sodium.sodium_memzero(plaintext);
        return null;
      }

      const data = JSON.parse(plaintext.toString('utf-8'));
      sodium.sodium_memzero(plaintext);
      return data;
    } catch {
      return null;
    }
  }

  hasState() {
    return existsSync(this.#statePath);
  }

  clearState() {
    if (existsSync(this.#statePath)) {
      writeFileSync(this.#statePath, Buffer.alloc(256));
      unlinkSync(this.#statePath);
    }
  }
}
