import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import sodium from 'sodium-native';

const STATE_DIR = 'state';
const STATE_FILE = 'session-state.enc.json';

// Argon2id parameters. MODERATE is the current default for long-term key
// material at rest; INTERACTIVE is the legacy default used to open files
// written before the upgrade (their params are read from the envelope).
export const KDF_DEFAULT = {
  opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
  memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
};
export const KDF_LEGACY = {
  opslimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
  memlimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
};

/**
 * Derive a 32-byte KEK from a passphrase using Argon2id.
 * @param {string} passphrase
 * @param {Buffer} [salt] - 16 bytes. If omitted, generates a new one.
 * @param {number} [opslimit] - Argon2id ops limit (defaults to MODERATE).
 * @param {number} [memlimit] - Argon2id mem limit (defaults to MODERATE).
 * @returns {{ kek: Buffer, salt: Buffer, opslimit: number, memlimit: number }}
 */
export function deriveKEK(
  passphrase,
  salt,
  opslimit = KDF_DEFAULT.opslimit,
  memlimit = KDF_DEFAULT.memlimit,
) {
  if (!salt) {
    salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
    sodium.randombytes_buf(salt);
  }
  const kek = sodium.sodium_malloc(32);
  sodium.crypto_pwhash(
    kek,
    Buffer.from(passphrase, 'utf-8'),
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  return { kek, salt, opslimit, memlimit };
}

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

  deriveKEK(passphrase, salt) {
    return deriveKEK(passphrase, salt);
  }

  /**
   * Encrypt and save state to disk.
   * @param {object} data - Plain object to serialize
   * @param {Buffer} kek - 32-byte key encryption key
   * @param {Buffer} salt - Salt used to derive KEK (stored alongside)
   */
  saveState(data, kek, salt, opslimit = KDF_DEFAULT.opslimit, memlimit = KDF_DEFAULT.memlimit) {
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
      opslimit,
      memlimit,
    };
    writeFileSync(this.#statePath, JSON.stringify(envelope), { encoding: 'utf-8', mode: 0o600 });
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

      // Legacy files have no stored params → they were written with INTERACTIVE.
      const opslimit = envelope.opslimit ?? KDF_LEGACY.opslimit;
      const memlimit = envelope.memlimit ?? KDF_LEGACY.memlimit;
      const { kek } = this.deriveKEK(passphrase, salt, opslimit, memlimit);
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
