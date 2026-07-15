import sodium from 'sodium-native';
import { deriveKEK, KDF_LEGACY } from './StateManager.js';

const BACKUP_VERSION = 1;

/**
 * Encrypt an identity+trust backup with a passphrase (Argon2id KEK +
 * XSalsa20-Poly1305), returning a self-describing JSON envelope string.
 * The envelope stores the KDF params so it is portable and future-proof.
 *
 * @param {object} data - e.g. { identity, trust }
 * @param {string} passphrase
 * @returns {string} JSON envelope
 */
export function exportBackup(data, passphrase) {
  const { kek, salt, opslimit, memlimit } = deriveKEK(passphrase);
  const plaintext = Buffer.from(JSON.stringify({ version: BACKUP_VERSION, ...data }), 'utf-8');
  const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
  sodium.randombytes_buf(nonce);

  const ciphertext = Buffer.alloc(plaintext.length + sodium.crypto_secretbox_MACBYTES);
  sodium.crypto_secretbox_easy(ciphertext, plaintext, nonce, kek);
  sodium.sodium_memzero(plaintext);
  sodium.sodium_memzero(kek);

  return JSON.stringify({
    kind: 'ciphermesh-backup',
    salt: salt.toString('base64'),
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    opslimit,
    memlimit,
  });
}

/**
 * Decrypt a backup envelope. Returns the data object or null on wrong
 * passphrase / corruption.
 * @param {string} raw - the JSON envelope
 * @param {string} passphrase
 * @returns {object|null}
 */
export function importBackup(raw, passphrase) {
  try {
    const env = JSON.parse(raw);
    if (env.kind !== 'ciphermesh-backup') {
      return null;
    }
    const salt = Buffer.from(env.salt, 'base64');
    const nonce = Buffer.from(env.nonce, 'base64');
    const ciphertext = Buffer.from(env.ciphertext, 'base64');
    const opslimit = env.opslimit ?? KDF_LEGACY.opslimit;
    const memlimit = env.memlimit ?? KDF_LEGACY.memlimit;

    const { kek } = deriveKEK(passphrase, salt, opslimit, memlimit);
    const plaintext = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
    const ok = sodium.crypto_secretbox_open_easy(plaintext, ciphertext, nonce, kek);
    sodium.sodium_memzero(kek);

    if (!ok) {
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
