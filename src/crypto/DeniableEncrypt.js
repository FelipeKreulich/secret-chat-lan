import sodium from 'sodium-native';
import { padMessage, unpadSecure } from './MessageCrypto.js';

/**
 * Derive a shared symmetric key from DH key exchange.
 * Uses crypto_box_beforenm (X25519 → shared key).
 * Both parties derive the same key, so either could have created any message.
 */
export function deriveSharedKey(mySecretKey, peerPublicKey) {
  const sharedKey = sodium.sodium_malloc(sodium.crypto_box_BEFORENMBYTES);
  sodium.crypto_box_beforenm(sharedKey, peerPublicKey, mySecretKey);
  return sharedKey;
}

/**
 * Encrypt with crypto_secretbox_easy (symmetric, deniable).
 * Uses XSalsa20-Poly1305 with a shared key — no sender authentication.
 */
export function encryptDeniable(plaintext, nonce, sharedKey) {
  const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const padded = padMessage(message);
  const ciphertext = Buffer.alloc(padded.length + sodium.crypto_secretbox_MACBYTES);

  sodium.crypto_secretbox_easy(ciphertext, padded, nonce, sharedKey);
  sodium.sodium_memzero(padded);

  return ciphertext;
}

/**
 * Decrypt with crypto_secretbox_open_easy (symmetric, deniable).
 */
export function decryptDeniable(ciphertext, nonce, sharedKey) {
  const padded = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
  const ok = sodium.crypto_secretbox_open_easy(padded, ciphertext, nonce, sharedKey);

  if (!ok) {
    sodium.sodium_memzero(padded);
    return null;
  }

  return unpadSecure(padded);
}
