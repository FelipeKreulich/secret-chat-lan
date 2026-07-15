import sodium from 'sodium-native';
import { padMessage, unpadSecure } from './MessageCrypto.js';

/**
 * Derive a shared symmetric key from a DH key exchange.
 * X25519(mySecret, peerPublic) → BLAKE2b → 32-byte secretbox key.
 * Both parties derive the same key (DH symmetry), so either could have created
 * any message — that is what gives the deniable construction its deniability.
 *
 * NOTE: this used to call crypto_box_beforenm, which sodium-native removed
 * (>=4.3.3), leaving deniable mode broken at runtime. We now derive the key
 * ourselves from the raw X25519 shared secret.
 */
export function deriveSharedKey(mySecretKey, peerPublicKey) {
  const dh = sodium.sodium_malloc(sodium.crypto_scalarmult_BYTES);
  sodium.crypto_scalarmult(dh, mySecretKey, peerPublicKey);

  const sharedKey = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES);
  sodium.crypto_generichash(sharedKey, dh);

  sodium.sodium_memzero(dh);
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
