import sodium from 'sodium-native';

/**
 * Encrypt plaintext using crypto_box_easy (X25519 + XSalsa20-Poly1305).
 * @param {string|Buffer} plaintext
 * @param {Buffer} nonce - 24 bytes
 * @param {Buffer} recipientPublicKey - 32 bytes
 * @param {Buffer} senderSecretKey - 32 bytes
 * @returns {Buffer} ciphertext (plaintext.length + 16 bytes MAC)
 */
export function encrypt(plaintext, nonce, recipientPublicKey, senderSecretKey) {
  const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const ciphertext = Buffer.alloc(message.length + sodium.crypto_box_MACBYTES);

  sodium.crypto_box_easy(ciphertext, message, nonce, recipientPublicKey, senderSecretKey);

  return ciphertext;
}

/**
 * Decrypt ciphertext using crypto_box_open_easy.
 * @param {Buffer} ciphertext
 * @param {Buffer} nonce - 24 bytes
 * @param {Buffer} senderPublicKey - 32 bytes
 * @param {Buffer} recipientSecretKey - 32 bytes
 * @returns {Buffer|null} plaintext, or null if MAC verification failed
 */
export function decrypt(ciphertext, nonce, senderPublicKey, recipientSecretKey) {
  if (ciphertext.length < sodium.crypto_box_MACBYTES) {
    return null;
  }

  const plaintext = Buffer.alloc(ciphertext.length - sodium.crypto_box_MACBYTES);
  const valid = sodium.crypto_box_open_easy(plaintext, ciphertext, nonce, senderPublicKey, recipientSecretKey);

  return valid ? plaintext : null;
}
