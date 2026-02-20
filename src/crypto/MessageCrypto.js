import sodium from 'sodium-native';
import { MESSAGE_PAD_BUCKETS } from '../shared/constants.js';

// ── Padding helpers ──────────────────────────────────────────

/**
 * Pad plaintext to a fixed-size bucket to hide message length.
 * Format: [2 bytes length BE] + [plaintext] + [random padding]
 */
export function padMessage(message) {
  const needed = 2 + message.length;

  // Find smallest bucket that fits
  let bucketSize = MESSAGE_PAD_BUCKETS[MESSAGE_PAD_BUCKETS.length - 1];
  for (const size of MESSAGE_PAD_BUCKETS) {
    if (size >= needed) {
      bucketSize = size;
      break;
    }
  }

  // If message is larger than biggest bucket, no padding (e.g. file chunks)
  if (needed > bucketSize) {
    bucketSize = needed;
  }

  const padded = Buffer.alloc(bucketSize);
  padded.writeUInt16BE(message.length, 0);
  message.copy(padded, 2);

  // Fill remaining bytes with random data
  if (bucketSize > needed) {
    const randomPart = padded.subarray(needed);
    sodium.randombytes_buf(randomPart);
  }

  return padded;
}

/**
 * Remove padding and extract original plaintext.
 */
export function unpadMessage(padded) {
  if (padded.length < 2) {
    return null;
  }

  const length = padded.readUInt16BE(0);
  if (length + 2 > padded.length) {
    return null;
  }

  return padded.subarray(2, 2 + length);
}

// ── Encrypt / Decrypt ────────────────────────────────────────

/**
 * Encrypt plaintext using crypto_box_easy (X25519 + XSalsa20-Poly1305).
 * Applies padding before encryption to hide message length.
 * @param {string|Buffer} plaintext
 * @param {Buffer} nonce - 24 bytes
 * @param {Buffer} recipientPublicKey - 32 bytes
 * @param {Buffer} senderSecretKey - 32 bytes
 * @returns {Buffer} ciphertext (padded length + 16 bytes MAC)
 */
export function encrypt(plaintext, nonce, recipientPublicKey, senderSecretKey) {
  const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
  const padded = padMessage(message);
  const ciphertext = Buffer.alloc(padded.length + sodium.crypto_box_MACBYTES);

  sodium.crypto_box_easy(ciphertext, padded, nonce, recipientPublicKey, senderSecretKey);

  return ciphertext;
}

/**
 * Decrypt ciphertext using crypto_box_open_easy.
 * Removes padding after decryption to recover original plaintext.
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

  const padded = Buffer.alloc(ciphertext.length - sodium.crypto_box_MACBYTES);
  const valid = sodium.crypto_box_open_easy(
    padded,
    ciphertext,
    nonce,
    senderPublicKey,
    recipientSecretKey,
  );

  if (!valid) {
    return null;
  }

  return unpadMessage(padded);
}

/**
 * Try to decrypt with current keys, falling back to previous keys (grace period).
 * @param {Buffer} ciphertext
 * @param {Buffer} nonce
 * @param {Buffer} senderPublicKey - current
 * @param {Buffer} recipientSecretKey - current
 * @param {Buffer|null} prevSenderPublicKey - previous sender key (if rotated)
 * @param {Buffer|null} prevRecipientSecretKey - previous recipient key (if rotated)
 * @returns {Buffer|null}
 */
export function decryptWithFallback(
  ciphertext,
  nonce,
  senderPublicKey,
  recipientSecretKey,
  prevSenderPublicKey,
  prevRecipientSecretKey,
) {
  // Try current keys first
  const result = decrypt(ciphertext, nonce, senderPublicKey, recipientSecretKey);
  if (result) {
    return result;
  }

  // Try with sender's previous public key + our current secret key
  if (prevSenderPublicKey) {
    const r = decrypt(ciphertext, nonce, prevSenderPublicKey, recipientSecretKey);
    if (r) {
      return r;
    }
  }

  // Try with our previous secret key + sender's current public key
  if (prevRecipientSecretKey) {
    const r = decrypt(ciphertext, nonce, senderPublicKey, prevRecipientSecretKey);
    if (r) {
      return r;
    }
  }

  // Try with both previous keys
  if (prevSenderPublicKey && prevRecipientSecretKey) {
    const r = decrypt(ciphertext, nonce, prevSenderPublicKey, prevRecipientSecretKey);
    if (r) {
      return r;
    }
  }

  return null;
}
