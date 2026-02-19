// @ts-nocheck
import sodium from 'sodium-native';
import { createHash } from 'node:crypto';
import { KEY_ROTATION_GRACE_MS } from '../shared/constants.js';

export class KeyManager {
  #publicKey;
  #secretKey;
  #fingerprint;
  #previousPublicKey;
  #previousSecretKey;
  #graceTimer;

  constructor() {
    this.#publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
    this.#secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
    this.#previousPublicKey = null;
    this.#previousSecretKey = null;
    this.#graceTimer = null;

    sodium.crypto_box_keypair(this.#publicKey, this.#secretKey);

    this.#fingerprint = KeyManager.computeFingerprint(this.#publicKey);
  }

  get publicKey() {
    return this.#publicKey;
  }

  get secretKey() {
    return this.#secretKey;
  }

  get publicKeyB64() {
    return this.#publicKey.toString('base64');
  }

  get fingerprint() {
    return this.#fingerprint;
  }

  get previousPublicKey() {
    return this.#previousPublicKey;
  }

  get previousSecretKey() {
    return this.#previousSecretKey;
  }

  /**
   * Generate a new keypair, keeping the old one for a grace period.
   */
  rotate() {
    // Clear any existing grace timer
    if (this.#graceTimer) {
      clearTimeout(this.#graceTimer);
      this.destroyPrevious();
    }

    // Move current keys to previous
    this.#previousPublicKey = this.#publicKey;
    this.#previousSecretKey = this.#secretKey;

    // Generate new keypair
    this.#publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
    this.#secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
    sodium.crypto_box_keypair(this.#publicKey, this.#secretKey);

    this.#fingerprint = KeyManager.computeFingerprint(this.#publicKey);

    // Auto-destroy previous keys after grace period
    this.#graceTimer = setTimeout(() => {
      this.destroyPrevious();
      this.#graceTimer = null;
    }, KEY_ROTATION_GRACE_MS);
  }

  destroyPrevious() {
    if (this.#previousSecretKey) {
      sodium.sodium_memzero(this.#previousSecretKey);
    }
    this.#previousSecretKey = null;
    this.#previousPublicKey = null;
  }

  static computeFingerprint(publicKey) {
    const hash = createHash('sha256').update(publicKey).digest();
    const parts = [];
    for (let i = 0; i < 8; i += 2) {
      parts.push(hash.subarray(i, i + 2).toString('hex').toUpperCase());
    }
    return parts.join(':');
  }

  destroy() {
    if (this.#graceTimer) {
      clearTimeout(this.#graceTimer);
    }
    this.destroyPrevious();
    if (this.#secretKey) {
      sodium.sodium_memzero(this.#secretKey);
    }
    this.#secretKey = null;
    this.#publicKey = null;
    this.#fingerprint = null;
  }
}
