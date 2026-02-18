// @ts-nocheck
import sodium from 'sodium-native';
import { createHash } from 'node:crypto';

export class KeyManager {
  #publicKey;
  #secretKey;
  #fingerprint;

  constructor() {
    this.#publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
    this.#secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);

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

  static computeFingerprint(publicKey) {
    const hash = createHash('sha256').update(publicKey).digest();
    const parts = [];
    for (let i = 0; i < 8; i += 2) {
      parts.push(hash.subarray(i, i + 2).toString('hex').toUpperCase());
    }
    return parts.join(':');
  }

  destroy() {
    if (this.#secretKey) {
      sodium.sodium_memzero(this.#secretKey);
    }
    this.#secretKey = null;
    this.#publicKey = null;
    this.#fingerprint = null;
  }
}
