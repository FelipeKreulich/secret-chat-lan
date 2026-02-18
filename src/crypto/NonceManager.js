import sodium from 'sodium-native';
import {
  NONCE_SIZE,
  NONCE_TIMESTAMP_OFFSET,
  NONCE_COUNTER_OFFSET,
  NONCE_RANDOM_OFFSET,
  NONCE_RANDOM_SIZE,
  NONCE_MAX_AGE_MS,
} from '../shared/constants.js';

export class NonceManager {
  #counter;
  #peerCounters; // Map<peerId, lastCounter>

  constructor() {
    this.#counter = 0;
    this.#peerCounters = new Map();
  }

  /**
   * Generate a new 24-byte nonce:
   * [8B timestamp][4B counter][12B random]
   */
  generate() {
    const nonce = Buffer.alloc(NONCE_SIZE);

    // 8 bytes: millisecond timestamp
    const now = BigInt(Date.now());
    nonce.writeBigUInt64BE(now, NONCE_TIMESTAMP_OFFSET);

    // 4 bytes: monotonic counter
    this.#counter = (this.#counter + 1) & 0xffffffff;
    nonce.writeUInt32BE(this.#counter, NONCE_COUNTER_OFFSET);

    // 12 bytes: random
    const randomPart = nonce.subarray(NONCE_RANDOM_OFFSET, NONCE_RANDOM_OFFSET + NONCE_RANDOM_SIZE);
    sodium.randombytes_buf(randomPart);

    return nonce;
  }

  /**
   * Validate an incoming nonce (anti-replay).
   * Returns true if valid, false if replayed or too old.
   */
  validate(peerId, nonce) {
    if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_SIZE) {
      return false;
    }

    // Check timestamp freshness
    const nonceTimestamp = Number(nonce.readBigUInt64BE(NONCE_TIMESTAMP_OFFSET));
    const now = Date.now();
    if (Math.abs(now - nonceTimestamp) > NONCE_MAX_AGE_MS) {
      return false;
    }

    // Check counter is strictly increasing per peer
    const counter = nonce.readUInt32BE(NONCE_COUNTER_OFFSET);
    const lastCounter = this.#peerCounters.get(peerId) ?? -1;
    if (counter <= lastCounter) {
      return false;
    }

    this.#peerCounters.set(peerId, counter);
    return true;
  }

  removePeer(peerId) {
    this.#peerCounters.delete(peerId);
  }
}
