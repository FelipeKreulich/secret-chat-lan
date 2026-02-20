import sodium from 'sodium-native';
import { RATCHET_MAX_SKIP, RATCHET_SKIP_KEY_MAX_AGE_MS } from '../shared/constants.js';
import { padMessage, unpadMessage } from './MessageCrypto.js';

const SCALARMULT_BYTES = 32;
const KEY_SIZE = 32;
const NONCE_SIZE = 24;

export class DoubleRatchet {
  #rootKey;
  #sendChainKey;
  #recvChainKey;
  #sendCounter;
  #recvCounter;
  #previousSendCount;
  #myEphKeyPair;
  #peerEphPublicKey;
  #skippedKeys; // Map<"ephHex:counter", { msgKey, timestamp }>
  #initialized;
  #needSendRatchet; // true when we need a DH ratchet step before next send

  /**
   * @param {string} mySessionId
   * @param {string} peerSessionId
   * @param {Buffer} myStaticSecretKey
   * @param {Buffer} peerStaticPublicKey
   */
  constructor(mySessionId, peerSessionId, myStaticSecretKey, peerStaticPublicKey) {
    this.#skippedKeys = new Map();
    this.#sendCounter = 0;
    this.#recvCounter = 0;
    this.#previousSendCount = 0;
    this.#sendChainKey = null;
    this.#recvChainKey = null;
    this.#myEphKeyPair = null;
    this.#peerEphPublicKey = null;
    this.#initialized = false;
    this.#needSendRatchet = true;

    // Derive initial rootKey from static DH
    const dhOutput = sodium.sodium_malloc(SCALARMULT_BYTES);
    sodium.crypto_scalarmult(dhOutput, myStaticSecretKey, peerStaticPublicKey);

    this.#rootKey = sodium.sodium_malloc(KEY_SIZE);
    sodium.crypto_generichash(this.#rootKey, dhOutput);
    sodium.sodium_memzero(dhOutput);

    const isInitiator = mySessionId < peerSessionId;

    if (isInitiator) {
      // Initiator generates ephemeral keypair immediately
      this.#myEphKeyPair = this.#generateEphemeralKeyPair();
      // Use peer's static public key as initial "ephemeral" until they respond
      this.#peerEphPublicKey = Buffer.from(peerStaticPublicKey);
    } else {
      // Responder: use copy of static secret key for initial DH on first receive.
      // Will be wiped and replaced with a true ephemeral on first send.
      const secretCopy = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
      myStaticSecretKey.copy(secretCopy);
      this.#myEphKeyPair = { publicKey: null, secretKey: secretCopy };
      this.#peerEphPublicKey = null;
    }

    this.#initialized = true;
  }

  get isInitialized() {
    return this.#initialized;
  }

  // ── Key generation ──────────────────────────────────────────

  #generateEphemeralKeyPair() {
    const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
    const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
    sodium.crypto_box_keypair(publicKey, secretKey);
    return { publicKey, secretKey };
  }

  // ── KDF functions ───────────────────────────────────────────

  /**
   * KDF_RK: Root Key ratchet. Produces new rootKey + chainKey from DH output.
   * BLAKE2b-512(key=rootKey, input=dhOutput) → 64 bytes
   * First 32B = newRootKey, last 32B = chainKey
   */
  #kdfRK(dhOutput) {
    const output = sodium.sodium_malloc(64);
    sodium.crypto_generichash(output, dhOutput, this.#rootKey);

    const newRootKey = sodium.sodium_malloc(KEY_SIZE);
    output.copy(newRootKey, 0, 0, 32);

    const chainKey = sodium.sodium_malloc(KEY_SIZE);
    output.copy(chainKey, 0, 32, 64);

    sodium.sodium_memzero(this.#rootKey);
    this.#rootKey = newRootKey;

    sodium.sodium_memzero(output);
    return chainKey;
  }

  /**
   * KDF_CK: Chain Key ratchet. Produces messageKey + nextChainKey.
   * messageKey = BLAKE2b-256(key=chainKey, input=0x01)
   * nextChainKey = BLAKE2b-256(key=chainKey, input=0x02)
   */
  #kdfCK(chainKey) {
    const msgKeyInput = Buffer.from([0x01]);
    const nextCKInput = Buffer.from([0x02]);

    const messageKey = sodium.sodium_malloc(KEY_SIZE);
    sodium.crypto_generichash(messageKey, msgKeyInput, chainKey);

    const nextChainKey = sodium.sodium_malloc(KEY_SIZE);
    sodium.crypto_generichash(nextChainKey, nextCKInput, chainKey);

    sodium.sodium_memzero(chainKey);
    return { messageKey, nextChainKey };
  }

  // ── DH helper ───────────────────────────────────────────────

  #dh(mySecretKey, theirPublicKey) {
    const output = sodium.sodium_malloc(SCALARMULT_BYTES);
    sodium.crypto_scalarmult(output, mySecretKey, theirPublicKey);
    return output;
  }

  // ── Encrypt ─────────────────────────────────────────────────

  /**
   * Encrypt plaintext for the peer.
   * @param {string|Buffer} plaintext
   * @returns {{ ciphertext: Buffer, nonce: Buffer, ephemeralPublicKey: Buffer, counter: number, previousCounter: number }}
   */
  encrypt(plaintext) {
    if (!this.#initialized) {
      throw new Error('Ratchet not initialized');
    }

    // DH ratchet step if needed (first send or after receiving)
    if (this.#needSendRatchet) {
      // Must have peer's ephemeral key before we can ratchet
      if (!this.#peerEphPublicKey) {
        throw new Error('No peer ephemeral key yet');
      }

      this.#previousSendCount = this.#sendCounter;
      this.#sendCounter = 0;

      // Generate new ephemeral keypair
      if (this.#myEphKeyPair) {
        // Wipe old secret key
        sodium.sodium_memzero(this.#myEphKeyPair.secretKey);
      }
      this.#myEphKeyPair = this.#generateEphemeralKeyPair();

      // DH ratchet: derive new send chain key
      const dhOut = this.#dh(this.#myEphKeyPair.secretKey, this.#peerEphPublicKey);
      this.#sendChainKey = this.#kdfRK(dhOut);
      sodium.sodium_memzero(dhOut);

      this.#needSendRatchet = false;
    }

    // Advance send chain
    const { messageKey, nextChainKey } = this.#kdfCK(this.#sendChainKey);
    this.#sendChainKey = nextChainKey;

    // Encrypt
    const message = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf-8');
    const padded = padMessage(message);
    const nonce = Buffer.alloc(NONCE_SIZE);
    sodium.randombytes_buf(nonce);

    const ciphertext = Buffer.alloc(padded.length + sodium.crypto_secretbox_MACBYTES);
    sodium.crypto_secretbox_easy(ciphertext, padded, nonce, messageKey);

    const counter = this.#sendCounter;
    this.#sendCounter++;

    // Wipe message key immediately
    sodium.sodium_memzero(messageKey);

    return {
      ciphertext,
      nonce,
      ephemeralPublicKey: this.#myEphKeyPair.publicKey,
      counter,
      previousCounter: this.#previousSendCount,
    };
  }

  // ── Decrypt ─────────────────────────────────────────────────

  /**
   * Decrypt a ratcheted message.
   * @param {Buffer} ciphertext
   * @param {Buffer} nonce
   * @param {Buffer} ephPub - sender's ephemeral public key
   * @param {number} counter
   * @param {number} prevCounter
   * @returns {Buffer|null} plaintext or null on failure
   */
  decrypt(ciphertext, nonce, ephPub, counter, prevCounter) {
    if (!this.#initialized) {
      return null;
    }

    // 1. Try skipped keys first
    const skippedResult = this.#trySkippedKeys(ephPub, counter, ciphertext, nonce);
    if (skippedResult) {
      return skippedResult;
    }

    // 2. If new ephemeral key from peer → DH ratchet step
    if (!this.#peerEphPublicKey || !ephPub.equals(this.#peerEphPublicKey)) {
      // Skip remaining messages in the current receive chain
      if (this.#recvChainKey) {
        this.#skipMessages(this.#peerEphPublicKey, prevCounter);
      }

      // DH ratchet step for receiving
      this.#peerEphPublicKey = Buffer.from(ephPub);
      const dhOut = this.#dh(this.#myEphKeyPair.secretKey, this.#peerEphPublicKey);
      this.#recvChainKey = this.#kdfRK(dhOut);
      sodium.sodium_memzero(dhOut);
      this.#recvCounter = 0;

      // Mark that we need a send ratchet before next encrypt
      this.#needSendRatchet = true;
    }

    // 3. Skip messages up to counter
    this.#skipMessages(ephPub, counter);

    // 4. Advance receive chain
    const { messageKey, nextChainKey } = this.#kdfCK(this.#recvChainKey);
    this.#recvChainKey = nextChainKey;
    this.#recvCounter++;

    // 5. Decrypt
    const padded = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
    const valid = sodium.crypto_secretbox_open_easy(padded, ciphertext, nonce, messageKey);
    sodium.sodium_memzero(messageKey);

    if (!valid) {
      return null;
    }

    // 6. Unpad
    const result = unpadMessage(padded);

    // 7. Cleanup expired skipped keys
    this.#cleanupSkippedKeys();

    return result;
  }

  // ── Skipped keys management ─────────────────────────────────

  #skipMessages(ephPub, until) {
    if (!this.#recvChainKey || !ephPub) {
      return;
    }

    const skip = until - this.#recvCounter;
    if (skip <= 0) {
      return;
    }
    if (skip > RATCHET_MAX_SKIP) {
      throw new Error(`Too many skipped messages: ${skip}`);
    }

    const ephHex = ephPub.toString('hex');
    for (let i = 0; i < skip; i++) {
      const { messageKey, nextChainKey } = this.#kdfCK(this.#recvChainKey);
      this.#recvChainKey = nextChainKey;

      const key = `${ephHex}:${this.#recvCounter}`;
      this.#skippedKeys.set(key, { msgKey: messageKey, timestamp: Date.now() });
      this.#recvCounter++;
    }
  }

  #trySkippedKeys(ephPub, counter, ciphertext, nonce) {
    const key = `${ephPub.toString('hex')}:${counter}`;
    const entry = this.#skippedKeys.get(key);
    if (!entry) {
      return null;
    }

    this.#skippedKeys.delete(key);

    const padded = Buffer.alloc(ciphertext.length - sodium.crypto_secretbox_MACBYTES);
    const valid = sodium.crypto_secretbox_open_easy(padded, ciphertext, nonce, entry.msgKey);
    sodium.sodium_memzero(entry.msgKey);

    if (!valid) {
      return null;
    }
    return unpadMessage(padded);
  }

  #cleanupSkippedKeys() {
    const now = Date.now();
    for (const [key, entry] of this.#skippedKeys) {
      if (now - entry.timestamp > RATCHET_SKIP_KEY_MAX_AGE_MS) {
        sodium.sodium_memzero(entry.msgKey);
        this.#skippedKeys.delete(key);
      }
    }
  }

  // ── Destroy ─────────────────────────────────────────────────

  destroy() {
    if (this.#rootKey) {
      sodium.sodium_memzero(this.#rootKey);
      this.#rootKey = null;
    }
    if (this.#sendChainKey) {
      sodium.sodium_memzero(this.#sendChainKey);
      this.#sendChainKey = null;
    }
    if (this.#recvChainKey) {
      sodium.sodium_memzero(this.#recvChainKey);
      this.#recvChainKey = null;
    }
    if (this.#myEphKeyPair) {
      sodium.sodium_memzero(this.#myEphKeyPair.secretKey);
      this.#myEphKeyPair = null;
    }
    for (const [, entry] of this.#skippedKeys) {
      sodium.sodium_memzero(entry.msgKey);
    }
    this.#skippedKeys.clear();
    this.#peerEphPublicKey = null;
    this.#initialized = false;
  }
}
