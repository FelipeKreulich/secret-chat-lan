import sodium from 'sodium-native';
import { KEY_ROTATION_GRACE_MS } from '../shared/constants.js';

export class Handshake {
  #keyManager;
  #peerKeys; // Map<sessionId, Buffer(publicKey)>
  #previousPeerKeys; // Map<sessionId, { publicKey, timer }>

  constructor(keyManager) {
    this.#keyManager = keyManager;
    this.#peerKeys = new Map();
    this.#previousPeerKeys = new Map();
  }

  /**
   * Register a peer's public key for future encryption/decryption.
   */
  registerPeer(peerId, peerPublicKey) {
    const pubBuf = Buffer.isBuffer(peerPublicKey)
      ? peerPublicKey
      : Buffer.from(peerPublicKey, 'base64');

    if (pubBuf.length !== sodium.crypto_box_PUBLICKEYBYTES) {
      throw new Error(`Invalid public key size: ${pubBuf.length}`);
    }

    this.#peerKeys.set(peerId, Buffer.from(pubBuf));
  }

  /**
   * Update a peer's public key (key rotation).
   * Keeps the old key for a grace period.
   */
  updatePeerKey(peerId, newPublicKey) {
    const newBuf = Buffer.isBuffer(newPublicKey)
      ? newPublicKey
      : Buffer.from(newPublicKey, 'base64');

    if (newBuf.length !== sodium.crypto_box_PUBLICKEYBYTES) {
      throw new Error(`Invalid public key size: ${newBuf.length}`);
    }

    const oldKey = this.#peerKeys.get(peerId);
    if (oldKey) {
      // Clear any existing grace timer for this peer
      const existing = this.#previousPeerKeys.get(peerId);
      if (existing) clearTimeout(existing.timer);

      const timer = setTimeout(() => {
        this.#previousPeerKeys.delete(peerId);
      }, KEY_ROTATION_GRACE_MS);

      this.#previousPeerKeys.set(peerId, { publicKey: oldKey, timer });
    }

    this.#peerKeys.set(peerId, Buffer.from(newBuf));
  }

  /**
   * Get the peer's current public key.
   */
  getPeerPublicKey(peerId) {
    return this.#peerKeys.get(peerId);
  }

  /**
   * Get the peer's previous public key (during grace period).
   */
  getPreviousPeerPublicKey(peerId) {
    const entry = this.#previousPeerKeys.get(peerId);
    return entry?.publicKey || null;
  }

  /**
   * Get our own secret key (for passing to MessageCrypto).
   */
  get secretKey() {
    return this.#keyManager.secretKey;
  }

  /**
   * Get our previous secret key (for decrypting in-flight msgs after rotation).
   */
  get previousSecretKey() {
    return this.#keyManager.previousSecretKey;
  }

  /**
   * Remove a peer.
   */
  removePeer(peerId) {
    this.#peerKeys.delete(peerId);
    const prev = this.#previousPeerKeys.get(peerId);
    if (prev) {
      clearTimeout(prev.timer);
      this.#previousPeerKeys.delete(peerId);
    }
  }

  /**
   * Destroy all state.
   */
  destroy() {
    this.#peerKeys.clear();
    for (const [, entry] of this.#previousPeerKeys) {
      clearTimeout(entry.timer);
    }
    this.#previousPeerKeys.clear();
  }
}
