import sodium from 'sodium-native';
import { KEY_ROTATION_GRACE_MS } from '../shared/constants.js';
import { DoubleRatchet } from './DoubleRatchet.js';

export class Handshake {
  #keyManager;
  #peerKeys; // Map<sessionId, Buffer(publicKey)>
  #previousPeerKeys; // Map<sessionId, { publicKey, timer }>
  #ratchets; // Map<sessionId, DoubleRatchet>
  #mySessionId;

  constructor(keyManager) {
    this.#keyManager = keyManager;
    this.#peerKeys = new Map();
    this.#previousPeerKeys = new Map();
    this.#ratchets = new Map();
    this.#mySessionId = null;
  }

  /**
   * Set our session ID (called after JOIN_ACK).
   * Also initializes ratchets for any already-registered peers.
   */
  setMySessionId(sessionId) {
    this.#mySessionId = sessionId;

    // Create ratchets for peers already registered
    for (const [peerId, pubKey] of this.#peerKeys) {
      if (!this.#ratchets.has(peerId)) {
        this.#ratchets.set(
          peerId,
          new DoubleRatchet(this.#mySessionId, peerId, this.#keyManager.secretKey, pubKey),
        );
      }
    }
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

    // Create ratchet if we already have our session ID
    if (this.#mySessionId && !this.#ratchets.has(peerId)) {
      this.#ratchets.set(
        peerId,
        new DoubleRatchet(this.#mySessionId, peerId, this.#keyManager.secretKey, pubBuf),
      );
    }
  }

  /**
   * Get the ratchet for a peer.
   */
  getRatchet(peerId) {
    return this.#ratchets.get(peerId) || null;
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
      if (existing) {
        clearTimeout(existing.timer);
      }

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

    const ratchet = this.#ratchets.get(peerId);
    if (ratchet) {
      ratchet.destroy();
      this.#ratchets.delete(peerId);
    }
  }

  /**
   * Re-map a ratchet from old peer ID to new peer ID (e.g., after reconnect).
   */
  migrateRatchet(oldPeerId, newPeerId) {
    const ratchet = this.#ratchets.get(oldPeerId);
    if (ratchet) {
      this.#ratchets.delete(oldPeerId);
      this.#ratchets.set(newPeerId, ratchet);
    }
    const peerKey = this.#peerKeys.get(oldPeerId);
    if (peerKey) {
      this.#peerKeys.delete(oldPeerId);
      this.#peerKeys.set(newPeerId, peerKey);
    }
    const prevKey = this.#previousPeerKeys.get(oldPeerId);
    if (prevKey) {
      this.#previousPeerKeys.delete(oldPeerId);
      this.#previousPeerKeys.set(newPeerId, prevKey);
    }
  }

  /**
   * Serialize all ratchets + peer keys for encrypted persistence.
   */
  serializeState() {
    const ratchets = {};
    for (const [peerId, ratchet] of this.#ratchets) {
      ratchets[peerId] = ratchet.serialize();
    }

    const peerKeys = {};
    for (const [peerId, pubKey] of this.#peerKeys) {
      peerKeys[peerId] = pubKey.toString('base64');
    }

    return {
      mySessionId: this.#mySessionId,
      ratchets,
      peerKeys,
    };
  }

  /**
   * Restore ratchets + peer keys from persisted state.
   */
  restoreState(data) {
    this.#mySessionId = data.mySessionId;

    for (const [peerId, pubKeyB64] of Object.entries(data.peerKeys || {})) {
      this.#peerKeys.set(peerId, Buffer.from(pubKeyB64, 'base64'));
    }

    for (const [peerId, ratchetData] of Object.entries(data.ratchets || {})) {
      this.#ratchets.set(peerId, DoubleRatchet.deserialize(ratchetData));
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

    for (const [, ratchet] of this.#ratchets) {
      ratchet.destroy();
    }
    this.#ratchets.clear();
    this.#mySessionId = null;
  }
}
