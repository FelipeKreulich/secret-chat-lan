import sodium from 'sodium-native';

export class Handshake {
  #keyManager;
  #peerKeys; // Map<sessionId, Buffer(publicKey)>

  constructor(keyManager) {
    this.#keyManager = keyManager;
    this.#peerKeys = new Map();
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
   * Get the peer's public key.
   */
  getPeerPublicKey(peerId) {
    return this.#peerKeys.get(peerId);
  }

  /**
   * Get our own secret key (for passing to MessageCrypto).
   */
  get secretKey() {
    return this.#keyManager.secretKey;
  }

  /**
   * Remove a peer.
   */
  removePeer(peerId) {
    this.#peerKeys.delete(peerId);
  }

  /**
   * Destroy all state.
   */
  destroy() {
    this.#peerKeys.clear();
  }
}
