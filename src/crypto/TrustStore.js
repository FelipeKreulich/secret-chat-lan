import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import sodium from 'sodium-native';
import { KeyManager } from './KeyManager.js';

const TRUST_DIR = '.ciphermesh';
const TRUST_FILE = 'trusted-peers.json';

export const TrustResult = {
  NEW_PEER: 'new_peer',
  TRUSTED: 'trusted',
  MISMATCH: 'mismatch',
  VERIFIED_MISMATCH: 'verified_mismatch',
};

export class TrustStore {
  #storePath;
  #store; // Map<lowerNickname, record>

  constructor(baseDir = process.cwd()) {
    const dir = join(baseDir, TRUST_DIR);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    this.#storePath = join(dir, TRUST_FILE);
    this.#store = new Map();
    this.#load();
  }

  #load() {
    try {
      if (existsSync(this.#storePath)) {
        const raw = readFileSync(this.#storePath, 'utf-8');
        const data = JSON.parse(raw);
        for (const [nick, record] of Object.entries(data)) {
          this.#store.set(nick, record);
        }
      }
    } catch {
      this.#store = new Map();
    }
  }

  #save() {
    const obj = Object.fromEntries(this.#store);
    writeFileSync(this.#storePath, JSON.stringify(obj, null, 2), 'utf-8');
  }

  /**
   * Check if a peer's fingerprint matches the stored one.
   */
  checkPeer(nickname, publicKeyB64) {
    const key = nickname.toLowerCase();
    const record = this.#store.get(key);

    if (!record) {
      return TrustResult.NEW_PEER;
    }

    const currentFingerprint = KeyManager.computeFingerprint(
      Buffer.from(publicKeyB64, 'base64'),
    );

    if (record.fingerprint === currentFingerprint) {
      record.lastSeen = Date.now();
      this.#save();
      return TrustResult.TRUSTED;
    }

    if (record.verified) {
      return TrustResult.VERIFIED_MISMATCH;
    }
    return TrustResult.MISMATCH;
  }

  /**
   * Record a first-time peer.
   */
  recordPeer(nickname, publicKeyB64) {
    const key = nickname.toLowerCase();
    const fingerprint = KeyManager.computeFingerprint(
      Buffer.from(publicKeyB64, 'base64'),
    );
    this.#store.set(key, {
      fingerprint,
      publicKey: publicKeyB64,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      verified: false,
    });
    this.#save();
  }

  /**
   * User explicitly accepts a new key (resets verified status).
   */
  updatePeer(nickname, publicKeyB64) {
    const key = nickname.toLowerCase();
    const fingerprint = KeyManager.computeFingerprint(
      Buffer.from(publicKeyB64, 'base64'),
    );
    const record = this.#store.get(key);
    if (!record) {
      this.recordPeer(nickname, publicKeyB64);
      return;
    }
    record.fingerprint = fingerprint;
    record.publicKey = publicKeyB64;
    record.lastSeen = Date.now();
    record.verified = false;
    this.#save();
  }

  /**
   * Auto-update from authenticated E2E key rotation (preserves verified status).
   */
  autoUpdatePeer(nickname, publicKeyB64) {
    const key = nickname.toLowerCase();
    const record = this.#store.get(key);
    if (!record) {
      this.recordPeer(nickname, publicKeyB64);
      return;
    }
    const fingerprint = KeyManager.computeFingerprint(
      Buffer.from(publicKeyB64, 'base64'),
    );
    record.fingerprint = fingerprint;
    record.publicKey = publicKeyB64;
    record.lastSeen = Date.now();
    this.#save();
  }

  /**
   * Compute a 6-digit SAS code from both public keys.
   * Both sides compute the same value independently.
   */
  static computeSAS(myPublicKey, peerPublicKey) {
    const myPub = Buffer.isBuffer(myPublicKey)
      ? myPublicKey
      : Buffer.from(myPublicKey, 'base64');
    const peerPub = Buffer.isBuffer(peerPublicKey)
      ? peerPublicKey
      : Buffer.from(peerPublicKey, 'base64');

    // Sort lexicographically for deterministic ordering
    const [first, second] =
      Buffer.compare(myPub, peerPub) <= 0
        ? [myPub, peerPub]
        : [peerPub, myPub];

    // BLAKE2b-256(pubA || pubB || domain separator)
    const context = Buffer.from('CipherMesh-SAS-v1');
    const input = Buffer.concat([first, second, context]);
    const hash = Buffer.alloc(32);
    sodium.crypto_generichash(hash, input);

    // First 3 bytes → 6 decimal digits
    const num = ((hash[0] << 16) | (hash[1] << 8) | hash[2]) % 1_000_000;
    return num.toString().padStart(6, '0');
  }

  markVerified(nickname) {
    const key = nickname.toLowerCase();
    const record = this.#store.get(key);
    if (record) {
      record.verified = true;
      this.#save();
      return true;
    }
    return false;
  }

  isVerified(nickname) {
    const key = nickname.toLowerCase();
    const record = this.#store.get(key);
    return record?.verified === true;
  }

  getPeerRecord(nickname) {
    return this.#store.get(nickname.toLowerCase()) || null;
  }
}
