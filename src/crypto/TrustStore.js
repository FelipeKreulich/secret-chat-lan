import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync, statSync } from 'node:fs';
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
    writeFileSync(this.#storePath, JSON.stringify(obj, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
  }

  // Securely delete the trust store from disk (panic / duress).
  wipe() {
    this.#store = new Map();
    try {
      if (existsSync(this.#storePath)) {
        writeFileSync(this.#storePath, Buffer.alloc(Math.max(256, statSync(this.#storePath).size)));
        unlinkSync(this.#storePath);
      }
    } catch {
      /* best effort */
    }
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

    // Compare the FULL public key (256 bits), not the 64-bit fingerprint.
    // Fall back to the fingerprint only for legacy records without publicKey.
    const matches = record.publicKey
      ? record.publicKey === publicKeyB64
      : record.fingerprint === KeyManager.computeFingerprint(Buffer.from(publicKeyB64, 'base64'));

    if (matches) {
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
    const fingerprint = KeyManager.computeFingerprint(Buffer.from(publicKeyB64, 'base64'));
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
    const fingerprint = KeyManager.computeFingerprint(Buffer.from(publicKeyB64, 'base64'));
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
    const fingerprint = KeyManager.computeFingerprint(Buffer.from(publicKeyB64, 'base64'));
    record.fingerprint = fingerprint;
    record.publicKey = publicKeyB64;
    record.lastSeen = Date.now();
    this.#save();
  }

  /**
   * Compute a Short Authentication String from both public keys.
   * ~40 bits of entropy shown as 13 grouped decimal digits (was 6 digits / ~20
   * bits, which is grindable offline). Both sides compute the same value; it is
   * only ever compared by humans out-of-band, never typed back.
   */
  static computeSAS(myPublicKey, peerPublicKey) {
    const myPub = Buffer.isBuffer(myPublicKey) ? myPublicKey : Buffer.from(myPublicKey, 'base64');
    const peerPub = Buffer.isBuffer(peerPublicKey)
      ? peerPublicKey
      : Buffer.from(peerPublicKey, 'base64');

    // Sort lexicographically for deterministic ordering
    const [first, second] =
      Buffer.compare(myPub, peerPub) <= 0 ? [myPub, peerPub] : [peerPub, myPub];

    // BLAKE2b-256(pubA || pubB || domain separator)
    const context = Buffer.from('CipherMesh-SAS-v1');
    const input = Buffer.concat([first, second, context]);
    const hash = Buffer.alloc(32);
    sodium.crypto_generichash(hash, input);

    // First 5 bytes (40 bits) → up to 13 decimal digits, grouped 4-4-5.
    let num = 0n;
    for (let i = 0; i < 5; i++) {
      num = (num << 8n) | BigInt(hash[i]);
    }
    const digits = num.toString().padStart(13, '0');
    return `${digits.slice(0, 4)} ${digits.slice(4, 8)} ${digits.slice(8)}`;
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

  // ── Contacts (friendly aliases on top of trust records) ──────
  // The alias lives on the trust record, so it survives restarts and rides
  // along in the existing identity backup for free.

  /** Set a friendly alias for an already-seen peer. False if peer unknown. */
  setAlias(nickname, alias) {
    const record = this.#store.get(nickname.toLowerCase());
    if (!record) {
      return false;
    }
    record.alias = String(alias).slice(0, 30);
    this.#save();
    return true;
  }

  /** Remove a peer's alias. False if there was none. */
  clearAlias(nickname) {
    const record = this.#store.get(nickname.toLowerCase());
    if (!record || !record.alias) {
      return false;
    }
    delete record.alias;
    this.#save();
    return true;
  }

  getAlias(nickname) {
    return this.#store.get(nickname.toLowerCase())?.alias || null;
  }

  /**
   * The contact book: aliased peers, or every known peer with `all`.
   * Sorted by most recently seen.
   */
  listContacts(all = false) {
    return [...this.#store.entries()]
      .filter(([, r]) => all || r.alias)
      .map(([nickname, r]) => ({
        nickname,
        alias: r.alias || null,
        verified: r.verified === true,
        fingerprint: r.fingerprint,
        lastSeen: r.lastSeen || 0,
      }))
      .sort((a, b) => b.lastSeen - a.lastSeen);
  }

  // ── Blocking ─────────────────────────────────────────────────
  // Entirely local: nothing is sent, the relay never learns, and blocking
  // someone affects only the person who did it. That is what makes it safe to
  // give to everyone — moderation needs authority and so has to be limited to
  // room owners, but refusing to listen needs none.
  //
  // It is also the only protection available in `general`, which has no owner
  // and therefore no moderation at all.
  //
  // Matched on the public key, never the nickname: /nick would otherwise undo a
  // block the same way it used to undo a ban.

  /** Block an already-seen peer. False if we have never seen them. */
  blockPeer(nickname) {
    const record = this.#store.get(nickname.toLowerCase());
    if (!record) {
      return false;
    }
    record.blocked = true;
    this.#save();
    return true;
  }

  /** Unblock a peer. False if they were not blocked. */
  unblockPeer(nickname) {
    const record = this.#store.get(nickname.toLowerCase());
    if (!record?.blocked) {
      return false;
    }
    delete record.blocked;
    this.#save();
    return true;
  }

  /**
   * Is this key blocked?
   *
   * Records are filed under the nickname they were first seen with, so a
   * rename leaves the record where it was — the key is what has to match.
   *
   * @param {string} publicKeyB64
   */
  isBlocked(publicKeyB64) {
    if (!publicKeyB64) {
      return false;
    }
    for (const record of this.#store.values()) {
      if (record.blocked && record.publicKey === publicKeyB64) {
        return true;
      }
    }
    return false;
  }

  /** Everyone currently blocked, most recently seen first. */
  listBlocked() {
    return [...this.#store.entries()]
      .filter(([, r]) => r.blocked)
      .map(([nickname, r]) => ({
        nickname,
        alias: r.alias || null,
        fingerprint: r.fingerprint,
        lastSeen: r.lastSeen || 0,
      }))
      .sort((a, b) => b.lastSeen - a.lastSeen);
  }

  /** Export all trust records as a plain object (for identity backup). */
  exportData() {
    return Object.fromEntries(this.#store);
  }

  /** Merge trust records from a backup, preferring imported verified peers. */
  importData(obj) {
    if (!obj || typeof obj !== 'object') {
      return;
    }
    for (const [nick, record] of Object.entries(obj)) {
      const existing = this.#store.get(nick);
      // Keep whichever record is verified; otherwise the imported one wins.
      if (!existing || record.verified || !existing.verified) {
        this.#store.set(nick, record);
      }
    }
    this.#save();
  }
}
