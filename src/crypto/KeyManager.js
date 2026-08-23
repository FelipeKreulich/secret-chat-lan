// @ts-nocheck
import sodium from 'sodium-native';
import { createHash } from 'node:crypto';
import { KEY_ROTATION_GRACE_MS } from '../shared/constants.js';
import { generatePQKeyPair } from './PQHybrid.js';
import { DeviceIdentity, newDeviceId } from './DeviceIdentity.js';

// Guarded memory is released with sodium_free, never merely zeroed.
//
// sodium_malloc'd pages are mlock'd and the OS caps how much a process may lock
// (RLIMIT_MEMLOCK — small on Linux, unlimited on macOS, which is why the ceiling
// is invisible here and fatal in CI). Zeroing leaves the pages locked until the
// garbage collector runs the buffer's finaliser; sodium_free zeroes *and*
// releases, so it is strictly stronger than the memzero it replaces. Every
// caller nulls its reference immediately after, so nothing can reach freed
// memory. Same reasoning as SenderKey.js, and the same failure it was written
// for: an allocation that fails lands as a SIGABRT in whatever allocated next.
export class KeyManager {
  #publicKey;
  #secretKey;
  #fingerprint;
  #previousPublicKey;
  #previousSecretKey;
  #graceTimer;
  #pqKeyPair; // ML-KEM-768 — the hybrid half (see crypto/PQHybrid.js)
  // Multi-device, step 2 (docs/design/multi-device.md). Carried, persisted,
  // backed up and advertised — and read by nobody. The box key above is still
  // the identity as far as every fingerprint, SAS and ban is concerned; this
  // pair exists so that the field is already on the wire when step 3 starts
  // signing device lists with it, the way the Ed25519 sender key landed before
  // the send path that needed it.
  #identity; // Ed25519 — signs device lists, never encrypts
  #deviceId; // names *this* device across box-key rotations
  #deviceCreatedAt; // when this device id was drawn
  // Version of the device list this device publishes. Persisted, and only ever
  // increased. A peer keeps the highest counter it has seen, so a list that
  // came back with a smaller one is a replay and is ignored — which also means
  // a counter that failed to grow after the descriptor changed would leave
  // every peer holding a list that no longer describes this device.
  #listCounter;

  constructor() {
    this.#publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
    this.#secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
    this.#previousPublicKey = null;
    this.#previousSecretKey = null;
    this.#graceTimer = null;

    sodium.crypto_box_keypair(this.#publicKey, this.#secretKey);
    this.#pqKeyPair = generatePQKeyPair();
    this.#identity = new DeviceIdentity();
    this.#deviceId = newDeviceId();
    this.#deviceCreatedAt = Date.now();
    this.#listCounter = 1;

    this.#fingerprint = KeyManager.computeFingerprint(this.#publicKey);
  }

  /** The signing identity. Survives box-key rotation; that is the point. */
  get identity() {
    return this.#identity;
  }

  get identityPublicKeyB64() {
    return this.#identity.publicKeyB64;
  }

  /**
   * The 128-bit identity fingerprint.
   *
   * Not what `/fingerprint` shows and not what a SAS compares — those stay on
   * the box key until step 4 moves them deliberately, with a migration. Two
   * fingerprints on screen before then would only teach people to compare the
   * wrong one.
   */
  get identityFingerprint() {
    return this.#identity.fingerprint;
  }

  get deviceId() {
    return this.#deviceId;
  }

  get listCounter() {
    return this.#listCounter;
  }

  /**
   * This device, as a device list names it.
   *
   * The label is empty and stays empty until there is a second device to tell
   * apart. A hostname would be the obvious filler and is exactly the kind of
   * thing this project does not put on a wire.
   */
  deviceDescriptor() {
    return {
      deviceId: this.#deviceId,
      boxPk: this.publicKeyB64,
      pqPk: this.pqPublicKeyB64,
      label: '',
      createdAt: this.#deviceCreatedAt,
    };
  }

  // The identity fingerprint stays X25519-only on purpose: it is what users
  // already verified out-of-band, and the KEM key adds no authentication.
  get pqPublicKey() {
    return this.#pqKeyPair.publicKey;
  }

  get pqPublicKeyB64() {
    return this.#pqKeyPair.publicKey.toString('base64');
  }

  get pqSecretKey() {
    return this.#pqKeyPair.secretKey;
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
   * Generate a new box keypair, keeping the old one for a grace period.
   *
   * The identity key and the device id are deliberately untouched. Rotating the
   * box key is a routine hygiene step; rotating an identity is a claim that you
   * are somebody new, and once device lists exist it would invalidate every one
   * of them. A device that rotates is the same device.
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
    // The descriptor just changed, so any list already out there describes a
    // key this device no longer uses. Without this the new list would carry the
    // old counter and every peer would discard it as not newer.
    this.#listCounter += 1;

    // Auto-destroy previous keys after grace period
    this.#graceTimer = setTimeout(() => {
      this.destroyPrevious();
      this.#graceTimer = null;
    }, KEY_ROTATION_GRACE_MS);
  }

  destroyPrevious() {
    if (this.#previousSecretKey) {
      sodium.sodium_free(this.#previousSecretKey);
    }
    this.#previousSecretKey = null;
    this.#previousPublicKey = null;
  }

  static computeFingerprint(publicKey) {
    const hash = createHash('sha256').update(publicKey).digest();
    const parts = [];
    for (let i = 0; i < 8; i += 2) {
      parts.push(
        hash
          .subarray(i, i + 2)
          .toString('hex')
          .toUpperCase(),
      );
    }
    return parts.join(':');
  }

  destroy() {
    if (this.#graceTimer) {
      clearTimeout(this.#graceTimer);
    }
    this.#identity?.destroy();
    this.#identity = null;
    this.destroyPrevious();
    if (this.#secretKey) {
      sodium.sodium_free(this.#secretKey);
    }
    this.#secretKey = null;
    this.#publicKey = null;
    this.#fingerprint = null;
  }

  serialize() {
    return {
      publicKey: this.#publicKey.toString('base64'),
      secretKey: this.#secretKey.toString('base64'),
      pqPublicKey: this.#pqKeyPair.publicKey.toString('base64'),
      pqSecretKey: this.#pqKeyPair.secretKey.toString('base64'),
      identity: this.#identity.serialize(),
      deviceId: this.#deviceId,
      deviceCreatedAt: this.#deviceCreatedAt,
      listCounter: this.#listCounter,
    };
  }

  static deserialize(data) {
    const km = new KeyManager(); // generates throwaway keys
    // sodium_free rather than memzero: the throwaway's pages are mlock'd, and
    // zeroing leaves them locked until a finaliser happens to run. One page is
    // harmless, but this is the pattern that aborted CI in 2.12.0 and it costs
    // nothing to get right.
    sodium.sodium_free(km.#secretKey);

    km.#publicKey = Buffer.from(data.publicKey, 'base64');
    const tempSec = Buffer.from(data.secretKey, 'base64');
    km.#secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
    tempSec.copy(km.#secretKey);
    sodium.sodium_memzero(tempSec);
    km.#fingerprint = KeyManager.computeFingerprint(km.#publicKey);
    km.#previousPublicKey = null;
    km.#previousSecretKey = null;
    // Restore the KEM pair when present; older backups simply get the fresh
    // one generated above (peers re-encapsulate on the next handshake).
    if (data.pqPublicKey && data.pqSecretKey) {
      km.#pqKeyPair = {
        publicKey: Buffer.from(data.pqPublicKey, 'base64'),
        secretKey: Buffer.from(data.pqSecretKey, 'base64'),
      };
    }
    // Same shape for the identity: a session or a backup written before this
    // existed simply keeps the fresh one generated above. Losing an identity
    // that nothing reads yet costs nothing; refusing to restore the session
    // would cost the user everything else in it.
    const identity = DeviceIdentity.deserialize(data.identity);
    if (identity) {
      km.#identity.destroy();
      km.#identity = identity;
    }
    if (typeof data.deviceId === 'string' && /^[0-9a-f]{32}$/.test(data.deviceId)) {
      km.#deviceId = data.deviceId;
      // Only meaningful alongside the id they belong to.
      if (Number.isSafeInteger(data.deviceCreatedAt) && data.deviceCreatedAt >= 0) {
        km.#deviceCreatedAt = data.deviceCreatedAt;
      }
      if (Number.isSafeInteger(data.listCounter) && data.listCounter >= 1) {
        km.#listCounter = data.listCounter;
      }
    }
    return km;
  }
}
