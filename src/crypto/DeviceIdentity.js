import sodium from 'sodium-native';

// ── Device identity ─────────────────────────────────────────────
//
// Step 1 of multi-device (docs/design/multi-device.md, item 4 of #481). This
// module has no callers on purpose. The sender-key rollout worked because the
// asymmetric half landed before the wire that carries it existed — "it cost a
// field on a wire nobody was using yet" — and the same trick applies here.
//
// The model, in one paragraph. Today the X25519 box key *is* the identity: it
// is what a fingerprint is computed from, what a SAS compares, and what a ban
// keys on. That works for one machine and breaks for two, because two machines
// can only share it by sharing the secret — which is what `/backup` plus the
// restore prompt actually does today, and it cannot be revoked. So identity
// moves up a level: a long-term **Ed25519 key that only ever signs**, and one
// **X25519 box key per device**, listed and signed by it. A device is added by
// signing a longer list; revoked by signing a shorter one with a higher
// counter.
//
// Nothing here encrypts. That separation is the point: a signing key that never
// touches a message is a key that can be kept somewhere a message key cannot.

const DEVICE_ID_SIZE = 16;
const MAX_DEVICES = 8;
const MAX_LABEL_LENGTH = 32;

// Domain separation. Two different structures must never produce the same
// bytes to sign, or a signature over one is a signature over the other.
const LIST_DOMAIN = 'CipherMesh-DeviceList-v1';
const FINGERPRINT_DOMAIN = 'CipherMesh-IdentityFingerprint-v1';

// Release a key allocated with sodium_malloc.
//
// Same reasoning as SenderKey.js: sodium_malloc'd pages are mlock'd, the OS
// caps how much a process may lock, and zeroing alone leaves them locked until
// a finaliser happens to run. sodium_free zeroes before releasing.
function freeKey(buf) {
  if (buf) {
    sodium.sodium_free(buf);
  }
}

/**
 * A stable name for one device, drawn once and kept.
 *
 * Deliberately *not* derived from the device's box key. A box key rotates
 * (`KeyManager.rotate`) and the device is still the same device; an id derived
 * from the key would rename it on every rotation, which is precisely when a
 * peer most needs to recognise it. Forging an id buys nothing on its own —
 * only a list signed by the identity key binds an id to a key.
 */
export function newDeviceId() {
  const buf = Buffer.alloc(DEVICE_ID_SIZE);
  sodium.randombytes_buf(buf);
  return buf.toString('hex');
}

/**
 * The long-term signing key. Signs device lists; never encrypts anything.
 */
export class DeviceIdentity {
  #publicKey;
  #secretKey;

  constructor(secretKey = null) {
    this.#publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
    this.#secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES);

    if (secretKey) {
      // An Ed25519 secret key carries its public half in the last 32 bytes, so
      // restoring one cannot disagree with the public key it is paired with.
      secretKey.copy(this.#secretKey);
      this.#secretKey
        .subarray(sodium.crypto_sign_SECRETKEYBYTES - sodium.crypto_sign_PUBLICKEYBYTES)
        .copy(this.#publicKey);
    } else {
      sodium.crypto_sign_keypair(this.#publicKey, this.#secretKey);
    }
  }

  get publicKey() {
    return this.#publicKey;
  }

  get publicKeyB64() {
    return this.#publicKey.toString('base64');
  }

  get fingerprint() {
    return identityFingerprint(this.#publicKey);
  }

  /** Detached signature over arbitrary bytes. */
  sign(bytes) {
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES);
    sodium.crypto_sign_detached(signature, bytes, this.#secretKey);
    return signature;
  }

  serialize() {
    return { secretKey: this.#secretKey.toString('base64') };
  }

  static deserialize(data) {
    const secretKey = decodeKey(data?.secretKey, sodium.crypto_sign_SECRETKEYBYTES);
    return secretKey ? new DeviceIdentity(secretKey) : null;
  }

  destroy() {
    freeKey(this.#secretKey);
    this.#secretKey = null;
    this.#publicKey = null;
  }
}

/**
 * The identity fingerprint, as a human compares it.
 *
 * 128 bits, not the 32 the box-key fingerprint uses. That difference is
 * deliberate: `KeyManager.computeFingerprint` is a display aid sitting next to
 * a 40-bit SAS that does the real work, whereas the plan (step 4) is for *this*
 * value to become what a person verifies. `computeSAS` already carries a note
 * that 20 bits was grindable offline; 32 is not enough to inherit that job.
 */
export function identityFingerprint(publicKey) {
  const key = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, 'base64');
  const hash = Buffer.alloc(32);
  sodium.crypto_generichash(hash, Buffer.concat([Buffer.from(FINGERPRINT_DOMAIN), key]));

  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(
      hash
        .subarray(i, i + 2)
        .toString('hex')
        .toUpperCase(),
    );
  }
  return parts.join(':');
}

function decodeKey(b64, size) {
  if (typeof b64 !== 'string') {
    return null;
  }
  let buf;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch {
    return null;
  }
  return buf.length === size ? buf : null;
}

// Length-prefixed on the *byte* count, so a label with a multi-byte character
// cannot make two different lists serialise the same way. The separator is
// cosmetic — the prefixes are what make the encoding injective.
const lp = (value) => `${Buffer.byteLength(String(value), 'utf-8')}:${value}`;

/**
 * What the signature covers.
 *
 * Everything a relay or a peer could tamper with: which identity the list
 * belongs to, its position in the sequence, how many devices it names, and
 * every field of every device. The count is in there so devices cannot be
 * dropped from the end without breaking the signature.
 *
 * The ML-KEM key is deliberately *not* in a descriptor. A list is a set of
 * claims about identity, and a KEM key is not one — it is transport material,
 * already advertised per session in JOIN, and a device could change it without
 * changing who it is. Carrying it here also cost 1584 bytes of base64 per
 * device, which is the difference between a provisioning grant that fits in a
 * QR code and one that does not.
 */
export function deviceListBytes({ identityPk, counter, devices }) {
  const parts = [LIST_DOMAIN, identityPk, String(counter), String(devices.length)];
  for (const device of devices) {
    parts.push(device.deviceId, device.boxPk, device.label, String(device.createdAt));
  }
  return Buffer.from(parts.map(lp).join('|'), 'utf-8');
}

/**
 * Sign a set of devices as the current list for this identity.
 *
 * `counter` is the caller's responsibility and must only ever go up — see
 * `isNewerList`. A list is a statement about *now*, so adding a device and
 * revoking one are the same operation with a different array.
 */
export function signDeviceList(identity, counter, devices) {
  const list = {
    identityPk: identity.publicKeyB64,
    counter,
    devices: devices.map(normaliseDevice),
  };
  const signature = identity.sign(deviceListBytes(list));
  return { ...list, signature: signature.toString('base64') };
}

function normaliseDevice(device) {
  return {
    deviceId: device.deviceId,
    boxPk: device.boxPk,
    label: device.label ?? '',
    createdAt: device.createdAt,
  };
}

/**
 * Read a device list that arrived from somewhere else.
 *
 * Returns the normalised list, or `null`. Never throws and never partially
 * accepts: a list is one signed statement, so half of it is not usable and
 * "the good devices out of a bad list" is exactly the shape of bug the
 * capability validator was written to avoid.
 *
 * The signature is checked *last*, after the structure, because verifying a
 * signature over a shape we would reject anyway is work an unauthenticated
 * peer gets to ask for.
 */
export function verifyDeviceList(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    return null;
  }

  const identityKey = decodeKey(envelope.identityPk, sodium.crypto_sign_PUBLICKEYBYTES);
  const signature = decodeKey(envelope.signature, sodium.crypto_sign_BYTES);
  if (!identityKey || !signature) {
    return null;
  }

  if (!Number.isSafeInteger(envelope.counter) || envelope.counter < 0) {
    return null;
  }

  if (!Array.isArray(envelope.devices) || envelope.devices.length === 0) {
    return null;
  }
  if (envelope.devices.length > MAX_DEVICES) {
    return null;
  }

  const devices = [];
  const ids = new Set();
  const boxKeys = new Set();

  for (const device of envelope.devices) {
    if (!device || typeof device !== 'object') {
      return null;
    }
    if (typeof device.deviceId !== 'string' || !/^[0-9a-f]{32}$/.test(device.deviceId)) {
      return null;
    }
    if (!decodeKey(device.boxPk, sodium.crypto_box_PUBLICKEYBYTES)) {
      return null;
    }
    if (typeof device.label !== 'string' || device.label.length > MAX_LABEL_LENGTH) {
      return null;
    }
    if (!Number.isSafeInteger(device.createdAt) || device.createdAt < 0) {
      return null;
    }

    // Two entries naming one device, or one key under two device ids, would
    // make "which device is this" ambiguous for every reader.
    if (ids.has(device.deviceId) || boxKeys.has(device.boxPk)) {
      return null;
    }
    ids.add(device.deviceId);
    boxKeys.add(device.boxPk);

    devices.push(normaliseDevice(device));
  }

  const list = { identityPk: envelope.identityPk, counter: envelope.counter, devices };
  if (!sodium.crypto_sign_verify_detached(signature, deviceListBytes(list), identityKey)) {
    return null;
  }

  return { ...list, signature: envelope.signature };
}

/**
 * Should `candidate` replace `held`?
 *
 * Highest counter wins, and it is enforced here — on receipt — rather than
 * trusted from the sender. Without it, a relay that kept a copy of an older
 * list could replay it to put a revoked device back.
 *
 * A candidate for a different identity is never newer; it is a different
 * question, and answering it here would let one identity's list displace
 * another's.
 */
export function isNewerList(candidate, held) {
  if (!candidate) {
    return false;
  }
  if (!held) {
    return true;
  }
  if (candidate.identityPk !== held.identityPk) {
    return false;
  }
  return candidate.counter > held.counter;
}

export const DEVICE_LIMITS = { MAX_DEVICES, MAX_LABEL_LENGTH, DEVICE_ID_SIZE };
