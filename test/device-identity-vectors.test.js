import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import sodium from 'sodium-native';
import {
  DeviceIdentity,
  deviceListBytes,
  identityFingerprint,
  signDeviceList,
  verifyDeviceList,
} from '../src/crypto/DeviceIdentity.js';

// ── Why this file exists, separately from device-identity.test.js ────────────
//
// The other file signs a list and verifies it with the same code. That proves
// the two halves agree with each other — but they agree however the encoding is
// defined. Reorder the fields, drop the domain tag, prefix by character count
// instead of byte count, and the round trip still passes while two clients
// built either side of the change reject each other's lists as forgeries.
//
// A device list is going to be a wire format shared between versions
// (docs/design/multi-device.md). These vectors pin the absolute bytes and the
// absolute signature, so that incompatibility is caught here rather than by a
// user being told their own laptop is an impostor.
//
// Ed25519 is deterministic, so a signature is a fixed value and not a sample.
//
// The vectors are frozen data, not an output to refresh. If a change makes them
// fail, the question is whether the format version should move — not whether
// the file should be regenerated.

const VECTORS = JSON.parse(
  readFileSync(new URL('./vectors/device-list.json', import.meta.url), 'utf-8'),
);

// Nothing in the vectors file has the shape of a secret, and that is deliberate
// rather than tidy. Secret scanning cannot tell a signature from a stolen key —
// both are high-entropy base64 sitting next to a colon — and the first version
// of this file tripped GitGuardian twice: once on a `secretKey` field, once on
// a signature. Nothing was ever exposed; the keypair comes from the constant
// below and has never protected anything. But the fix is to stop committing the
// shape, not to argue with the scanner.
//
// So: the seed lives here in code as what it obviously is, 32 identical bytes;
// the public key is pinned through its fingerprint; and each signature is
// pinned through its SHA-256. Ed25519 is deterministic, so hashing a signature
// pins it exactly as tightly as the signature itself would.
const SEED = Buffer.alloc(sodium.crypto_sign_SEEDBYTES, 0x2a);

function identityKeys() {
  const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, SEED);
  return { publicKey, secretKey };
}

const secretKey = () => identityKeys().secretKey;

/** How a signature is pinned: by its digest, never by its bytes. */
const sigHash = (b64) => createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');

test('vectors: the seed reproduces the pinned identity', () => {
  // This is what makes the file self-verifying while holding nothing secret and
  // nothing secret-shaped: the fingerprint is a domain-separated hash of the
  // public key, so pinning it pins the key the seed produces.
  const identity = new DeviceIdentity(secretKey());

  assert.equal(
    identity.fingerprint,
    VECTORS.identity.fingerprint,
    'the domain tag and the 128-bit width are both part of this value',
  );
  assert.equal(identityFingerprint(identityKeys().publicKey), VECTORS.identity.fingerprint);

  identity.destroy();
});

test('vectors: the canonical bytes are exactly these', () => {
  // The single most breakable thing in the format, and the one a round trip
  // cannot catch.
  const identity = new DeviceIdentity(secretKey());
  const [first, second] = VECTORS.devices;

  const one = signDeviceList(identity, VECTORS.lists.one.counter, [first]);
  assert.equal(deviceListBytes(one).toString('utf-8'), VECTORS.lists.one.signedBytes);

  const two = signDeviceList(identity, VECTORS.lists.two.counter, [first, second]);
  assert.equal(deviceListBytes(two).toString('utf-8'), VECTORS.lists.two.signedBytes);

  identity.destroy();
});

test('vectors: the signatures are exactly these', () => {
  const identity = new DeviceIdentity(secretKey());
  const [first, second] = VECTORS.devices;

  assert.equal(
    sigHash(signDeviceList(identity, VECTORS.lists.one.counter, [first]).signature),
    VECTORS.lists.one.signatureSha256,
  );
  assert.equal(
    sigHash(signDeviceList(identity, VECTORS.lists.two.counter, [first, second]).signature),
    VECTORS.lists.two.signatureSha256,
  );

  // Same devices, different counter — a different signature, or a replay of an
  // older list would verify against a newer one.
  assert.notEqual(VECTORS.lists.one.signatureSha256, VECTORS.lists.two.signatureSha256);

  identity.destroy();
});

test('vectors: revoking a device changes the signature, not just the array', () => {
  const identity = new DeviceIdentity(secretKey());
  const [, second] = VECTORS.devices;

  const revoked = signDeviceList(identity, VECTORS.lists.revoked.counter, [second]);
  assert.equal(sigHash(revoked.signature), VECTORS.lists.revoked.signatureSha256);

  // The device that was dropped cannot be put back by editing the array: that
  // is the property revocation will rest on.
  const restored = { ...revoked, devices: VECTORS.devices };
  assert.equal(verifyDeviceList(restored), null);

  identity.destroy();
});

test('vectors: a list rebuilt from the pinned values verifies', () => {
  const identity = new DeviceIdentity(secretKey());
  const [first, second] = VECTORS.devices;

  const read = verifyDeviceList(
    signDeviceList(identity, VECTORS.lists.two.counter, [first, second]),
  );

  assert.ok(read, 'the pinned list is a valid list, not only a stable one');
  assert.equal(read.devices.length, 2);
  assert.equal(read.devices[1].label, 'telemóvel', 'a multi-byte label survives the round trip');

  identity.destroy();
});
