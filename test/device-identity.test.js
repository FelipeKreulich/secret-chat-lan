/**
 * Device identity — step 1 of multi-device (item 4 of #481).
 *
 * `src/crypto/DeviceIdentity.js` has no callers yet, which is the whole idea:
 * the sender-key rollout worked because the asymmetric half landed while the
 * wire that carries it was still free. So this file is the only thing holding
 * the module to its promises, and the promises worth holding it to are the
 * adversarial ones — a device list is a signed statement that will one day
 * arrive from a stranger through a relay that would like to edit it.
 *
 * The absolute values live in device-identity-vectors.test.js. Everything here
 * is about what must be *rejected*.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import {
  DeviceIdentity,
  DEVICE_LIMITS,
  deviceListBytes,
  identityFingerprint,
  isNewerList,
  newDeviceId,
  signDeviceList,
  verifyDeviceList,
} from '../src/crypto/DeviceIdentity.js';

const boxKey = (fill) => Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES, fill).toString('base64');

const device = (fill, over = {}) => ({
  deviceId: newDeviceId(),
  boxPk: boxKey(fill),
  label: `device-${fill}`,
  createdAt: 1755000000000 + fill,
  ...over,
});

/** A signed list, plus the identity that signed it, cleaned up by the caller. */
function signed(devices, counter = 1) {
  const identity = new DeviceIdentity();
  const list = signDeviceList(identity, counter, devices);
  return { identity, list };
}

// ── The identity key ────────────────────────────────────────────────────────

describe('DeviceIdentity', () => {
  it('survives a round trip through serialize/deserialize', () => {
    const identity = new DeviceIdentity();
    const restored = DeviceIdentity.deserialize(identity.serialize());

    assert.equal(restored.publicKeyB64, identity.publicKeyB64);
    assert.equal(restored.fingerprint, identity.fingerprint);

    identity.destroy();
    restored.destroy();
  });

  it('recovers the public key from the secret rather than being told it', () => {
    // An Ed25519 secret key carries its public half. Taking it from there means
    // a restored identity cannot be handed a public key that does not match.
    const identity = new DeviceIdentity();
    const restored = DeviceIdentity.deserialize({
      secretKey: identity.serialize().secretKey,
      publicKey: Buffer.alloc(32, 0xff).toString('base64'), // ignored
    });

    assert.equal(restored.publicKeyB64, identity.publicKeyB64);
    identity.destroy();
    restored.destroy();
  });

  it('refuses to deserialize anything that is not a secret key', () => {
    for (const junk of [undefined, null, {}]) {
      assert.equal(DeviceIdentity.deserialize(junk), null, `${JSON.stringify(junk)}`);
    }

    const wrong = [
      null,
      42,
      '',
      'not base64 at all!!',
      Buffer.alloc(32).toString('base64'), // right shape, wrong size
    ];
    for (const value of wrong) {
      assert.equal(DeviceIdentity.deserialize({ secretKey: value }), null, `${value}`);
    }
  });

  it('gives a 128-bit fingerprint, not the 32 the box key uses', () => {
    const identity = new DeviceIdentity();
    const parts = identity.fingerprint.split(':');

    assert.equal(parts.length, 8, 'eight groups of two bytes');
    assert.ok(
      parts.every((p) => /^[0-9A-F]{4}$/.test(p)),
      'uppercase hex, four characters each',
    );
    identity.destroy();
  });

  it('separates the fingerprint domain from the raw key', () => {
    // Not a hash of the key alone: a value that appears in two protocols with
    // two meanings is a value one of them can be tricked into accepting.
    const identity = new DeviceIdentity();
    const plain = Buffer.alloc(32);
    sodium.crypto_generichash(plain, identity.publicKey);

    assert.notEqual(
      identityFingerprint(identity.publicKey).replace(/:/g, ''),
      plain.toString('hex').slice(0, 32).toUpperCase(),
    );
    identity.destroy();
  });

  it('takes the public key as base64 or as a buffer, identically', () => {
    const identity = new DeviceIdentity();
    assert.equal(
      identityFingerprint(identity.publicKeyB64),
      identityFingerprint(identity.publicKey),
    );
    identity.destroy();
  });
});

// ── Signing and reading a list ──────────────────────────────────────────────

describe('device list', () => {
  it('verifies a list it just signed', () => {
    const { identity, list } = signed([device(1), device(2)]);
    const read = verifyDeviceList(list);

    assert.ok(read, 'a well-formed list verifies');
    assert.equal(read.counter, 1);
    assert.equal(read.devices.length, 2);
    assert.equal(read.identityPk, identity.publicKeyB64);
    identity.destroy();
  });

  it('ignores an ML-KEM key offered in a descriptor', () => {
    // Not part of a device list. It is transport material, already advertised
    // per session in JOIN, and a device could change it without changing who it
    // is — so it is normalised away rather than signed over.
    const { identity, list } = signed([device(1, { pqPk: 'AQID' })]);
    const read = verifyDeviceList(list);

    assert.equal(read.devices[0].pqPk, undefined);
    identity.destroy();
  });

  it('rejects a list signed by a different identity', () => {
    const { identity, list } = signed([device(1)]);
    const other = new DeviceIdentity();

    // Claiming somebody else's identity does not survive the signature check.
    assert.equal(verifyDeviceList({ ...list, identityPk: other.publicKeyB64 }), null);

    identity.destroy();
    other.destroy();
  });

  it('rejects a tampered field, whichever one it is', () => {
    const { identity, list } = signed([device(1), device(2)], 4);

    const mutations = {
      counter: (l) => ({ ...l, counter: l.counter + 1 }),
      label: (l) => patch(l, 0, { label: 'somebody else' }),
      boxPk: (l) => patch(l, 0, { boxPk: boxKey(9) }),
      deviceId: (l) => patch(l, 0, { deviceId: newDeviceId() }),
      createdAt: (l) => patch(l, 0, { createdAt: 1 }),
      signature: (l) => ({ ...l, signature: Buffer.alloc(64, 3).toString('base64') }),
    };

    for (const [field, mutate] of Object.entries(mutations)) {
      assert.equal(
        verifyDeviceList(mutate(clone(list))),
        null,
        `tampered ${field} must not verify`,
      );
    }
    identity.destroy();
  });

  it('rejects a device dropped off the end', () => {
    // This is why the device count is inside the signed bytes. Without it,
    // truncating the list would be a silent way to hide a device — or, once
    // revocation exists, to hide that one was added back.
    const { identity, list } = signed([device(1), device(2), device(3)]);
    const truncated = clone(list);
    truncated.devices.pop();

    assert.equal(verifyDeviceList(truncated), null);
    identity.destroy();
  });

  it('rejects a reordered list', () => {
    const { identity, list } = signed([device(1), device(2)]);
    const swapped = clone(list);
    swapped.devices.reverse();

    assert.equal(verifyDeviceList(swapped), null);
    identity.destroy();
  });

  it('rejects a device appended by somebody else', () => {
    const { identity, list } = signed([device(1)]);
    const extended = clone(list);
    extended.devices.push(device(2));

    assert.equal(verifyDeviceList(extended), null, 'adding a device needs the identity key');
    identity.destroy();
  });
});

// ── Structural rejection, before the signature is even checked ──────────────

describe('device list — malformed input', () => {
  it('rejects anything that is not an object', () => {
    for (const junk of [undefined, null, 'a list', 42, []]) {
      assert.equal(verifyDeviceList(junk), null, `${JSON.stringify(junk)}`);
    }
  });

  it('rejects an empty device list', () => {
    // An identity with no devices is not a state anything should act on: it
    // would mean "this person is reachable at zero keys", which reads as a
    // successful delivery to nobody.
    const { identity, list } = signed([device(1)]);
    assert.equal(verifyDeviceList({ ...clone(list), devices: [] }), null);
    identity.destroy();
  });

  it('rejects more devices than the limit allows', () => {
    const many = Array.from({ length: DEVICE_LIMITS.MAX_DEVICES + 1 }, (_, i) => device(i));
    const { identity, list } = signed(many);

    assert.equal(verifyDeviceList(list), null, 'a correctly signed list is still too long');
    identity.destroy();
  });

  it('rejects two entries naming the same device', () => {
    const id = newDeviceId();
    const { identity, list } = signed([device(1, { deviceId: id }), device(2, { deviceId: id })]);

    assert.equal(verifyDeviceList(list), null);
    identity.destroy();
  });

  it('rejects one key claimed by two devices', () => {
    const key = boxKey(1);
    const { identity, list } = signed([device(1, { boxPk: key }), device(2, { boxPk: key })]);

    assert.equal(verifyDeviceList(list), null, 'which device is this becomes unanswerable');
    identity.destroy();
  });

  it('rejects a bad counter', () => {
    const { identity, list } = signed([device(1)]);
    for (const counter of [-1, 1.5, NaN, Infinity, '2', null, undefined]) {
      assert.equal(verifyDeviceList({ ...clone(list), counter }), null, `counter ${counter}`);
    }
    identity.destroy();
  });

  it('rejects a malformed device id or an oversized label', () => {
    const { identity, list } = signed([device(1)]);

    for (const deviceId of ['', 'nothex', 'AABB'.repeat(8), 'aabb', 42, null]) {
      assert.equal(verifyDeviceList(patch(clone(list), 0, { deviceId })), null, `id ${deviceId}`);
    }
    const long = 'x'.repeat(DEVICE_LIMITS.MAX_LABEL_LENGTH + 1);
    assert.equal(verifyDeviceList(patch(clone(list), 0, { label: long })), null, 'long label');
    assert.equal(verifyDeviceList(patch(clone(list), 0, { label: 42 })), null, 'non-string label');
    identity.destroy();
  });

  it('rejects a box key of the wrong size', () => {
    const { identity, list } = signed([device(1)]);
    const short = Buffer.alloc(16, 1).toString('base64');

    assert.equal(verifyDeviceList(patch(clone(list), 0, { boxPk: short })), null);
    identity.destroy();
  });
});

// ── The encoding itself ─────────────────────────────────────────────────────

describe('deviceListBytes', () => {
  it('cannot be confused by a label containing the separators', () => {
    // The prefixes are what make the encoding injective; the `|` and `:` are
    // cosmetic. A label that contains both must not be able to impersonate a
    // field boundary.
    const base = { identityPk: 'IDENTITY', counter: 1 };
    const a = deviceListBytes({
      ...base,
      devices: [{ deviceId: 'a', boxPk: 'B', label: 'x|3:y', createdAt: 1 }],
    });
    const b = deviceListBytes({
      ...base,
      devices: [{ deviceId: 'a', boxPk: 'B', label: 'x', createdAt: 1 }],
    });

    assert.notEqual(a.toString('utf-8'), b.toString('utf-8'));
  });

  it('counts label length in bytes, not in characters', () => {
    // 'é' is one character and two bytes. Prefixing with the character count
    // would let a multi-byte label shift a field boundary.
    const bytes = deviceListBytes({
      identityPk: 'I',
      counter: 0,
      devices: [{ deviceId: 'd', boxPk: 'b', label: 'é', createdAt: 0 }],
    }).toString('utf-8');

    assert.ok(bytes.includes('2:é'), `expected a byte-length prefix, got: ${bytes}`);
  });

  it('distinguishes a missing ML-KEM key from an empty one', () => {
    const make = (pqPk) =>
      deviceListBytes({
        identityPk: 'I',
        counter: 0,
        devices: [{ deviceId: 'd', boxPk: 'b', pqPk, label: '', createdAt: 0 }],
      }).toString('utf-8');

    // Both serialise to an empty field, which is fine — they mean the same
    // thing — but this pins that they are treated as the same thing rather
    // than accidentally differing.
    assert.equal(make(null), make(''));
  });
});

// ── Replay ──────────────────────────────────────────────────────────────────

describe('isNewerList', () => {
  const list = (identityPk, counter) => ({ identityPk, counter });

  it('accepts the first list it is ever shown', () => {
    assert.equal(isNewerList(list('A', 0), null), true);
  });

  it('takes a higher counter and refuses a lower or equal one', () => {
    assert.equal(isNewerList(list('A', 5), list('A', 4)), true);
    assert.equal(isNewerList(list('A', 4), list('A', 4)), false, 'equal is not newer');
    assert.equal(isNewerList(list('A', 3), list('A', 4)), false, 'a replayed older list');
  });

  it('never lets one identity displace another', () => {
    // Otherwise a peer could hand over a list for their own identity with a
    // huge counter and evict somebody else's devices.
    assert.equal(isNewerList(list('B', 999), list('A', 1)), false);
  });

  it('treats nothing as not newer', () => {
    assert.equal(isNewerList(null, list('A', 1)), false);
  });
});

// ── helpers ─────────────────────────────────────────────────────────────────

function clone(list) {
  return JSON.parse(JSON.stringify(list));
}

function patch(list, index, fields) {
  list.devices[index] = { ...list.devices[index], ...fields };
  return list;
}
