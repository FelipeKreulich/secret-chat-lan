/**
 * KeyManager, and the identity key it started carrying in step 2 of
 * multi-device (docs/design/multi-device.md, item 4 of #481).
 *
 * The identity key is read by nobody yet, which makes it exactly the kind of
 * thing that can be broken without anyone noticing: a serialize() that drops
 * it, a rotate() that replaces it, a restore that silently generates a new one.
 * Each of those is invisible today and expensive at step 4, when the value
 * becomes what a person has verified.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { KeyManager } from '../src/crypto/KeyManager.js';

describe('KeyManager — identity key', () => {
  it('carries an identity key and a device id from the start', () => {
    const km = new KeyManager();

    assert.match(km.identityFingerprint, /^([0-9A-F]{4}:){7}[0-9A-F]{4}$/, '128-bit fingerprint');
    assert.match(km.deviceId, /^[0-9a-f]{32}$/);
    assert.notEqual(
      km.identityPublicKeyB64,
      km.publicKeyB64,
      'the signing key is not the box key wearing a hat',
    );
    km.destroy();
  });

  it('gives two clients different identities', () => {
    const a = new KeyManager();
    const b = new KeyManager();

    assert.notEqual(a.identityPublicKeyB64, b.identityPublicKeyB64);
    assert.notEqual(a.deviceId, b.deviceId);
    a.destroy();
    b.destroy();
  });

  it('survives serialize/deserialize, identity and device id together', () => {
    const km = new KeyManager();
    const before = {
      identity: km.identityPublicKeyB64,
      fingerprint: km.identityFingerprint,
      deviceId: km.deviceId,
      box: km.publicKeyB64,
    };

    const restored = KeyManager.deserialize(km.serialize());

    assert.equal(restored.identityPublicKeyB64, before.identity);
    assert.equal(restored.identityFingerprint, before.fingerprint);
    assert.equal(restored.deviceId, before.deviceId);
    assert.equal(restored.publicKeyB64, before.box, 'the box key still round-trips too');

    km.destroy();
    restored.destroy();
  });

  it('restores a session written before identities existed', () => {
    // A state file or a backup from an older build has no identity in it.
    // Refusing it would cost the user everything else in the session to save a
    // value nothing reads yet.
    const km = new KeyManager();
    const old = km.serialize();
    delete old.identity;
    delete old.deviceId;

    const restored = KeyManager.deserialize(old);

    assert.equal(restored.publicKeyB64, km.publicKeyB64, 'the box key is what mattered');
    assert.match(restored.identityFingerprint, /^([0-9A-F]{4}:){7}/, 'a fresh identity is drawn');
    assert.match(restored.deviceId, /^[0-9a-f]{32}$/);

    km.destroy();
    restored.destroy();
  });

  it('ignores a device id that is not one', () => {
    const km = new KeyManager();
    for (const junk of ['', 'nothex', 'AB'.repeat(16), 42, null]) {
      const restored = KeyManager.deserialize({ ...km.serialize(), deviceId: junk });
      assert.match(restored.deviceId, /^[0-9a-f]{32}$/, `deviceId ${junk}`);
      assert.notEqual(restored.deviceId, junk);
      restored.destroy();
    }
    km.destroy();
  });

  it('keeps the identity across a box-key rotation', () => {
    // The one that would be easy to get wrong, and silently: rotating is
    // routine hygiene, but an identity that rotated with it would invalidate
    // every device list signed under the old one.
    const km = new KeyManager();
    const identity = km.identityPublicKeyB64;
    const deviceId = km.deviceId;
    const box = km.publicKeyB64;

    km.rotate();

    assert.notEqual(km.publicKeyB64, box, 'the box key did rotate');
    assert.equal(km.identityPublicKeyB64, identity, 'the identity did not');
    assert.equal(km.deviceId, deviceId, 'and neither did the device id');
    km.destroy();
  });

  it('moves the device-list counter when the descriptor changes', () => {
    // A rotation gives this device a new box key, so any list already published
    // describes a key it no longer uses. If the counter did not move, every peer
    // would discard the replacement as not newer and keep pointing at the old
    // key — silently, since a list nobody can supersede raises nothing.
    const km = new KeyManager();
    const before = km.deviceDescriptor();
    assert.equal(km.listCounter, 1);

    km.rotate();

    assert.equal(km.listCounter, 2);
    assert.notEqual(km.deviceDescriptor().boxPk, before.boxPk, 'the descriptor did change');
    assert.equal(km.deviceDescriptor().deviceId, before.deviceId, 'still the same device');
    assert.equal(km.deviceDescriptor().createdAt, before.createdAt);
    km.destroy();
  });

  it('never lets the counter go backwards across a restart', () => {
    const km = new KeyManager();
    km.rotate();
    km.rotate();
    assert.equal(km.listCounter, 3);

    const restored = KeyManager.deserialize(km.serialize());
    assert.equal(restored.listCounter, 3, 'a restart does not reset it');

    restored.rotate();
    assert.equal(restored.listCounter, 4);

    km.destroy();
    restored.destroy();
  });

  it('starts the counter at 1 for a session that predates it', () => {
    const km = new KeyManager();
    km.rotate();
    const old = km.serialize();
    delete old.listCounter;
    delete old.deviceCreatedAt;

    const restored = KeyManager.deserialize(old);
    assert.equal(restored.listCounter, 1);
    assert.match(restored.deviceId, /^[0-9a-f]{32}$/);

    km.destroy();
    restored.destroy();
  });

  it('signs with the identity it reports', () => {
    const km = new KeyManager();
    const restored = KeyManager.deserialize(km.serialize());

    const bytes = Buffer.from('a device list, one day');
    const signature = km.identity.sign(bytes);

    // The restored copy signs identically — Ed25519 is deterministic, so this
    // is the same key rather than merely a working one.
    assert.deepEqual(restored.identity.sign(bytes), signature);

    km.destroy();
    restored.destroy();
  });
});
