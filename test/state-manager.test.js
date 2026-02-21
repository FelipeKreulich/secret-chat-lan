import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import sodium from 'sodium-native';
import { StateManager } from '../src/crypto/StateManager.js';
import { DoubleRatchet } from '../src/crypto/DoubleRatchet.js';
import { KeyManager } from '../src/crypto/KeyManager.js';

function generateKeyPair() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

describe('StateManager', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'statemanager-test-'));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('deriveKEK produces same key with same passphrase and salt', () => {
    const sm = new StateManager(tempDir);
    const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
    sodium.randombytes_buf(salt);

    const { kek: kek1 } = sm.deriveKEK('test-password', salt);
    const { kek: kek2 } = sm.deriveKEK('test-password', salt);

    assert.ok(Buffer.from(kek1).equals(Buffer.from(kek2)));

    sodium.sodium_memzero(kek1);
    sodium.sodium_memzero(kek2);
  });

  it('saveState and loadState round-trip', () => {
    const sm = new StateManager(tempDir);
    const data = { key: 'value', num: 42, nested: { arr: [1, 2, 3] } };

    const { kek, salt } = sm.deriveKEK('mypassword');
    sm.saveState(data, kek, salt);
    sodium.sodium_memzero(kek);

    const loaded = sm.loadState('mypassword');
    assert.deepEqual(loaded, data);
  });

  it('loadState returns null with wrong passphrase', () => {
    const sm = new StateManager(tempDir);
    const { kek, salt } = sm.deriveKEK('correct');
    sm.saveState({ secret: true }, kek, salt);
    sodium.sodium_memzero(kek);

    const result = sm.loadState('wrong');
    assert.equal(result, null);
  });

  it('hasState and clearState work correctly', () => {
    const sm = new StateManager(tempDir);
    assert.equal(sm.hasState(), false);

    const { kek, salt } = sm.deriveKEK('pass');
    sm.saveState({ x: 1 }, kek, salt);
    sodium.sodium_memzero(kek);

    assert.equal(sm.hasState(), true);

    sm.clearState();
    assert.equal(sm.hasState(), false);
  });
});

describe('DoubleRatchet serialization', () => {
  it('serialize/deserialize preserves ratchet state', () => {
    const alice = generateKeyPair();
    const bob = generateKeyPair();

    const aliceRatchet = new DoubleRatchet('alice', 'bob', alice.secretKey, bob.publicKey);
    const bobRatchet = new DoubleRatchet('bob', 'alice', bob.secretKey, alice.publicKey);

    // Exchange a few messages to advance ratchet state
    const r1 = aliceRatchet.encrypt('msg1');
    bobRatchet.decrypt(r1.ciphertext, r1.nonce, r1.ephemeralPublicKey, r1.counter, r1.previousCounter);

    const r2 = bobRatchet.encrypt('msg2');
    aliceRatchet.decrypt(r2.ciphertext, r2.nonce, r2.ephemeralPublicKey, r2.counter, r2.previousCounter);

    // Serialize Alice's ratchet
    const serialized = aliceRatchet.serialize();
    assert.ok(serialized.rootKey);
    assert.equal(typeof serialized.sendCounter, 'number');
    assert.equal(serialized.initialized, true);

    // Deserialize into a new ratchet
    const restored = DoubleRatchet.deserialize(serialized);

    // Send a message from the restored ratchet
    const r3 = restored.encrypt('msg3');
    const p3 = bobRatchet.decrypt(
      r3.ciphertext, r3.nonce, r3.ephemeralPublicKey, r3.counter, r3.previousCounter,
    );

    assert.ok(p3);
    assert.equal(p3.toString('utf-8'), 'msg3');

    aliceRatchet.destroy();
    bobRatchet.destroy();
    restored.destroy();
  });
});

describe('KeyManager serialization', () => {
  it('serialize/deserialize preserves keys and fingerprint', () => {
    const km = new KeyManager();
    const originalFp = km.fingerprint;
    const originalPubB64 = km.publicKeyB64;

    const serialized = km.serialize();
    const restored = KeyManager.deserialize(serialized);

    assert.equal(restored.fingerprint, originalFp);
    assert.equal(restored.publicKeyB64, originalPubB64);

    km.destroy();
    restored.destroy();
  });
});
