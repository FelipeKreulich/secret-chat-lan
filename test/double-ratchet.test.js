import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import { DoubleRatchet } from '../src/crypto/DoubleRatchet.js';

function generateKeyPair() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

function createRatchetPair() {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  // "alice" < "bob" → alice is initiator
  const aliceRatchet = new DoubleRatchet('alice', 'bob', alice.secretKey, bob.publicKey);
  const bobRatchet = new DoubleRatchet('bob', 'alice', bob.secretKey, alice.publicKey);
  return { aliceRatchet, bobRatchet };
}

function encryptAndDecrypt(sender, receiver, text) {
  const result = sender.encrypt(text);
  const plaintext = receiver.decrypt(
    result.ciphertext,
    result.nonce,
    result.ephemeralPublicKey,
    result.counter,
    result.previousCounter,
  );
  assert.ok(plaintext, `Decryption failed for: ${text}`);
  return plaintext.toString('utf-8');
}

describe('DoubleRatchet', () => {
  it('basic encrypt/decrypt between initiator and responder', () => {
    const { aliceRatchet, bobRatchet } = createRatchetPair();

    const result = aliceRatchet.encrypt('Hello Bob');
    assert.equal(result.counter, 0);
    assert.ok(Buffer.isBuffer(result.ephemeralPublicKey));
    assert.equal(result.ephemeralPublicKey.length, 32);

    const plaintext = bobRatchet.decrypt(
      result.ciphertext,
      result.nonce,
      result.ephemeralPublicKey,
      result.counter,
      result.previousCounter,
    );

    assert.ok(plaintext);
    assert.equal(plaintext.toString('utf-8'), 'Hello Bob');

    aliceRatchet.destroy();
    bobRatchet.destroy();
  });

  it('multiple message exchange with alternating turns', () => {
    const { aliceRatchet, bobRatchet } = createRatchetPair();

    // Alice → Bob
    const msg1 = encryptAndDecrypt(aliceRatchet, bobRatchet, 'Message 1');
    assert.equal(msg1, 'Message 1');

    // Bob → Alice
    const msg2 = encryptAndDecrypt(bobRatchet, aliceRatchet, 'Message 2');
    assert.equal(msg2, 'Message 2');

    // Alice → Bob
    const msg3 = encryptAndDecrypt(aliceRatchet, bobRatchet, 'Message 3');
    assert.equal(msg3, 'Message 3');

    // Bob → Alice
    const msg4 = encryptAndDecrypt(bobRatchet, aliceRatchet, 'Message 4');
    assert.equal(msg4, 'Message 4');

    aliceRatchet.destroy();
    bobRatchet.destroy();
  });

  it('out-of-order messages using skipped keys', () => {
    const { aliceRatchet, bobRatchet } = createRatchetPair();

    // Alice sends 3 consecutive messages
    const r0 = aliceRatchet.encrypt('msg0');
    const r1 = aliceRatchet.encrypt('msg1');
    const r2 = aliceRatchet.encrypt('msg2');

    // Bob decrypts msg2 first (skipping 0 and 1)
    const p2 = bobRatchet.decrypt(
      r2.ciphertext, r2.nonce, r2.ephemeralPublicKey, r2.counter, r2.previousCounter,
    );
    assert.ok(p2);
    assert.equal(p2.toString('utf-8'), 'msg2');

    // Bob decrypts msg0 (from skipped keys)
    const p0 = bobRatchet.decrypt(
      r0.ciphertext, r0.nonce, r0.ephemeralPublicKey, r0.counter, r0.previousCounter,
    );
    assert.ok(p0);
    assert.equal(p0.toString('utf-8'), 'msg0');

    // Bob decrypts msg1 (from skipped keys)
    const p1 = bobRatchet.decrypt(
      r1.ciphertext, r1.nonce, r1.ephemeralPublicKey, r1.counter, r1.previousCounter,
    );
    assert.ok(p1);
    assert.equal(p1.toString('utf-8'), 'msg1');

    aliceRatchet.destroy();
    bobRatchet.destroy();
  });

  it('DH ratchet step generates new ephemeral keys each turn', () => {
    const { aliceRatchet, bobRatchet } = createRatchetPair();

    // Alice sends — note ephemeralPublicKey
    const r1 = aliceRatchet.encrypt('turn1');
    const eph1 = Buffer.from(r1.ephemeralPublicKey);

    bobRatchet.decrypt(
      r1.ciphertext, r1.nonce, r1.ephemeralPublicKey, r1.counter, r1.previousCounter,
    );

    // Bob sends — note Bob's ephemeral
    const r2 = bobRatchet.encrypt('turn2');
    aliceRatchet.decrypt(
      r2.ciphertext, r2.nonce, r2.ephemeralPublicKey, r2.counter, r2.previousCounter,
    );

    // Alice sends again — should have NEW ephemeral key
    const r3 = aliceRatchet.encrypt('turn3');
    const eph3 = Buffer.from(r3.ephemeralPublicKey);

    assert.ok(!eph1.equals(eph3), 'Ephemeral key should change after DH ratchet step');

    bobRatchet.decrypt(
      r3.ciphertext, r3.nonce, r3.ephemeralPublicKey, r3.counter, r3.previousCounter,
    );

    aliceRatchet.destroy();
    bobRatchet.destroy();
  });

  it('errors: encrypt before peer key and too many skips', () => {
    // Responder tries to encrypt before receiving (no peerEphPublicKey)
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    const bobRatchet = new DoubleRatchet('bob', 'alice', bob.secretKey, alice.publicKey);

    assert.throws(
      () => bobRatchet.encrypt('should fail'),
      /No peer ephemeral key yet/,
    );
    bobRatchet.destroy();

    // Too many skips (> RATCHET_MAX_SKIP = 100)
    const { aliceRatchet, bobRatchet: bobR } = createRatchetPair();

    // Alice sends 102 messages, bob only tries to decrypt the last one
    let lastResult;
    for (let i = 0; i < 102; i++) {
      lastResult = aliceRatchet.encrypt(`msg${i}`);
    }

    assert.throws(
      () => bobR.decrypt(
        lastResult.ciphertext,
        lastResult.nonce,
        lastResult.ephemeralPublicKey,
        lastResult.counter,
        lastResult.previousCounter,
      ),
      /Too many skipped messages/,
    );

    aliceRatchet.destroy();
    bobR.destroy();
  });
});
