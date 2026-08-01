import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import {
  generatePQKeyPair,
  pqEncapsulate,
  pqDecapsulate,
  mixPQIntoRoot,
  PQ_PUBLIC_KEY_SIZE,
  PQ_CIPHERTEXT_SIZE,
  PQ_SHARED_SECRET_SIZE,
} from '../src/crypto/PQHybrid.js';
import { DoubleRatchet } from '../src/crypto/DoubleRatchet.js';
import { KeyManager } from '../src/crypto/KeyManager.js';

function classicPair() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

describe('PQHybrid — ML-KEM-768 primitives', () => {
  it('encapsulate/decapsulate agree on a 32-byte secret', () => {
    const kp = generatePQKeyPair();
    assert.equal(kp.publicKey.length, PQ_PUBLIC_KEY_SIZE);

    const enc = pqEncapsulate(kp.publicKey);
    assert.equal(enc.ciphertext.length, PQ_CIPHERTEXT_SIZE);
    assert.equal(enc.sharedSecret.length, PQ_SHARED_SECRET_SIZE);

    const ss = pqDecapsulate(enc.ciphertext, kp.secretKey);
    assert.deepEqual(ss, enc.sharedSecret);
  });

  it('accepts base64 input and rejects malformed input without throwing', () => {
    const kp = generatePQKeyPair();
    assert.ok(pqEncapsulate(kp.publicKey.toString('base64')), 'base64 public key works');

    assert.equal(pqEncapsulate(Buffer.alloc(10)), null);
    assert.equal(pqEncapsulate('not base64 at all!!'), null);
    assert.equal(pqDecapsulate(Buffer.alloc(10), kp.secretKey), null);
    assert.equal(pqDecapsulate(Buffer.alloc(PQ_CIPHERTEXT_SIZE), null), null);
  });

  it('a ciphertext for another key yields a different secret (fails closed)', () => {
    const a = generatePQKeyPair();
    const b = generatePQKeyPair();
    const enc = pqEncapsulate(a.publicKey);
    // ML-KEM is designed to return a pseudorandom secret rather than error.
    const wrong = pqDecapsulate(enc.ciphertext, b.secretKey);
    assert.ok(wrong === null || !wrong.equals(enc.sharedSecret), 'wrong key never recovers it');
  });

  it('mixPQIntoRoot binds both inputs and is deterministic', () => {
    const root = Buffer.alloc(32, 1);
    const ss = Buffer.alloc(32, 2);
    const mixed = Buffer.from(mixPQIntoRoot(root, ss));

    assert.deepEqual(Buffer.from(mixPQIntoRoot(root, ss)), mixed, 'deterministic');
    assert.notDeepEqual(mixed, root, 'root actually changes');
    assert.notDeepEqual(
      Buffer.from(mixPQIntoRoot(Buffer.alloc(32, 9), ss)),
      mixed,
      'different root → different result',
    );
    assert.notDeepEqual(
      Buffer.from(mixPQIntoRoot(root, Buffer.alloc(32, 9))),
      mixed,
      'different secret → different result',
    );
  });
});

describe('DoubleRatchet — hybrid handshake', () => {
  const hybridPair = () => {
    const A = classicPair();
    const B = classicPair();
    const pqA = generatePQKeyPair();
    const pqB = generatePQKeyPair();
    // 'a' < 'b' → A is the initiator and encapsulates at construction.
    const ra = new DoubleRatchet('a', 'b', A.secretKey, B.publicKey, {
      peerPublicKey: pqB.publicKey,
      mySecretKey: pqA.secretKey,
    });
    const rb = new DoubleRatchet('b', 'a', B.secretKey, A.publicKey, {
      peerPublicKey: pqA.publicKey,
      mySecretKey: pqB.secretKey,
    });
    return { ra, rb };
  };

  const pass = (from, to, text) => {
    const e = from.encrypt(text);
    const out = to.decrypt(
      e.ciphertext,
      e.nonce,
      e.ephemeralPublicKey,
      e.counter,
      e.previousCounter,
      e.pqCiphertext,
    );
    return { envelope: e, plaintext: out?.toString('utf-8') };
  };

  it('initiator mixes at construction; responder mixes on first receive', () => {
    const { ra, rb } = hybridPair();
    assert.equal(ra.isHybrid, true, 'initiator is hybrid immediately');
    assert.equal(rb.isHybrid, false, 'responder not yet');

    const first = pass(ra, rb, 'olá pós-quântico');
    assert.equal(first.envelope.pqCiphertext.length, PQ_CIPHERTEXT_SIZE);
    assert.equal(first.plaintext, 'olá pós-quântico');
    assert.equal(rb.isHybrid, true, 'responder folded the KEM secret in');
  });

  it('conversation flows both ways and stops advertising the ciphertext', () => {
    const { ra, rb } = hybridPair();
    assert.equal(pass(ra, rb, 'um').plaintext, 'um');
    assert.equal(pass(rb, ra, 'dois').plaintext, 'dois');

    const third = pass(ra, rb, 'três');
    assert.equal(third.plaintext, 'três');
    assert.ok(!third.envelope.pqCiphertext, 'ciphertext dropped once the peer replied');

    assert.equal(pass(rb, ra, 'quatro').plaintext, 'quatro');
  });

  it('classical peers still work (no PQ material anywhere)', () => {
    const A = classicPair();
    const B = classicPair();
    const ra = new DoubleRatchet('a', 'b', A.secretKey, B.publicKey);
    const rb = new DoubleRatchet('b', 'a', B.secretKey, A.publicKey);

    assert.equal(ra.isHybrid, false);
    assert.equal(pass(ra, rb, 'clássico').plaintext, 'clássico');
    assert.equal(pass(rb, ra, 'de volta').plaintext, 'de volta');
  });

  it('mixed generations interoperate: PQ initiator ↔ classical responder', () => {
    const A = classicPair();
    const B = classicPair();
    const pqA = generatePQKeyPair();

    // A knows nothing about B's KEM key (old peer) → stays classical.
    const ra = new DoubleRatchet('a', 'b', A.secretKey, B.publicKey, {
      peerPublicKey: null,
      mySecretKey: pqA.secretKey,
    });
    const rb = new DoubleRatchet('b', 'a', B.secretKey, A.publicKey);

    assert.equal(ra.isHybrid, false, 'no peer KEM key → classical');
    assert.equal(pass(ra, rb, 'compat').plaintext, 'compat');
    assert.equal(pass(rb, ra, 'ok').plaintext, 'ok');
  });

  it('an old client ignoring the ciphertext cannot read a hybrid message', () => {
    const { ra, rb } = hybridPair();
    const e = ra.encrypt('segredo híbrido');
    // Same envelope, but the KEM ciphertext is dropped (pre-v3 client).
    const out = rb.decrypt(
      e.ciphertext,
      e.nonce,
      e.ephemeralPublicKey,
      e.counter,
      e.previousCounter,
    );
    assert.equal(out, null, 'roots differ → fails closed, never garbles');
  });

  it('hybrid state survives serialization without double-mixing', () => {
    const { ra, rb } = hybridPair();
    pass(ra, rb, 'antes');

    const restored = DoubleRatchet.deserialize(JSON.parse(JSON.stringify(rb.serialize())));
    assert.equal(restored.isHybrid, true, 'pqApplied persisted');

    const e = ra.encrypt('depois');
    const out = restored.decrypt(
      e.ciphertext,
      e.nonce,
      e.ephemeralPublicKey,
      e.counter,
      e.previousCounter,
      e.pqCiphertext,
    );
    assert.equal(out?.toString('utf-8'), 'depois', 'restored ratchet keeps decrypting');
  });
});

describe('KeyManager — KEM keypair', () => {
  it('exposes an ML-KEM key and round-trips it through serialization', () => {
    const km = new KeyManager();
    assert.equal(km.pqPublicKey.length, PQ_PUBLIC_KEY_SIZE);
    assert.equal(km.pqPublicKeyB64, km.pqPublicKey.toString('base64'));

    const restored = KeyManager.deserialize(km.serialize());
    assert.deepEqual(restored.pqPublicKey, km.pqPublicKey);

    // A secret restored from the same pair still decapsulates our ciphertexts.
    const enc = pqEncapsulate(km.pqPublicKey);
    assert.deepEqual(pqDecapsulate(enc.ciphertext, restored.pqSecretKey), enc.sharedSecret);
  });

  it('an old backup without KEM material still loads (fresh pair generated)', () => {
    const km = new KeyManager();
    const legacy = km.serialize();
    delete legacy.pqPublicKey;
    delete legacy.pqSecretKey;

    const restored = KeyManager.deserialize(legacy);
    assert.equal(restored.pqPublicKey.length, PQ_PUBLIC_KEY_SIZE, 'generated on the fly');
    assert.equal(restored.publicKeyB64, km.publicKeyB64, 'classical identity preserved');
  });
});
