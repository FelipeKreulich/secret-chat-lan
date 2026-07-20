import { test } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import { DoubleRatchet } from '../src/crypto/DoubleRatchet.js';
import { RATCHET_MAX_SKIP } from '../src/shared/constants.js';

// Deterministic PRNG so any failure reproduces (seed is fixed).
function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function keyPair() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

function pair() {
  const a = keyPair();
  const b = keyPair();
  return {
    alice: new DoubleRatchet('alice', 'bob', a.secretKey, b.publicKey),
    bob: new DoubleRatchet('bob', 'alice', b.secretKey, a.publicKey),
  };
}

const dec = (r, p) => r.decrypt(p.ciphertext, p.nonce, p.ephemeralPublicKey, p.counter, p.previousCounter);

function shuffle(arr, rng) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function randBuf(rng, n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    b[i] = Math.floor(rng() * 256);
  }
  return b;
}

test('out-of-order delivery within a burst always decrypts (skipped keys)', () => {
  const rng = mulberry32(9110001);
  const cap = Math.min(24, RATCHET_MAX_SKIP - 1);
  for (let iter = 0; iter < 40; iter++) {
    const { alice, bob } = pair();
    const n = 1 + Math.floor(rng() * cap);
    const packets = [];
    for (let i = 0; i < n; i++) {
      packets.push({ text: `m${i}`, ...alice.encrypt(`m${i}`) });
    }
    for (const idx of shuffle([...packets.keys()], rng)) {
      const plain = dec(bob, packets[idx]);
      assert.ok(plain, `msg ${idx} should decrypt out of order`);
      assert.equal(plain.toString('utf-8'), packets[idx].text);
    }
    alice.destroy();
    bob.destroy();
  }
});

test('replays are rejected and never corrupt state', () => {
  const { alice, bob } = pair();
  const p0 = { text: 'a', ...alice.encrypt('a') };
  const p1 = { text: 'b', ...alice.encrypt('b') };
  assert.equal(dec(bob, p0).toString('utf-8'), 'a');
  assert.equal(dec(bob, p0), null, 'replay of p0 rejected');
  assert.equal(dec(bob, p1).toString('utf-8'), 'b', 'state intact after replay');
  assert.equal(dec(bob, p1), null, 'replay of p1 rejected');
  alice.destroy();
  bob.destroy();
});

test('a tampered ciphertext is rejected and does not consume/corrupt state', () => {
  const rng = mulberry32(9110003);
  for (let iter = 0; iter < 60; iter++) {
    const { alice, bob } = pair();
    const good = { ...alice.encrypt('legit') };
    const forged = { ...good, ciphertext: Buffer.from(good.ciphertext) };
    forged.ciphertext[Math.floor(rng() * forged.ciphertext.length)] ^= 0xff;
    assert.equal(dec(bob, forged), null, 'forged message rejected');
    // The forgery must NOT have consumed message key 0 — the real one still works.
    assert.equal(dec(bob, good).toString('utf-8'), 'legit', 'real message still decrypts');
    alice.destroy();
    bob.destroy();
  }
});

test('garbage decrypt inputs never throw and never corrupt state', () => {
  const rng = mulberry32(9110004);
  const { alice, bob } = pair();
  const attempt = (counterMax) => {
    const garbage = {
      ciphertext: randBuf(rng, 1 + Math.floor(rng() * 96)),
      nonce: randBuf(rng, 24),
      ephemeralPublicKey: randBuf(rng, 32),
      counter: Math.floor(rng() * counterMax),
      previousCounter: Math.floor(rng() * counterMax),
    };
    let res;
    assert.doesNotThrow(() => {
      res = dec(bob, garbage);
    });
    assert.equal(res, null, 'garbage never decrypts');
  };
  // Bulk: realistic small counters (varied ciphertext sizes incl. < MAC).
  for (let i = 0; i < 800; i++) {
    attempt(16);
  }
  // A few with huge counters to exercise the maxSkip guard (kept small in count
  // so the sodium guarded-memory pool isn't exhausted on constrained runners).
  for (let i = 0; i < 20; i++) {
    attempt(5000);
  }
  // After all that garbage, a genuine message still decrypts.
  const p = { text: 'still works', ...alice.encrypt('still works') };
  assert.equal(dec(bob, p).toString('utf-8'), 'still works');
  alice.destroy();
  bob.destroy();
});

test('random bidirectional conversation decrypts under immediate delivery', () => {
  const rng = mulberry32(9110005);
  for (let iter = 0; iter < 40; iter++) {
    const { alice, bob } = pair();
    for (let i = 0; i < 40; i++) {
      // The responder (bob) can't send until he's received the initiator's
      // first message — so the very first message must come from alice.
      const aliceSends = i === 0 ? true : rng() < 0.5;
      const sender = aliceSends ? alice : bob;
      const receiver = aliceSends ? bob : alice;
      const text = 'x'.repeat(Math.floor(rng() * 60));
      const p = sender.encrypt(text);
      const plain = receiver.decrypt(
        p.ciphertext,
        p.nonce,
        p.ephemeralPublicKey,
        p.counter,
        p.previousCounter,
      );
      assert.ok(plain, `msg ${i} should decrypt`);
      assert.equal(plain.toString('utf-8'), text);
    }
    alice.destroy();
    bob.destroy();
  }
});
