import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SenderChain, GroupSession, groupDecrypt } from '../src/crypto/SenderKey.js';

// ── Why this file exists, separately from sender-key.test.js ─────────────────
//
// sender-key.test.js round-trips a sender against a receiver built from the same
// random key. That proves the two halves agree with each other — but they agree
// with each other however the KDF is defined. Swap the two domain tags, reverse
// the BLAKE2b argument order, change the padding prefix: the round-trip still
// passes, and two clients built either side of that change cannot read a word
// from one another.
//
// Sender keys are about to become a wire format shared between versions
// (docs/design/sender-keys-on-relay.md). These vectors pin the absolute values
// so that the incompatibility is caught here rather than in a public room with
// half its members upgraded.
//
// The vectors are frozen data, not an output to refresh. If a change makes them
// fail, the question is whether the protocol version should move — not whether
// the file should be regenerated.

const VECTORS = JSON.parse(
  readFileSync(new URL('./vectors/sender-key.json', import.meta.url), 'utf-8'),
);

const seed = () => Buffer.from(VECTORS.seedChainKey, 'base64');
const b64 = (buf) => Buffer.from(buf).toString('base64');

test('vectors: the KDF chain derives the pinned message and chain keys', () => {
  const chain = new SenderChain(seed(), 0);

  for (const step of VECTORS.kdf.steps) {
    const { messageKey, counter } = chain.deriveNext();
    assert.equal(counter, step.counter, 'counter starts at 0 and increments by 1');
    assert.equal(
      b64(messageKey),
      step.messageKey,
      `message key at counter ${step.counter} — domain tag 0x01, keyed BLAKE2b`,
    );
    assert.equal(
      chain.serialize().chainKey,
      step.chainKeyAfter,
      `chain key after counter ${step.counter} — domain tag 0x02`,
    );
  }

  chain.destroy();
});

test('vectors: distribution serialises to the pinned shape and value', () => {
  const chain = new SenderChain(seed(), 0);
  for (let i = 0; i < 5; i++) {
    chain.deriveNext();
  }

  const dist = chain.serialize();
  assert.deepEqual(
    Object.keys(dist).sort(),
    ['chainKey', 'counter'],
    'the distribution message carries exactly these two fields',
  );
  assert.deepEqual(dist, VECTORS.distributionAfter5Steps);
  assert.equal(typeof dist.chainKey, 'string', 'chainKey travels as base64, not raw bytes');
  assert.equal(Buffer.from(dist.chainKey, 'base64').length, 32);

  chain.destroy();
});

test('vectors: a chain rebuilt from a distribution literal derives the same keys', () => {
  // The interop case: a member that only ever saw the serialised distribution,
  // never the live object, must land on the same keys.
  const receiver = SenderChain.deserialize({ ...VECTORS.distributionAfter5Steps });

  const { messageKey, counter } = receiver.deriveNext();
  assert.equal(counter, 5, 'the counter resumes where the distribution left off');
  // Continuing the pinned chain: step 5 follows from chainKeyAfter of step 4.
  const direct = new SenderChain(seed(), 0);
  for (let i = 0; i < 5; i++) {
    direct.deriveNext();
  }
  const { messageKey: expected } = direct.deriveNext();
  assert.equal(b64(messageKey), b64(expected));

  receiver.destroy();
  direct.destroy();
});

test('vectors: skipping to a counter derives the same key as arriving in order', () => {
  const receiver = new SenderChain(seed(), 0);

  const jumped = receiver.messageKeyFor(3);
  assert.equal(b64(jumped), VECTORS.skipped.jumpToCounter3);
  assert.equal(
    VECTORS.skipped.jumpToCounter3,
    VECTORS.kdf.steps[3].messageKey,
    'out-of-order receipt must not fork the chain',
  );

  const cached = receiver.messageKeyFor(1);
  assert.equal(b64(cached), VECTORS.skipped.thenCachedCounter1);
  assert.equal(VECTORS.skipped.thenCachedCounter1, VECTORS.kdf.steps[1].messageKey);

  receiver.destroy();
});

test('vectors: the frozen ciphertext still opens', () => {
  // Pins secretbox, the 24-byte nonce, the 16-byte MAC and the padding layout
  // (2-byte big-endian length prefix ahead of the plaintext) all at once.
  // The message key is derived rather than read from the file, so this only
  // passes if the KDF above is also right.
  const chain = new SenderChain(seed(), 0);
  const { messageKey } = chain.deriveNext();
  assert.equal(b64(messageKey), VECTORS.aead.messageKey, 'same key the box was sealed with');

  const plain = groupDecrypt(
    Buffer.from(VECTORS.aead.messageKey, 'base64'),
    Buffer.from(VECTORS.aead.ciphertext, 'base64'),
    Buffer.from(VECTORS.aead.nonce, 'base64'),
  );
  assert.notEqual(plain, null, 'a frozen ciphertext that no longer opens is a protocol break');
  assert.equal(plain.toString('utf-8'), VECTORS.aead.plaintext);

  const nonce = Buffer.from(VECTORS.aead.nonce, 'base64');
  assert.equal(nonce.length, 24, 'nonce size is part of the wire format');
  const ciphertext = Buffer.from(VECTORS.aead.ciphertext, 'base64');
  assert.equal(ciphertext.length, 128 + 16, 'smallest padding bucket, plus the MAC');

  chain.destroy();
});

test('vectors: a tampered frozen ciphertext does not open', () => {
  const ciphertext = Buffer.from(VECTORS.aead.ciphertext, 'base64');
  ciphertext[0] ^= 0x01;
  const plain = groupDecrypt(
    Buffer.from(VECTORS.aead.messageKey, 'base64'),
    ciphertext,
    Buffer.from(VECTORS.aead.nonce, 'base64'),
  );
  assert.equal(plain, null);
});

// ── Rotation ────────────────────────────────────────────────────────────────
// rotate() draws fresh randomness, so there is no value to pin. What can be
// pinned is the shape of the break it causes, which is what the relay work has
// to get right on every membership change.

test('rotation resets the counter and abandons the old chain', () => {
  const alice = new GroupSession();
  const before = alice.distribution();
  for (let i = 0; i < 3; i++) {
    alice.encrypt('x');
  }
  assert.equal(alice.distribution().counter, 3);

  alice.rotate();
  const after = alice.distribution();
  assert.equal(after.counter, 0, 'a rotated chain starts a fresh counter');
  assert.notEqual(after.chainKey, before.chainKey, 'and a fresh key, not a ratchet step');

  alice.destroy();
});

test('rotation is silent until the sender redistributes', () => {
  // The failure this guards: rotate() without a following distribution leaves
  // the room unable to read the rotator, with nothing raising an error. It is
  // the caller's job, and SenderKey.js says so in a comment — this asserts it.
  const alice = new GroupSession();
  const bob = new GroupSession();
  bob.addMember('alice', alice.distribution());
  assert.equal(bob.decrypt('alice', alice.encrypt('before')).toString('utf-8'), 'before');

  alice.rotate();
  assert.equal(
    bob.decrypt('alice', alice.encrypt('after')),
    null,
    'no exception, no signal — just silence, which is why redistribution must be wired to every departure',
  );

  bob.addMember('alice', alice.distribution());
  assert.equal(bob.decrypt('alice', alice.encrypt('after redistribution')).toString('utf-8'),
    'after redistribution');

  alice.destroy();
  bob.destroy();
});

test('a stale distribution cannot be replayed to read a rotated chain', () => {
  const alice = new GroupSession();
  const stale = alice.distribution();
  alice.rotate();

  const attacker = new GroupSession();
  attacker.addMember('alice', stale);
  assert.equal(
    attacker.decrypt('alice', alice.encrypt('post-rotation')),
    null,
    'holding the pre-rotation key must not grant reading after rotation',
  );

  alice.destroy();
  attacker.destroy();
});
