import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SenderChain, GroupSession, groupEncrypt, groupDecrypt } from '../src/crypto/SenderKey.js';

// A sender chain and a receiver chain seeded from the same distribution derive
// identical message keys per counter → round-trip.
test('sender and receiver chains agree on message keys in order', () => {
  const sender = new SenderChain();
  const receiver = SenderChain.deserialize(sender.serialize());

  for (let i = 0; i < 5; i++) {
    const { messageKey, counter } = sender.deriveNext();
    assert.equal(counter, i);
    const { ciphertext, nonce } = groupEncrypt(messageKey, `msg ${i}`);
    const plain = groupDecrypt(receiver.messageKeyFor(counter), ciphertext, nonce);
    assert.equal(plain.toString('utf-8'), `msg ${i}`);
  }
  sender.destroy();
  receiver.destroy();
});

test('out-of-order delivery is handled via skipped keys', () => {
  const sender = new SenderChain();
  const receiver = SenderChain.deserialize(sender.serialize());

  const packets = [];
  for (let i = 0; i < 4; i++) {
    const { messageKey, counter } = sender.deriveNext();
    packets.push({ counter, ...groupEncrypt(messageKey, `m${i}`) });
  }
  // Deliver 3, 1, 0, 2
  for (const idx of [3, 1, 0, 2]) {
    const p = packets[idx];
    const plain = groupDecrypt(receiver.messageKeyFor(p.counter), p.ciphertext, p.nonce);
    assert.equal(plain.toString('utf-8'), `m${idx}`);
  }
  sender.destroy();
  receiver.destroy();
});

test('a replayed counter yields no key', () => {
  const sender = new SenderChain();
  const receiver = SenderChain.deserialize(sender.serialize());
  const { messageKey, counter } = sender.deriveNext();
  groupEncrypt(messageKey, 'x'); // consumes key 0
  assert.ok(receiver.messageKeyFor(counter), 'first receipt works');
  assert.equal(receiver.messageKeyFor(counter), null, 'replay of counter 0 rejected');
  sender.destroy();
  receiver.destroy();
});

test('a gap beyond maxSkip is refused', () => {
  const receiver = new SenderChain(null, 0, 10);
  assert.equal(receiver.messageKeyFor(50), null, 'too far ahead → null');
  receiver.destroy();
});

test('groupDecrypt rejects a tampered ciphertext', () => {
  const sender = new SenderChain();
  const receiver = SenderChain.deserialize(sender.serialize());
  const { messageKey, counter } = sender.deriveNext();
  const { ciphertext, nonce } = groupEncrypt(messageKey, 'secret');
  ciphertext[ciphertext.length - 1] ^= 0xff; // flip a byte
  assert.equal(groupDecrypt(receiver.messageKeyFor(counter), ciphertext, nonce), null);
  sender.destroy();
  receiver.destroy();
});

test('GroupSession: one ciphertext is decrypted by every member (O(1) broadcast)', () => {
  const alice = new GroupSession();
  const bob = new GroupSession();
  const carol = new GroupSession();

  // Alice distributes her sender key to Bob and Carol (over the pairwise channel).
  bob.addMember('alice', alice.distribution());
  carol.addMember('alice', alice.distribution());

  // Alice encrypts ONCE.
  const packet = alice.encrypt('hello group');

  // Both members decrypt the same ciphertext.
  assert.equal(bob.decrypt('alice', packet).toString('utf-8'), 'hello group');
  assert.equal(carol.decrypt('alice', packet).toString('utf-8'), 'hello group');

  // A non-member (no distribution) cannot.
  const mallory = new GroupSession();
  assert.equal(mallory.decrypt('alice', packet), null);

  alice.destroy();
  bob.destroy();
  carol.destroy();
  mallory.destroy();
});

test('GroupSession: rotate() changes the chain and needs re-distribution', () => {
  const alice = new GroupSession();
  const bob = new GroupSession();
  bob.addMember('alice', alice.distribution());
  bob.decrypt('alice', alice.encrypt('before')); // establish

  alice.rotate(); // e.g. a member left
  const afterPacket = alice.encrypt('after');
  // Bob's stale chain can't decrypt the rotated message...
  assert.equal(bob.decrypt('alice', afterPacket), null);
  // ...until Alice redistributes.
  bob.addMember('alice', alice.distribution());
  const afterPacket2 = alice.encrypt('after2');
  assert.equal(bob.decrypt('alice', afterPacket2).toString('utf-8'), 'after2');

  alice.destroy();
  bob.destroy();
});

// ── Guarded memory is released, not merely zeroed ───────────────────────────
//
// sodium_malloc'd pages are mlock'd, and the OS caps how much a process may
// lock at once (RLIMIT_MEMLOCK). Zeroing a spent key leaves its pages locked
// until the garbage collector runs the buffer's finaliser, so a chain that
// ratchets faster than the collector runs walks into sodium_malloc returning
// NULL — which aborts the process on whatever unrelated call allocates next.
//
// That is exactly how this surfaced: a SIGABRT inside the pairwise ratchet, on
// Linux CI only, from a change that had touched neither. macOS leaves the limit
// unlimited, so these two tests have teeth only where the limit is real. They
// are cheap enough to keep anyway, and the failure they guard against is a
// crash rather than a wrong answer.

test('a long-lived chain does not accumulate locked pages', () => {
  const sender = new SenderChain();
  const receiver = SenderChain.deserialize(sender.serialize());

  // Enough steps that leaking one guarded buffer each would exceed a typical
  // 8 MiB memlock ceiling several times over.
  for (let i = 0; i < 5000; i++) {
    const { messageKey, counter } = sender.deriveNext();
    const { ciphertext, nonce } = groupEncrypt(messageKey, `m${i}`);
    const plain = groupDecrypt(receiver.messageKeyFor(counter), ciphertext, nonce);
    assert.equal(plain.toString('utf-8'), `m${i}`);
  }

  sender.destroy();
  receiver.destroy();
});

test('rotating repeatedly does not accumulate locked pages', () => {
  // Rotation runs on every membership change, and each one replaces both the
  // chain and the signing key. A busy room is a lot of rotations.
  const alice = new GroupSession();
  const bob = new GroupSession();

  for (let i = 0; i < 2000; i++) {
    alice.rotate();
    bob.addMember('alice', alice.distribution());
    assert.equal(bob.decrypt('alice', alice.encrypt(`r${i}`)).toString('utf-8'), `r${i}`);
  }

  alice.destroy();
  bob.destroy();
});

test('destroying a session twice is safe', () => {
  // Freeing is not zeroing: a second free of the same pages is a hard crash,
  // not a no-op. Shutdown paths overlap — a room switch drops every chain and
  // the controller's own destroy() runs later — so this has to hold.
  const s = new GroupSession();
  s.addMember('peer', new GroupSession().distribution());
  s.destroy();
  s.destroy();

  const chain = new SenderChain();
  chain.destroy();
  chain.destroy();
});
