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
  const packet = alice.encrypt('ola grupo');

  // Both members decrypt the same ciphertext.
  assert.equal(bob.decrypt('alice', packet).toString('utf-8'), 'ola grupo');
  assert.equal(carol.decrypt('alice', packet).toString('utf-8'), 'ola grupo');

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
  bob.decrypt('alice', alice.encrypt('antes')); // establish

  alice.rotate(); // e.g. a member left
  const afterPacket = alice.encrypt('depois');
  // Bob's stale chain can't decrypt the rotated message...
  assert.equal(bob.decrypt('alice', afterPacket), null);
  // ...until Alice redistributes.
  bob.addMember('alice', alice.distribution());
  const afterPacket2 = alice.encrypt('depois2');
  assert.equal(bob.decrypt('alice', afterPacket2).toString('utf-8'), 'depois2');

  alice.destroy();
  bob.destroy();
});
