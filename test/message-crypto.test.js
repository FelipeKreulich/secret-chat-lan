import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import {
  padMessage,
  unpadMessage,
  unpadSecure,
  encrypt,
  decrypt,
  decryptWithFallback,
} from '../src/crypto/MessageCrypto.js';

function generateKeyPair() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  return { publicKey, secretKey };
}

describe('MessageCrypto', () => {
  describe('padMessage', () => {
    it('selects correct bucket sizes', () => {
      // 5 bytes + 2 header = 7 → bucket 128
      const p1 = padMessage(Buffer.alloc(5));
      assert.equal(p1.length, 128);

      // 200 bytes + 2 = 202 → bucket 256
      const p2 = padMessage(Buffer.alloc(200));
      assert.equal(p2.length, 256);

      // 500 bytes + 2 = 502 → bucket 512
      const p3 = padMessage(Buffer.alloc(500));
      assert.equal(p3.length, 512);

      // 33000 bytes + 2 = 33002 → no bucket fits, use needed size
      const p4 = padMessage(Buffer.alloc(33000));
      assert.equal(p4.length, 33002);
    });

    it('stores original length in first 2 bytes', () => {
      const msg = Buffer.from('Hello');
      const padded = padMessage(msg);
      assert.equal(padded.readUInt16BE(0), 5);
      assert.ok(msg.equals(padded.subarray(2, 7)));
    });
  });

  describe('unpadMessage / unpadSecure', () => {
    it('round-trips correctly', () => {
      const original = Buffer.from('Test message');
      const padded = padMessage(original);

      const result = unpadMessage(padded);
      assert.ok(result);
      assert.ok(original.equals(result));
    });

    it('unpadSecure returns a Buffer and wipes padded', () => {
      const original = Buffer.from('Secure test');
      const padded = padMessage(original);
      const paddedCopy = Buffer.from(padded); // keep a copy to verify wipe

      const result = unpadSecure(padded);
      assert.ok(result);
      assert.ok(original.equals(result));

      // padded should be zeroed
      const allZero = padded.every((b) => b === 0);
      assert.ok(allZero, 'padded buffer should be wiped');
    });

    it('returns null for too-short buffer', () => {
      assert.equal(unpadMessage(Buffer.alloc(1)), null);
    });

    it('returns null for corrupt length', () => {
      const padded = Buffer.alloc(128);
      padded.writeUInt16BE(9999, 0); // length > buffer size
      assert.equal(unpadMessage(padded), null);
    });
  });

  describe('encrypt / decrypt', () => {
    it('round-trips with correct keys', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();

      const nonce = Buffer.alloc(24);
      sodium.randombytes_buf(nonce);

      const ciphertext = encrypt('Hello Bob', nonce, bob.publicKey, alice.secretKey);
      const plaintext = decrypt(ciphertext, nonce, alice.publicKey, bob.secretKey);

      assert.ok(plaintext);
      assert.equal(plaintext.toString('utf-8'), 'Hello Bob');

      sodium.sodium_memzero(alice.secretKey);
      sodium.sodium_memzero(bob.secretKey);
    });

    it('returns null with wrong keys', () => {
      const alice = generateKeyPair();
      const bob = generateKeyPair();
      const eve = generateKeyPair();

      const nonce = Buffer.alloc(24);
      sodium.randombytes_buf(nonce);

      const ciphertext = encrypt('Secret', nonce, bob.publicKey, alice.secretKey);
      const result = decrypt(ciphertext, nonce, alice.publicKey, eve.secretKey);

      assert.equal(result, null);

      sodium.sodium_memzero(alice.secretKey);
      sodium.sodium_memzero(bob.secretKey);
      sodium.sodium_memzero(eve.secretKey);
    });
  });

  describe('decryptWithFallback', () => {
    it('tries all 4 key combinations', () => {
      const aliceCurr = generateKeyPair();
      const alicePrev = generateKeyPair();
      const bobCurr = generateKeyPair();
      const bobPrev = generateKeyPair();

      const nonce = Buffer.alloc(24);

      // Case 1: current keys
      sodium.randombytes_buf(nonce);
      const ct1 = encrypt('msg1', nonce, bobCurr.publicKey, aliceCurr.secretKey);
      const r1 = decryptWithFallback(ct1, nonce, aliceCurr.publicKey, bobCurr.secretKey, null, null);
      assert.ok(r1);
      assert.equal(r1.toString('utf-8'), 'msg1');

      // Case 2: sender used previous key
      sodium.randombytes_buf(nonce);
      const ct2 = encrypt('msg2', nonce, bobCurr.publicKey, alicePrev.secretKey);
      const r2 = decryptWithFallback(
        ct2, nonce, aliceCurr.publicKey, bobCurr.secretKey, alicePrev.publicKey, null,
      );
      assert.ok(r2);
      assert.equal(r2.toString('utf-8'), 'msg2');

      // Case 3: recipient used previous key
      sodium.randombytes_buf(nonce);
      const ct3 = encrypt('msg3', nonce, bobPrev.publicKey, aliceCurr.secretKey);
      const r3 = decryptWithFallback(
        ct3, nonce, aliceCurr.publicKey, bobCurr.secretKey, null, bobPrev.secretKey,
      );
      assert.ok(r3);
      assert.equal(r3.toString('utf-8'), 'msg3');

      // Case 4: both used previous keys
      sodium.randombytes_buf(nonce);
      const ct4 = encrypt('msg4', nonce, bobPrev.publicKey, alicePrev.secretKey);
      const r4 = decryptWithFallback(
        ct4, nonce, aliceCurr.publicKey, bobCurr.secretKey, alicePrev.publicKey, bobPrev.secretKey,
      );
      assert.ok(r4);
      assert.equal(r4.toString('utf-8'), 'msg4');

      // Case 5: completely wrong keys → null
      const eve = generateKeyPair();
      sodium.randombytes_buf(nonce);
      const ct5 = encrypt('msg5', nonce, eve.publicKey, eve.secretKey);
      const r5 = decryptWithFallback(
        ct5, nonce, aliceCurr.publicKey, bobCurr.secretKey, alicePrev.publicKey, bobPrev.secretKey,
      );
      assert.equal(r5, null);

      // Cleanup
      for (const kp of [aliceCurr, alicePrev, bobCurr, bobPrev, eve]) {
        sodium.sodium_memzero(kp.secretKey);
      }
    });
  });
});
