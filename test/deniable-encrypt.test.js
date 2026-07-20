import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import { deriveSharedKey, encryptDeniable, decryptDeniable } from '../src/crypto/DeniableEncrypt.js';

function keyPair() {
  const pk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const sk = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(pk, sk);
  return { pk, sk };
}

function nonce() {
  const n = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES);
  sodium.randombytes_buf(n);
  return n;
}

describe('DeniableEncrypt', () => {
  it('deriveSharedKey returns a 32-byte key without throwing (regression: crypto_box_beforenm removed)', () => {
    const a = keyPair();
    const b = keyPair();
    const key = deriveSharedKey(a.sk, b.pk);
    assert.equal(key.length, sodium.crypto_secretbox_KEYBYTES);
  });

  it('both parties derive the same shared key (DH symmetry — the basis of deniability)', () => {
    const a = keyPair();
    const b = keyPair();
    const keyAB = deriveSharedKey(a.sk, b.pk);
    const keyBA = deriveSharedKey(b.sk, a.pk);
    assert.ok(Buffer.compare(Buffer.from(keyAB), Buffer.from(keyBA)) === 0);
  });

  it('round-trips a message with the shared key', () => {
    const a = keyPair();
    const b = keyPair();
    const key = deriveSharedKey(a.sk, b.pk);
    const n = nonce();
    const ct = encryptDeniable('secret message 🔒', n, key);
    const pt = decryptDeniable(ct, n, deriveSharedKey(b.sk, a.pk));
    assert.ok(pt, 'decryption should succeed');
    assert.equal(pt.toString('utf-8'), 'secret message 🔒');
  });

  it('fails to decrypt with the wrong key', () => {
    const a = keyPair();
    const b = keyPair();
    const c = keyPair();
    const key = deriveSharedKey(a.sk, b.pk);
    const n = nonce();
    const ct = encryptDeniable('hello', n, key);
    const wrong = deriveSharedKey(c.sk, a.pk);
    assert.equal(decryptDeniable(ct, n, wrong), null);
  });
});
