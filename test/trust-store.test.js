import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import sodium from 'sodium-native';
import { TrustStore, TrustResult } from '../src/crypto/TrustStore.js';

function generatePublicKeyB64() {
  const publicKey = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(publicKey, secretKey);
  sodium.sodium_memzero(secretKey);
  return publicKey.toString('base64');
}

describe('TrustStore', () => {
  let tempDir;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'truststore-test-'));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('records a new peer and returns TRUSTED on second check', () => {
    const store = new TrustStore(tempDir);
    const pubKey = generatePublicKeyB64();

    const result1 = store.checkPeer('Alice', pubKey);
    assert.equal(result1, TrustResult.NEW_PEER);

    store.recordPeer('Alice', pubKey);

    const result2 = store.checkPeer('Alice', pubKey);
    assert.equal(result2, TrustResult.TRUSTED);
  });

  it('detects key mismatch for unverified peer', () => {
    const store = new TrustStore(tempDir);
    const key1 = generatePublicKeyB64();
    const key2 = generatePublicKeyB64();

    store.recordPeer('Alice', key1);

    const result = store.checkPeer('Alice', key2);
    assert.equal(result, TrustResult.MISMATCH);
  });

  it('detects key mismatch for verified peer', () => {
    const store = new TrustStore(tempDir);
    const key1 = generatePublicKeyB64();
    const key2 = generatePublicKeyB64();

    store.recordPeer('Alice', key1);
    store.markVerified('Alice');

    const result = store.checkPeer('Alice', key2);
    assert.equal(result, TrustResult.VERIFIED_MISMATCH);
  });

  it('computes SAS identically from both sides', () => {
    const keyA = generatePublicKeyB64();
    const keyB = generatePublicKeyB64();

    const sas1 = TrustStore.computeSAS(keyA, keyB);
    const sas2 = TrustStore.computeSAS(keyB, keyA);

    assert.equal(sas1, sas2, 'SAS should be the same regardless of order');
    assert.match(sas1, /^\d{6}$/, 'SAS should be 6 digits');
  });

  it('autoUpdatePeer preserves verified status', () => {
    const store = new TrustStore(tempDir);
    const key1 = generatePublicKeyB64();
    const key2 = generatePublicKeyB64();

    store.recordPeer('Alice', key1);
    store.markVerified('Alice');
    assert.equal(store.isVerified('Alice'), true);

    store.autoUpdatePeer('Alice', key2);
    assert.equal(store.isVerified('Alice'), true, 'verified should be preserved');

    const result = store.checkPeer('Alice', key2);
    assert.equal(result, TrustResult.TRUSTED, 'new key should be trusted after auto-update');
  });

  it('persists data across instances', () => {
    const key = generatePublicKeyB64();

    const store1 = new TrustStore(tempDir);
    store1.recordPeer('Alice', key);
    store1.markVerified('Alice');

    // Create a new instance with the same directory
    const store2 = new TrustStore(tempDir);
    assert.equal(store2.checkPeer('Alice', key), TrustResult.TRUSTED);
    assert.equal(store2.isVerified('Alice'), true);
  });
});
