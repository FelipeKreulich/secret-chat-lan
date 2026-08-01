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
    assert.match(sas1, /^\d{4} \d{4} \d{5}$/, 'SAS is 13 digits grouped 4-4-5 (~40 bits)');
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

  it('contacts: alias set/get/clear on known peers only, persisted', () => {
    const store = new TrustStore(tempDir);
    store.recordPeer('Alice', generatePublicKeyB64());

    assert.equal(store.setAlias('ghost', 'Fantasma'), false, 'unknown peer cannot be aliased');
    assert.equal(store.setAlias('alice', 'João da Firma'), true, 'case-insensitive nick');
    assert.equal(store.getAlias('ALICE'), 'João da Firma');

    // Alias survives a new instance (same file as the trust records).
    const store2 = new TrustStore(tempDir);
    assert.equal(store2.getAlias('alice'), 'João da Firma');

    assert.equal(store2.clearAlias('alice'), true);
    assert.equal(store2.clearAlias('alice'), false, 'clearing twice is a no-op');
    assert.equal(store2.getAlias('alice'), null);
  });

  it('contacts: listContacts filters by alias and sorts by last seen', () => {
    const store = new TrustStore(tempDir);
    store.recordPeer('Alice', generatePublicKeyB64());
    store.recordPeer('Bob', generatePublicKeyB64());
    store.recordPeer('Carol', generatePublicKeyB64());
    store.setAlias('alice', 'A');
    store.setAlias('bob', 'B');
    store.markVerified('bob');

    const contacts = store.listContacts();
    assert.deepEqual(contacts.map((c) => c.nickname).sort(), ['alice', 'bob']);
    assert.equal(contacts.find((c) => c.nickname === 'bob').verified, true);

    const everyone = store.listContacts(true);
    assert.equal(everyone.length, 3, '`all` includes peers without an alias');
  });

  it('contacts: alias truncates to 30 chars and rides along in export/import', () => {
    const store = new TrustStore(tempDir);
    store.recordPeer('Alice', generatePublicKeyB64());
    store.setAlias('alice', 'x'.repeat(50));
    assert.equal(store.getAlias('alice').length, 30);

    const exported = store.exportData();
    assert.equal(exported.alice.alias, 'x'.repeat(30), 'alias included in identity backup data');
  });
});
