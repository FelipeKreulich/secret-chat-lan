import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { createEncryptedMessage } from '../src/protocol/messages.js';
import { FILE_CHUNK_SIZE, MAX_PAYLOAD_SIZE } from '../src/shared/constants.js';

test('padMessage refuses a payload it cannot length-prefix (2-byte cap)', () => {
  assert.doesNotThrow(() => MessageCrypto.padMessage(Buffer.alloc(0xffff)));
  assert.throws(() => MessageCrypto.padMessage(Buffer.alloc(0x10000)), /too large/i);
});

test('a full file chunk encrypts and fits under MAX_PAYLOAD_SIZE on the wire', () => {
  // Reproduces the real send path: chunk → base64 in JSON → encrypt → ciphertext
  // base64 in the wire envelope. This is the double-base64 expansion that made
  // FILE_CHUNK_SIZE=49152 overflow both padMessage and MAX_PAYLOAD_SIZE.
  const sender = new KeyManager();
  const rcpt = new KeyManager();

  const chunk = randomBytes(FILE_CHUNK_SIZE);
  const payload = JSON.stringify({
    action: 'file_chunk',
    transferId: 'abcd1234',
    chunkIndex: 999,
    data: chunk.toString('base64'),
    sentAt: 1_784_310_295_024,
  });

  // Must not overflow padMessage's 2-byte length field.
  assert.ok(Buffer.byteLength(payload) <= 0xffff, 'chunk plaintext fits padMessage');

  const nonce = randomBytes(24);
  const ciphertext = MessageCrypto.encrypt(payload, nonce, rcpt.publicKey, sender.secretKey);

  const wire = JSON.stringify(
    createEncryptedMessage('sess-from', 'sess-to', ciphertext.toString('base64'), nonce.toString('base64')),
  );
  assert.ok(
    Buffer.byteLength(wire) <= MAX_PAYLOAD_SIZE,
    `wire frame ${Buffer.byteLength(wire)} must fit MAX_PAYLOAD_SIZE ${MAX_PAYLOAD_SIZE}`,
  );

  // And it round-trips.
  const plain = MessageCrypto.decrypt(ciphertext, nonce, sender.publicKey, rcpt.secretKey);
  assert.equal(plain.toString('utf-8'), payload);

  sender.destroy();
  rcpt.destroy();
});
