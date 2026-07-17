import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seal, unseal, sealEnvelope, openEnvelope } from '../src/crypto/SealedSender.js';
import { KeyManager } from '../src/crypto/KeyManager.js';

test('seal/unseal round-trips for the intended recipient', () => {
  const rcpt = new KeyManager();
  const sealed = seal('mensagem secreta', rcpt.publicKey);
  const opened = unseal(sealed, rcpt.publicKey, rcpt.secretKey);
  assert.equal(opened.toString('utf-8'), 'mensagem secreta');
  rcpt.destroy();
});

test('a different recipient cannot open the sealed box', () => {
  const rcpt = new KeyManager();
  const other = new KeyManager();
  const sealed = seal('so pra rcpt', rcpt.publicKey);
  assert.equal(unseal(sealed, other.publicKey, other.secretKey), null);
  rcpt.destroy();
  other.destroy();
});

test('a tampered sealed box fails to open', () => {
  const rcpt = new KeyManager();
  const sealed = seal('intacta', rcpt.publicKey);
  sealed[sealed.length - 1] ^= 0xff;
  assert.equal(unseal(sealed, rcpt.publicKey, rcpt.secretKey), null);
  rcpt.destroy();
});

test('the sealed ciphertext does not leak the sender identity in the clear', () => {
  const rcpt = new KeyManager();
  const sealedB64 = sealEnvelope('alice-session-id-1234', { ciphertext: 'AA==' }, rcpt.publicKey);
  // Neither the base64 nor the raw bytes contain the sender id.
  assert.ok(!sealedB64.includes('alice-session-id-1234'));
  assert.equal(Buffer.from(sealedB64, 'base64').includes('alice-session-id'), false);
  rcpt.destroy();
});

test('sealEnvelope/openEnvelope carries from + payload to the recipient only', () => {
  const rcpt = new KeyManager();
  const other = new KeyManager();
  const payload = { ciphertext: 'Y2lwaGVy', nonce: 'bm9uY2U=' };
  const sealedB64 = sealEnvelope('bob', payload, rcpt.publicKey);

  const opened = openEnvelope(sealedB64, rcpt.publicKey, rcpt.secretKey);
  assert.deepEqual(opened, { from: 'bob', payload });

  // A wrong recipient just gets null (can't tell who it was for).
  assert.equal(openEnvelope(sealedB64, other.publicKey, other.secretKey), null);
  rcpt.destroy();
  other.destroy();
});
