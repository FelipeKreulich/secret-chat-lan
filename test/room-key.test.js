import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveRoomSecrets,
  signRoomChallenge,
  verifyRoomChallenge,
  encryptRoomPayload,
  decryptRoomPayload,
  isRoomWrapped,
  freeRoomSecrets,
} from '../src/crypto/RoomKey.js';

// Argon2id MODERATE is intentionally slow (~1s) — derive once per password
// and reuse across tests.
let right; // ('cofre', 'senha secreta')
let rightAgain; // same inputs, derived independently
let wrongPassword; // ('cofre', 'senha errada')
let otherRoom; // ('outra', 'senha secreta')

describe('RoomKey — password-derived private room secrets', () => {
  before(() => {
    right = deriveRoomSecrets('cofre', 'senha secreta');
    rightAgain = deriveRoomSecrets('cofre', 'senha secreta');
    wrongPassword = deriveRoomSecrets('cofre', 'senha errada');
    otherRoom = deriveRoomSecrets('outra', 'senha secreta');
  });

  it('is deterministic: same (room, password) → same keys', () => {
    assert.deepEqual(right.authPublicKey, rightAgain.authPublicKey);
    assert.deepEqual(Buffer.from(right.roomKey), Buffer.from(rightAgain.roomKey));
  });

  it('different password or room → different keys', () => {
    assert.notDeepEqual(right.authPublicKey, wrongPassword.authPublicKey);
    assert.notDeepEqual(right.authPublicKey, otherRoom.authPublicKey);
    assert.notDeepEqual(Buffer.from(right.roomKey), Buffer.from(wrongPassword.roomKey));
  });

  it('challenge signature verifies with the right password', () => {
    const sig = signRoomChallenge(right.authSecretKey, 'cofre', 'nonceB64', 'session-1');
    assert.equal(
      verifyRoomChallenge(right.authPublicKey, sig, 'cofre', 'nonceB64', 'session-1'),
      true,
    );
  });

  it('challenge signature fails with the wrong password', () => {
    const sig = signRoomChallenge(wrongPassword.authSecretKey, 'cofre', 'nonceB64', 'session-1');
    assert.equal(
      verifyRoomChallenge(right.authPublicKey, sig, 'cofre', 'nonceB64', 'session-1'),
      false,
    );
  });

  it('challenge signature is bound to room, nonce and sessionId', () => {
    const sig = signRoomChallenge(right.authSecretKey, 'cofre', 'nonceB64', 'session-1');
    assert.equal(
      verifyRoomChallenge(right.authPublicKey, sig, 'outra', 'nonceB64', 'session-1'),
      false,
      'different room must fail',
    );
    assert.equal(
      verifyRoomChallenge(right.authPublicKey, sig, 'cofre', 'other-nonce', 'session-1'),
      false,
      'different nonce must fail',
    );
    assert.equal(
      verifyRoomChallenge(right.authPublicKey, sig, 'cofre', 'nonceB64', 'session-2'),
      false,
      'different session must fail',
    );
  });

  it('rejects malformed keys/signatures without throwing', () => {
    const sig = signRoomChallenge(right.authSecretKey, 'cofre', 'n', 's');
    assert.equal(verifyRoomChallenge(Buffer.alloc(5), sig, 'cofre', 'n', 's'), false);
    assert.equal(verifyRoomChallenge(right.authPublicKey, Buffer.alloc(5), 'cofre', 'n', 's'), false);
    assert.equal(verifyRoomChallenge('not-a-buffer', sig, 'cofre', 'n', 's'), false);
  });

  it('content layer round-trips', () => {
    const wrapped = encryptRoomPayload('{"text":"olá sala privada"}', right.roomKey);
    const data = JSON.parse(wrapped);
    assert.equal(isRoomWrapped(data), true);
    assert.equal(decryptRoomPayload(data, right.roomKey), '{"text":"olá sala privada"}');
  });

  it('content layer fails closed on wrong key or tampering', () => {
    const wrapped = JSON.parse(encryptRoomPayload('segredo', right.roomKey));
    assert.equal(decryptRoomPayload(wrapped, wrongPassword.roomKey), null, 'wrong key');

    const tampered = { ...wrapped };
    const bytes = Buffer.from(tampered.c, 'base64');
    bytes[0] ^= 0xff;
    tampered.c = bytes.toString('base64');
    assert.equal(decryptRoomPayload(tampered, right.roomKey), null, 'tampered ciphertext');

    assert.equal(decryptRoomPayload({ rk: 1, n: 'x', c: 'y' }, right.roomKey), null, 'garbage');
    assert.equal(decryptRoomPayload(null, right.roomKey), null);
  });

  it('isRoomWrapped only matches the wrapper shape', () => {
    assert.equal(isRoomWrapped({ rk: 1, n: 'a', c: 'b' }), true);
    assert.equal(isRoomWrapped({ text: 'oi' }), false);
    assert.equal(isRoomWrapped({ rk: 2, n: 'a', c: 'b' }), false);
    assert.equal(isRoomWrapped(null), false);
    assert.equal(isRoomWrapped('string'), false);
  });

  it('freeRoomSecrets zeroes key material and tolerates null', () => {
    const s = deriveRoomSecrets('efemera', 'x');
    const keyCopy = Buffer.from(s.roomKey);
    freeRoomSecrets(s);
    assert.notDeepEqual(Buffer.from(s.roomKey), keyCopy, 'roomKey must be wiped');
    assert.equal(Buffer.from(s.roomKey).every((b) => b === 0), true);
    freeRoomSecrets(null); // must not throw
  });
});
