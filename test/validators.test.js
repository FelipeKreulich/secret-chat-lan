import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseMessage,
  validateJoin,
  validateEncryptedMessage,
  validateKeyUpdate,
  validateChangeRoom,
  validateKickPeer,
  validateMutePeer,
  validateBanPeer,
  sanitizeNickname,
} from '../src/protocol/validators.js';
import { PROTOCOL_VERSION } from '../src/shared/constants.js';

const pk32 = Buffer.alloc(32, 7).toString('base64');
const nonce24 = Buffer.alloc(24, 3).toString('base64');

describe('validators — parseMessage', () => {
  it('rejects an oversized raw string', () => {
    assert.equal(parseMessage('x'.repeat(70000)).valid, false);
  });

  it('rejects invalid JSON', () => {
    assert.equal(parseMessage('{not json').valid, false);
  });

  it('rejects non-objects', () => {
    assert.equal(parseMessage('123').valid, false);
    assert.equal(parseMessage('[]').valid, false);
  });

  it('rejects an unsupported protocol version', () => {
    const raw = JSON.stringify({ version: PROTOCOL_VERSION + 1, type: 'join', timestamp: 1 });
    assert.equal(parseMessage(raw).valid, false);
  });

  it('rejects missing type or timestamp', () => {
    assert.equal(parseMessage(JSON.stringify({ version: PROTOCOL_VERSION, timestamp: 1 })).valid, false);
    assert.equal(parseMessage(JSON.stringify({ version: PROTOCOL_VERSION, type: 'x' })).valid, false);
  });

  it('accepts a well-formed message as string or object', () => {
    const obj = { version: PROTOCOL_VERSION, type: 'join', timestamp: Date.now() };
    assert.equal(parseMessage(JSON.stringify(obj)).valid, true);
    assert.equal(parseMessage(obj).valid, true);
  });
});

describe('validators — sanitizeNickname', () => {
  it('strips control chars and trims', () => {
    assert.equal(sanitizeNickname('  al\x00ice\x1f '), 'alice');
  });

  it('rejects empty, too long, non-string and illegal chars', () => {
    assert.equal(sanitizeNickname(''), null);
    assert.equal(sanitizeNickname('a'.repeat(21)), null);
    assert.equal(sanitizeNickname('bad name'), null);
    assert.equal(sanitizeNickname('joão'), null);
    assert.equal(sanitizeNickname(42), null);
  });

  it('accepts alphanumeric, dash and underscore', () => {
    assert.equal(sanitizeNickname('a-b_2'), 'a-b_2');
  });
});

describe('validators — validateJoin', () => {
  it('accepts a valid nickname and public key', () => {
    const r = validateJoin({ nickname: 'alice', publicKey: pk32 });
    assert.equal(r.valid, true);
    assert.equal(r.nickname, 'alice');
  });

  it('rejects a bad nickname', () => {
    assert.equal(validateJoin({ nickname: '!!', publicKey: pk32 }).valid, false);
  });

  it('rejects a wrong-size public key', () => {
    const short = Buffer.alloc(16).toString('base64');
    assert.equal(validateJoin({ nickname: 'alice', publicKey: short }).valid, false);
  });
});

describe('validators — validateEncryptedMessage', () => {
  const base = { from: 's1', to: 's2', payload: { ciphertext: 'AAA', nonce: nonce24 } };

  it('accepts a valid static message', () => {
    assert.equal(validateEncryptedMessage(base).valid, true);
  });

  it('rejects missing/invalid from or to', () => {
    assert.equal(validateEncryptedMessage({ ...base, from: 5 }).valid, false);
  });

  it('rejects a bad nonce size', () => {
    const m = { ...base, payload: { ciphertext: 'AAA', nonce: Buffer.alloc(10).toString('base64') } };
    assert.equal(validateEncryptedMessage(m).valid, false);
  });

  it('validates ratchet fields when ephemeralPublicKey is present', () => {
    const good = {
      ...base,
      payload: { ...base.payload, ephemeralPublicKey: pk32, counter: 0, previousCounter: 0 },
    };
    assert.equal(validateEncryptedMessage(good).valid, true);

    const badCounter = {
      ...base,
      payload: { ...base.payload, ephemeralPublicKey: pk32, counter: -1, previousCounter: 0 },
    };
    assert.equal(validateEncryptedMessage(badCounter).valid, false);

    const badEph = {
      ...base,
      payload: { ...base.payload, ephemeralPublicKey: 'zzz', counter: 0, previousCounter: 0 },
    };
    assert.equal(validateEncryptedMessage(badEph).valid, false);
  });
});

describe('validators — rooms & moderation', () => {
  it('validateChangeRoom lowercases and rejects bad names', () => {
    assert.deepEqual(validateChangeRoom({ room: 'MyRoom' }), { valid: true, room: 'myroom' });
    assert.equal(validateChangeRoom({ room: 'has space' }).valid, false);
    assert.equal(validateChangeRoom({ room: '' }).valid, false);
    assert.equal(validateChangeRoom({ room: 'a'.repeat(31) }).valid, false);
  });

  it('validateMutePeer requires a positive duration', () => {
    assert.equal(validateMutePeer({ targetNickname: 'bob', durationMs: 1000 }).valid, true);
    assert.equal(validateMutePeer({ targetNickname: 'bob', durationMs: 0 }).valid, false);
    assert.equal(validateMutePeer({ targetNickname: 'bob' }).valid, false);
  });

  it('validateKickPeer / validateBanPeer clamp the reason to 200 chars', () => {
    const r = validateKickPeer({ targetNickname: 'bob', reason: 'x'.repeat(500) });
    assert.equal(r.valid, true);
    assert.equal(r.reason.length, 200);
    assert.equal(validateBanPeer({ targetNickname: '!!' }).valid, false);
  });

  it('validateKeyUpdate checks the key size', () => {
    assert.equal(validateKeyUpdate({ publicKey: pk32 }).valid, true);
    assert.equal(validateKeyUpdate({ publicKey: 'AA' }).valid, false);
  });
});
