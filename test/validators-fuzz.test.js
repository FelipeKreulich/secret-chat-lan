import { test } from 'node:test';
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
  validateListRooms,
} from '../src/protocol/validators.js';
import { PROTOCOL_VERSION } from '../src/shared/constants.js';

// Deterministic PRNG so any failure is reproducible (seed is fixed).
function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NASTY_STRINGS = [
  '',
  'a'.repeat(100_000), // over MAX_PAYLOAD
  '\x00\x01\x1f\x7f',
  '../../etc/passwd',
  '{"__proto__":{"x":1}}',
  '💣🔥'.repeat(50),
  'AAAA', // short base64
  Buffer.alloc(32).toString('base64'), // 32-byte base64 (key-shaped)
  Buffer.alloc(24).toString('base64'), // 24-byte base64 (nonce-shaped)
  '-flag',
];

function randString(rng) {
  if (rng() < 0.3) {
    return NASTY_STRINGS[Math.floor(rng() * NASTY_STRINGS.length)];
  }
  const len = Math.floor(rng() * 40);
  let s = '';
  for (let i = 0; i < len; i++) {
    s += String.fromCharCode(Math.floor(rng() * 0x2100));
  }
  return s;
}

function randValue(rng, depth) {
  const r = rng();
  if (depth > 3 || r < 0.15) {
    const prims = [null, undefined, true, false, 0, -1, NaN, Infinity, -Infinity, 1e308, 42.5];
    if (r < 0.08) return prims[Math.floor(rng() * prims.length)];
    return randString(rng);
  }
  if (r < 0.4) return randString(rng);
  if (r < 0.55) {
    const n = Math.floor(rng() * 4);
    return Array.from({ length: n }, () => randValue(rng, depth + 1));
  }
  const obj = {};
  const n = Math.floor(rng() * 5);
  const keys = ['type', 'from', 'to', 'payload', 'nickname', 'publicKey', 'room', 'x', '__proto__'];
  for (let i = 0; i < n; i++) {
    obj[keys[Math.floor(rng() * keys.length)]] = randValue(rng, depth + 1);
  }
  return obj;
}

const VALIDATORS = [
  validateJoin,
  validateEncryptedMessage,
  validateKeyUpdate,
  validateChangeRoom,
  validateKickPeer,
  validateMutePeer,
  validateBanPeer,
  validateListRooms,
];

test('parseMessage never throws and returns a boolean verdict on any input', () => {
  const rng = mulberry32(0xc0ffee);
  for (let i = 0; i < 6000; i++) {
    const raw = i % 3 === 0 ? randString(rng) : randValue(rng, 0);
    let res;
    assert.doesNotThrow(() => {
      res = parseMessage(raw);
    });
    assert.equal(typeof res.valid, 'boolean');
    if (res.valid) {
      // Anything accepted must carry the invariants parseMessage promises.
      assert.equal(typeof res.msg, 'object');
      assert.equal(res.msg.version, PROTOCOL_VERSION);
      assert.equal(typeof res.msg.type, 'string');
      assert.equal(typeof res.msg.timestamp, 'number');
    }
  }
});

test('type validators never throw on arbitrary objects', () => {
  const rng = mulberry32(0xbadf00d);
  for (let i = 0; i < 6000; i++) {
    const raw = randValue(rng, 0);
    const msg = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : { x: raw };
    for (const v of VALIDATORS) {
      let res;
      assert.doesNotThrow(() => {
        res = v(msg);
      }, `${v.name} threw`);
      assert.equal(typeof res.valid, 'boolean', `${v.name} returned a non-boolean verdict`);
    }
  }
});

test('a __proto__ payload does not pollute Object.prototype', () => {
  const before = {}.polluted;
  parseMessage(
    JSON.stringify({
      __proto__: { polluted: true },
      version: PROTOCOL_VERSION,
      type: 'join',
      timestamp: 1,
    }),
  );
  validateJoin({ __proto__: { polluted: true }, nickname: 'x', publicKey: 'y' });
  assert.equal({}.polluted, before, 'prototype must be untouched');
});

test('almost-valid messages exercise the accept path without throwing', () => {
  const rng = mulberry32(0x5eed);
  for (let i = 0; i < 2000; i++) {
    const msg = {
      version: PROTOCOL_VERSION,
      type: 'encrypted_message',
      timestamp: Date.now(),
      from: randString(rng),
      to: randString(rng),
      payload: { ciphertext: randString(rng), nonce: randString(rng) },
    };
    const parsed = parseMessage(msg);
    assert.equal(parsed.valid, true, 'well-formed envelope parses');
    let res;
    assert.doesNotThrow(() => {
      res = validateEncryptedMessage(msg);
    });
    assert.equal(typeof res.valid, 'boolean');
  }
});
