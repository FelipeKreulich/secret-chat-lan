/**
 * Capability advertisement in JOIN.
 *
 * Step 2 of #463. Nothing acts on a capability yet — this is the negotiation
 * that group send/receive will be gated on, landed first so the rollout
 * mechanism is proven before the thing it protects exists.
 *
 * The property that matters throughout: a peer that says nothing is an older
 * peer, not an error, and one such peer holds the whole room on the old path.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { SessionManager } from '../src/server/SessionManager.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { SecureWSServer } from '../src/server/WebSocketServer.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { createJoin, MSG, ERR } from '../src/protocol/messages.js';
import { validateJoin } from '../src/protocol/validators.js';
import { normalizeCaps, peerSupports, roomSupports } from '../src/protocol/capabilities.js';
import { CAP, MAX_CAPABILITIES, MAX_CAPABILITY_LENGTH } from '../src/shared/constants.js';

const TEST_PORT = 3704;

function waitForMessage(ws, predicate, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout waiting for message')), timeoutMs);
    const handler = (data) => {
      const msg = JSON.parse(data.toString());
      if (predicate(msg)) {
        clearTimeout(timer);
        ws.off('message', handler);
        resolve(msg);
      }
    };
    ws.on('message', handler);
  });
}

function waitForOpen(ws) {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.OPEN) {
      resolve();
    } else {
      ws.on('open', resolve);
    }
  });
}

// ── normalizeCaps: reading an untrusted list ────────────────────────────────

describe('normalizeCaps', () => {
  it('treats anything that is not a list as no capabilities', () => {
    for (const junk of [undefined, null, 'sk1', 42, {}, { 0: 'sk1' }]) {
      assert.deepEqual(normalizeCaps(junk), []);
    }
  });

  it('drops entries that could not have come from a well-behaved client', () => {
    const caps = normalizeCaps([
      'sk1',
      '',
      'SK1', // uppercase
      '-lead', // must start alphanumeric
      'has space',
      'x'.repeat(MAX_CAPABILITY_LENGTH + 1),
      null,
      42,
      { cap: 'sk1' },
      ['sk1'],
    ]);
    assert.deepEqual(caps, ['sk1']);
  });

  it('deduplicates and bounds the list length', () => {
    assert.deepEqual(normalizeCaps(['sk1', 'sk1', 'sk1']), ['sk1']);

    const flood = Array.from({ length: MAX_CAPABILITIES + 50 }, (_, i) => `cap${i}`);
    assert.equal(normalizeCaps(flood).length, MAX_CAPABILITIES);
  });

  it('accepts the shape real capabilities use', () => {
    assert.deepEqual(normalizeCaps([CAP.SENDER_KEYS]), ['sk1']);
    assert.deepEqual(normalizeCaps(['a', 'a1', 'a_b', 'a-b']), ['a', 'a1', 'a_b', 'a-b']);
  });
});

// ── roomSupports: the strict-consensus rule ─────────────────────────────────

describe('roomSupports', () => {
  const OWN = [CAP.SENDER_KEYS];
  const capable = { nickname: 'a', caps: [CAP.SENDER_KEYS] };
  const old = { nickname: 'b' }; // pre-capability client: no caps field at all

  it('is true when this client and every peer advertise it', () => {
    assert.equal(roomSupports([capable, capable], CAP.SENDER_KEYS, OWN), true);
  });

  it('is false when a single peer does not advertise it', () => {
    assert.equal(
      roomSupports([capable, old, capable], CAP.SENDER_KEYS, OWN),
      false,
      'one older client holds the whole room on the old path',
    );
  });

  it('is false when this client does not advertise it, however capable the room', () => {
    assert.equal(roomSupports([capable, capable], CAP.SENDER_KEYS, []), false);
  });

  it('is vacuously true in an empty room', () => {
    assert.equal(roomSupports([], CAP.SENDER_KEYS, OWN), true, 'nobody left to misunderstand');
  });

  it('accepts an iterator, not just an array', () => {
    // ChatController passes a Map's .values() straight in.
    const m = new Map([['sid', capable]]);
    assert.equal(roomSupports(m.values(), CAP.SENDER_KEYS, OWN), true);
  });

  it('does not confuse one capability for another', () => {
    const other = { caps: ['other'] };
    assert.equal(roomSupports([other], CAP.SENDER_KEYS, OWN), false);
    assert.equal(peerSupports(other, 'other'), true);
    assert.equal(peerSupports(other, CAP.SENDER_KEYS), false);
  });

  it('ignores a peer capability that survived neither validation nor normalisation', () => {
    assert.equal(roomSupports([{ caps: ['SK1'] }], CAP.SENDER_KEYS, OWN), false);
    assert.equal(roomSupports([{ caps: 'sk1' }], CAP.SENDER_KEYS, OWN), false);
  });
});

// ── createJoin: additive on the wire ────────────────────────────────────────

describe('createJoin with capabilities', () => {
  const pk = 'A'.repeat(43) + '=';

  it('omits the field entirely when there is nothing to advertise', () => {
    for (const nothing of [undefined, null, []]) {
      const msg = createJoin('Alice', pk, null, nothing);
      assert.equal('caps' in msg, false, 'wire is byte-identical to a pre-capability client');
    }
  });

  it('includes and copies the list when there is', () => {
    const own = [CAP.SENDER_KEYS];
    const msg = createJoin('Alice', pk, null, own);
    assert.deepEqual(msg.caps, ['sk1']);

    msg.caps.push('mutated');
    assert.deepEqual(own, [CAP.SENDER_KEYS], 'the caller’s array is not aliased');
  });
});

// ── validateJoin: the relay rejects rather than forwards junk ───────────────

describe('validateJoin capability handling', () => {
  const pk = Buffer.alloc(32, 7).toString('base64');
  const join = (caps) => ({ nickname: 'Alice', publicKey: pk, ...(caps !== undefined && { caps }) });

  it('a JOIN without the field is valid and advertises nothing', () => {
    const r = validateJoin(join(undefined));
    assert.equal(r.valid, true);
    assert.deepEqual(r.capabilities, [], 'absent is an older client, not an error');
  });

  it('accepts a well-formed list and deduplicates it', () => {
    const r = validateJoin(join([CAP.SENDER_KEYS, CAP.SENDER_KEYS]));
    assert.equal(r.valid, true);
    assert.deepEqual(r.capabilities, ['sk1']);
  });

  it('rejects a malformed list rather than filtering it', () => {
    // The relay stores this and hands it to other clients. Forwarding the good
    // half of a bad list would make a peer look capable of something it never
    // claimed, so the whole JOIN is refused.
    const bad = [
      'sk1', // not a list
      { sk1: true },
      ['sk1', ''], // empty entry
      ['sk1', 'UPPER'],
      ['sk1', 'has space'],
      ['sk1', 'x'.repeat(MAX_CAPABILITY_LENGTH + 1)],
      ['sk1', null],
      ['sk1', 42],
      ['sk1', ['nested']],
      ['-leading-dash'],
      Array.from({ length: MAX_CAPABILITIES + 1 }, (_, i) => `cap${i}`),
    ];
    for (const caps of bad) {
      const r = validateJoin(join(caps));
      assert.equal(r.valid, false, `should reject ${JSON.stringify(caps)}`);
      assert.match(r.error, /capability/i);
    }
  });

  it('accepts exactly the maximum number of capabilities', () => {
    const max = Array.from({ length: MAX_CAPABILITIES }, (_, i) => `cap${i}`);
    const r = validateJoin(join(max));
    assert.equal(r.valid, true, 'the bound is inclusive');
    assert.equal(r.capabilities.length, MAX_CAPABILITIES);
  });
});

// ── End to end through a real relay ─────────────────────────────────────────

describe('capabilities across the relay', () => {
  let server;

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    const messageRouter = new MessageRouter(sessionManager, offlineQueue);
    server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, TEST_PORT);
  });

  after(async () => {
    await server.close();
  });

  it('relays a capability list verbatim, and a silent peer stays silent', async () => {
    const aliceKeys = new KeyManager();
    const bobKeys = new KeyManager();

    // Alice advertises; Bob is a pre-capability client and sends no field.
    const aliceWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(aliceWs);
    const aliceAckP = waitForMessage(aliceWs, (m) => m.type === MSG.JOIN_ACK);
    aliceWs.send(
      JSON.stringify(createJoin('AliceCap', aliceKeys.publicKeyB64, null, [CAP.SENDER_KEYS])),
    );
    await aliceAckP;

    const bobWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(bobWs);
    const alicePeerJoinedP = waitForMessage(aliceWs, (m) => m.type === MSG.PEER_JOINED);
    const bobAckP = waitForMessage(bobWs, (m) => m.type === MSG.JOIN_ACK);
    bobWs.send(JSON.stringify(createJoin('BobOld', bobKeys.publicKeyB64)));
    const [bobAck, alicePeerJoined] = await Promise.all([bobAckP, alicePeerJoinedP]);

    // Bob's peer list carries what Alice advertised, unchanged.
    const aliceAsSeenByBob = bobAck.peers.find((p) => p.nickname === 'AliceCap');
    assert.deepEqual(aliceAsSeenByBob.caps, ['sk1'], 'joinAck carries the list through');

    // Alice's view of Bob has no caps field at all — absent, not empty.
    assert.equal(
      'caps' in alicePeerJoined.peer,
      false,
      'peer_joined omits the field for a client that advertised nothing',
    );

    // Which is exactly the room that must not switch paths.
    assert.equal(
      roomSupports([aliceAsSeenByBob], CAP.SENDER_KEYS, [CAP.SENDER_KEYS]),
      true,
      'Bob would see Alice as capable…',
    );
    assert.equal(
      roomSupports([alicePeerJoined.peer], CAP.SENDER_KEYS, [CAP.SENDER_KEYS]),
      false,
      '…but Alice sees Bob is not, so the room stays on the per-peer path',
    );

    aliceWs.close();
    bobWs.close();
  });

  it('refuses a JOIN carrying a malformed capability list', async () => {
    const keys = new KeyManager();
    const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws);

    const errP = waitForMessage(ws, (m) => m.type === MSG.ERROR);
    const join = createJoin('Mallory', keys.publicKeyB64);
    join.caps = Array.from({ length: MAX_CAPABILITIES + 1 }, (_, i) => `cap${i}`);
    ws.send(JSON.stringify(join));

    const err = await errP;
    assert.equal(err.code, ERR.INVALID_MESSAGE);
    assert.match(err.message, /capability/i);

    ws.close();
  });
});
