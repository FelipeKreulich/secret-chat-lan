/**
 * The identity key on the wire — step 2 of multi-device (item 4 of #481).
 *
 * Nothing reads this key yet. That is the point of landing it now, and it is
 * also why it needs a test: an advertisement nobody consumes can stop arriving
 * without a single symptom, and the first person to notice would be whoever
 * builds step 3 on the assumption that it is there.
 *
 * So what is proven here is only the trip: a JOIN carries it, the relay passes
 * it on verbatim to the peer list and to PEER_JOINED, and a client that sends
 * none is an older client rather than an error.
 *
 * What is deliberately *not* proven is that it means anything. The relay
 * forwards this key without being able to check it belongs to the session that
 * sent it — a hostile relay can substitute one, and a client must not trust it
 * until a signed device list is checked against it in step 3.
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

const TEST_PORT = 3708;

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

// ── validateJoin: the shape, and nothing more ───────────────────────────────

describe('validateJoin — identity key', () => {
  const keys = new KeyManager();
  const base = () => ({ nickname: 'alice', publicKey: keys.publicKeyB64 });

  after(() => keys.destroy());

  it('accepts a JOIN without one', () => {
    // An older client. Absence is the pre-multi-device state, not a fault.
    const result = validateJoin(base());
    assert.equal(result.valid, true);
    assert.equal(result.identityKey, null);
  });

  it('accepts and returns a well-formed one', () => {
    const result = validateJoin({ ...base(), identityKey: keys.identityPublicKeyB64 });
    assert.equal(result.valid, true);
    assert.equal(result.identityKey, keys.identityPublicKeyB64);
  });

  it('rejects anything that is not a 32-byte key', () => {
    for (const junk of [
      '',
      'not base64 at all!!',
      Buffer.alloc(16).toString('base64'),
      Buffer.alloc(64).toString('base64'),
      42,
      {},
      [],
    ]) {
      const result = validateJoin({ ...base(), identityKey: junk });
      assert.equal(result.valid, false, `${JSON.stringify(junk)} should be refused`);
      assert.match(result.error, /identity key/i);
    }
  });
});

// ── Through a real relay ────────────────────────────────────────────────────

describe('identity key through the relay', () => {
  let server;
  const sockets = [];

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    const messageRouter = new MessageRouter(sessionManager, offlineQueue);
    server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, TEST_PORT);
  });

  after(async () => {
    for (const ws of sockets) {
      try {
        ws.close();
      } catch {
        /* already gone */
      }
    }
    await server.close();
  });

  const connect = async () => {
    const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
    sockets.push(ws);
    await waitForOpen(ws);
    return ws;
  };

  const join = async (ws, nick, keys, withIdentity = true) => {
    const ack = waitForMessage(ws, (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR);
    ws.send(
      JSON.stringify(
        createJoin(
          nick,
          keys.publicKeyB64,
          keys.pqPublicKeyB64,
          [],
          withIdentity ? keys.identityPublicKeyB64 : null,
        ),
      ),
    );
    return ack;
  };

  it('reaches a peer already in the room, through the peer list', async () => {
    const alice = new KeyManager();
    const bob = new KeyManager();

    const aliceWs = await connect();
    await join(aliceWs, 'ident_alice', alice);

    const bobWs = await connect();
    const ack = await join(bobWs, 'ident_bob', bob);

    const seen = ack.peers.find((p) => p.nickname === 'ident_alice');
    assert.ok(seen, 'bob sees alice');
    assert.equal(
      seen.identityKey,
      alice.identityPublicKeyB64,
      'relayed verbatim, byte for byte — the relay must not normalise it either',
    );

    alice.destroy();
    bob.destroy();
  });

  it('reaches a peer who was already there, through PEER_JOINED', async () => {
    const alice = new KeyManager();
    const carol = new KeyManager();

    const aliceWs = await connect();
    await join(aliceWs, 'pj_alice', alice);

    const joined = waitForMessage(aliceWs, (m) => m.type === MSG.PEER_JOINED);
    const carolWs = await connect();
    await join(carolWs, 'pj_carol', carol);

    const msg = await joined;
    assert.equal(msg.peer.nickname, 'pj_carol');
    assert.equal(msg.peer.identityKey, carol.identityPublicKeyB64);

    alice.destroy();
    carol.destroy();
  });

  it('omits the field for a client that sends none, rather than inventing one', async () => {
    const older = new KeyManager();
    const watcher = new KeyManager();

    const olderWs = await connect();
    await join(olderWs, 'old_client', older, false);

    const watcherWs = await connect();
    const ack = await join(watcherWs, 'old_watcher', watcher);

    const seen = ack.peers.find((p) => p.nickname === 'old_client');
    assert.ok(seen, 'an older client is still a peer');
    assert.equal(seen.identityKey, undefined, 'absent, not null and not guessed');

    older.destroy();
    watcher.destroy();
  });

  it('refuses a JOIN whose identity key is malformed', async () => {
    const keys = new KeyManager();
    const ws = await connect();

    const reply = waitForMessage(ws, (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR);
    ws.send(
      JSON.stringify({
        ...createJoin('bad_ident', keys.publicKeyB64),
        identityKey: Buffer.alloc(16).toString('base64'),
      }),
    );

    const msg = await reply;
    assert.equal(msg.type, MSG.ERROR);
    assert.equal(msg.code, ERR.INVALID_MESSAGE);

    keys.destroy();
  });
});
