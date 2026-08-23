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
import { newDeviceId, signDeviceList } from '../src/crypto/DeviceIdentity.js';

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

  // ── One nickname, two devices (#481, step 5) ──────────────────
  //
  // A name is held by a person, not a connection. The proof that a second
  // session belongs to the same person is the signed device list in its JOIN:
  // signed by the identity the existing sessions use, and naming this JOIN's
  // own public key.
  //
  // No challenge, and none invented. Replaying somebody else's list buys a seat
  // in a room under a name whose messages you cannot read, because you do not
  // hold the box secret it names.

  const listFor = (identity, counter, keys) =>
    signDeviceList(
      identity,
      counter,
      keys.map((boxPk) => ({
        deviceId: newDeviceId(),
        boxPk,
        label: '',
        createdAt: 1755000000000,
      })),
    );

  it('admits a second device under a name its first device holds', async () => {
    const laptop = new KeyManager();
    const phone = new KeyManager();
    const list = listFor(laptop.identity, 2, [laptop.publicKeyB64, phone.publicKeyB64]);

    const laptopWs = await connect();
    await join(laptopWs, 'two_dev', laptop);

    const phoneWs = await connect();
    const ack = waitForMessage(phoneWs, (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR);
    phoneWs.send(
      JSON.stringify(
        createJoin('two_dev', phone.publicKeyB64, null, [], laptop.identityPublicKeyB64, list),
      ),
    );

    const msg = await ack;
    assert.equal(msg.type, MSG.JOIN_ACK, 'the phone got in under the same name');

    laptop.destroy();
    phone.destroy();
  });

  it('still refuses a stranger who simply claims the name', async () => {
    const owner = new KeyManager();
    const stranger = new KeyManager();

    const ownerWs = await connect();
    await join(ownerWs, 'not_yours', owner);

    const strangerWs = await connect();
    const reply = waitForMessage(
      strangerWs,
      (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR,
    );
    strangerWs.send(JSON.stringify(createJoin('not_yours', stranger.publicKeyB64)));

    const msg = await reply;
    assert.equal(msg.type, MSG.ERROR);
    assert.equal(msg.code, ERR.NICKNAME_TAKEN);

    owner.destroy();
    stranger.destroy();
  });

  it('refuses a list that does not name the key joining under it', async () => {
    // The check that makes a replayed list worthless: you have to be *in* the
    // list you present.
    const owner = new KeyManager();
    const stranger = new KeyManager();
    const list = listFor(owner.identity, 2, [owner.publicKeyB64]);

    const ownerWs = await connect();
    await join(ownerWs, 'replay_me', owner);

    const strangerWs = await connect();
    const reply = waitForMessage(
      strangerWs,
      (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR,
    );
    strangerWs.send(
      JSON.stringify(
        createJoin('replay_me', stranger.publicKeyB64, null, [], owner.identityPublicKeyB64, list),
      ),
    );

    const msg = await reply;
    assert.equal(msg.code, ERR.NICKNAME_TAKEN);

    owner.destroy();
    stranger.destroy();
  });

  it('refuses a list signed by an identity the name is not using', async () => {
    const owner = new KeyManager();
    const stranger = new KeyManager();
    // Correctly signed — by the wrong identity.
    const list = listFor(stranger.identity, 2, [stranger.publicKeyB64]);

    const ownerWs = await connect();
    await join(ownerWs, 'wrong_ident', owner);

    const strangerWs = await connect();
    const reply = waitForMessage(
      strangerWs,
      (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR,
    );
    strangerWs.send(
      JSON.stringify(
        createJoin(
          'wrong_ident',
          stranger.publicKeyB64,
          null,
          [],
          stranger.identityPublicKeyB64,
          list,
        ),
      ),
    );

    const msg = await reply;
    assert.equal(msg.code, ERR.NICKNAME_TAKEN);

    owner.destroy();
    stranger.destroy();
  });

  it('frees the name only when the last device leaves', async () => {
    const laptop = new KeyManager();
    const phone = new KeyManager();
    const list = listFor(laptop.identity, 2, [laptop.publicKeyB64, phone.publicKeyB64]);

    const laptopWs = await connect();
    await join(laptopWs, 'last_one', laptop);
    const phoneWs = await connect();
    const phoneAck = waitForMessage(phoneWs, (m) => m.type === MSG.JOIN_ACK);
    phoneWs.send(
      JSON.stringify(
        createJoin('last_one', phone.publicKeyB64, null, [], laptop.identityPublicKeyB64, list),
      ),
    );
    await phoneAck;

    // The laptop goes; the phone still answers to the name.
    laptopWs.close();
    await new Promise((resolve) => setTimeout(resolve, 150));

    const stranger = new KeyManager();
    const strangerWs = await connect();
    const reply = waitForMessage(
      strangerWs,
      (m) => m.type === MSG.JOIN_ACK || m.type === MSG.ERROR,
    );
    strangerWs.send(JSON.stringify(createJoin('last_one', stranger.publicKeyB64)));

    const msg = await reply;
    assert.equal(msg.code, ERR.NICKNAME_TAKEN, 'the name is still held by the phone');

    laptop.destroy();
    phone.destroy();
    stranger.destroy();
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
