/**
 * Integration test: multi-room membership over the relay (join_room /
 * leave_room), including the private-room challenge in additive mode and
 * per-room peer notifications.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { SessionManager } from '../src/server/SessionManager.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { SecureWSServer } from '../src/server/WebSocketServer.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import {
  createJoin,
  createJoinRoom,
  createLeaveRoom,
  createRoomAuth,
  MSG,
  ERR,
} from '../src/protocol/messages.js';
import { deriveRoomSecrets, signRoomChallenge } from '../src/crypto/RoomKey.js';

const TEST_PORT = 3702;

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

async function connectAndJoin(nickname) {
  const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
  await waitForOpen(ws);
  const ackPromise = waitForMessage(ws, (m) => m.type === MSG.JOIN_ACK);
  ws.send(JSON.stringify(createJoin(nickname, new KeyManager().publicKeyB64)));
  const ack = await ackPromise;
  return { ws, sessionId: ack.sessionId };
}

describe('Multi-room membership over the relay', () => {
  let server;

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    server = new SecureWSServer(
      sessionManager,
      new MessageRouter(sessionManager, offlineQueue),
      offlineQueue,
      TEST_PORT,
    );
  });

  after(async () => {
    await server.close();
  });

  it('join_room is additive, leave_room is scoped, last room is protected', async () => {
    const alice = await connectAndJoin('Alice');
    const bob = await connectAndJoin('Bob');

    // ── Alice additively joins #dev while staying in #general ──
    const joined = waitForMessage(alice.ws, (m) => m.type === MSG.ROOM_JOINED);
    alice.ws.send(JSON.stringify(createJoinRoom('dev')));
    const devJoined = await joined;
    assert.equal(devJoined.room, 'dev');
    assert.equal(devJoined.peers.length, 0, 'dev is empty');

    // Bob joins dev too; Alice is notified WITH the room tag and Bob's ack
    // lists Alice — she never left general, yet is visible in dev.
    const aliceSawPromise = waitForMessage(
      alice.ws,
      (m) => m.type === MSG.PEER_JOINED && m.room === 'dev',
    );
    const bobAck = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_JOINED);
    bob.ws.send(JSON.stringify(createJoinRoom('dev')));
    const aliceSaw = await aliceSawPromise;
    assert.equal(aliceSaw.peer.nickname, 'Bob');
    assert.equal((await bobAck).peers.length, 1, 'Bob sees Alice in dev');

    // Joining twice fails.
    const dupErr = waitForMessage(alice.ws, (m) => m.type === MSG.ERROR);
    alice.ws.send(JSON.stringify(createJoinRoom('dev')));
    assert.match((await dupErr).message, /already in this room/i);

    // ── Bob leaves #dev: only dev peers are told, tagged ──
    const aliceSawLeave = waitForMessage(
      alice.ws,
      (m) => m.type === MSG.PEER_LEFT && m.room === 'dev',
    );
    const bobLeft = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_LEFT);
    bob.ws.send(JSON.stringify(createLeaveRoom('dev')));
    assert.equal((await bobLeft).room, 'dev');
    assert.equal((await aliceSawLeave).nickname, 'Bob');

    // ── Bob cannot leave his last room ──
    const lastErr = waitForMessage(bob.ws, (m) => m.type === MSG.ERROR);
    bob.ws.send(JSON.stringify(createLeaveRoom('general')));
    assert.match((await lastErr).message, /last room/i);

    alice.ws.close();
    bob.ws.close();
  });

  it('join_room supports the private-room challenge (additive mode)', async () => {
    const secrets = deriveRoomSecrets('cofre2', 'senha boa');
    const alice = await connectAndJoin('Ana');

    // Create the private room additively — Ana stays in general too.
    const created = waitForMessage(alice.ws, (m) => m.type === MSG.ROOM_JOINED);
    alice.ws.send(
      JSON.stringify(createJoinRoom('cofre2', secrets.authPublicKey.toString('base64'))),
    );
    assert.equal((await created).private, true);

    // Bob answers the challenge and joins WITHOUT leaving general.
    const bob = await connectAndJoin('Beto');
    const challenge = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    bob.ws.send(JSON.stringify(createJoinRoom('cofre2')));
    const ch = await challenge;

    const joined = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_JOINED);
    const sig = signRoomChallenge(secrets.authSecretKey, ch.room, ch.nonce, bob.sessionId);
    bob.ws.send(JSON.stringify(createRoomAuth(ch.room, ch.nonce, sig.toString('base64'))));
    const res = await joined;
    assert.equal(res.room, 'cofre2');
    assert.equal(res.private, true);
    assert.equal(res.peers.length, 1, 'Beto sees Ana inside');

    // Wrong password on the additive path fails too.
    const carol = await connectAndJoin('Cris');
    const wrong = deriveRoomSecrets('cofre2', 'senha errada');
    const cch = waitForMessage(carol.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    carol.ws.send(JSON.stringify(createJoinRoom('cofre2')));
    const c = await cch;
    const err = waitForMessage(carol.ws, (m) => m.type === MSG.ERROR);
    const badSig = signRoomChallenge(wrong.authSecretKey, c.room, c.nonce, carol.sessionId);
    carol.ws.send(JSON.stringify(createRoomAuth(c.room, c.nonce, badSig.toString('base64'))));
    assert.equal((await err).code, ERR.ROOM_AUTH_FAILED);

    alice.ws.close();
    bob.ws.close();
    carol.ws.close();
  });
});
