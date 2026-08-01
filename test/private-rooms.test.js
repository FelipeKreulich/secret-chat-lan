/**
 * Integration test: password-protected private rooms over the relay.
 * Covers create → challenge → auth (right/wrong password), the ROOM_EXISTS
 * guard, and the room (verifier included) dying with its last member.
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
  createChangeRoom,
  createRoomAuth,
  createListRooms,
  MSG,
  ERR,
} from '../src/protocol/messages.js';
import { deriveRoomSecrets, signRoomChallenge } from '../src/crypto/RoomKey.js';

const TEST_PORT = 3701;
const ROOM = 'cofre';

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

describe('Private rooms — challenge-response over the relay', () => {
  let server;
  // Argon2id is slow — derive once, reuse everywhere.
  let rightSecrets;
  let wrongSecrets;

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    server = new SecureWSServer(
      sessionManager,
      new MessageRouter(sessionManager, offlineQueue),
      offlineQueue,
      TEST_PORT,
    );
    rightSecrets = deriveRoomSecrets(ROOM, 'senha secreta');
    wrongSecrets = deriveRoomSecrets(ROOM, 'senha errada');
  });

  after(async () => {
    await server.close();
  });

  it('runs the full private-room lifecycle', async () => {
    // ── Alice creates the private room ───────────────────
    const alice = await connectAndJoin('Alice');
    const aliceChanged = waitForMessage(alice.ws, (m) => m.type === MSG.ROOM_CHANGED);
    alice.ws.send(
      JSON.stringify(createChangeRoom(ROOM, rightSecrets.authPublicKey.toString('base64'))),
    );
    const created = await aliceChanged;
    assert.equal(created.room, ROOM);
    assert.equal(created.private, true, 'room is flagged private on creation');

    // ── The room list shows the lock ─────────────────────
    const listPromise = waitForMessage(alice.ws, (m) => m.type === MSG.ROOM_LIST);
    alice.ws.send(JSON.stringify(createListRooms()));
    const list = await listPromise;
    assert.equal(list.rooms.find((r) => r.name === ROOM).private, true);

    // ── Creating it again fails: it exists ───────────────
    const dave = await connectAndJoin('Dave');
    const daveError = waitForMessage(dave.ws, (m) => m.type === MSG.ERROR);
    dave.ws.send(
      JSON.stringify(createChangeRoom(ROOM, wrongSecrets.authPublicKey.toString('base64'))),
    );
    assert.equal((await daveError).code, ERR.ROOM_EXISTS);

    // ── general can never be created as private ──────────
    const daveError2 = waitForMessage(dave.ws, (m) => m.type === MSG.ERROR);
    dave.ws.send(
      JSON.stringify(createChangeRoom('general', wrongSecrets.authPublicKey.toString('base64'))),
    );
    assert.equal((await daveError2).code, ERR.ROOM_EXISTS);
    dave.ws.close();

    // ── Bob joins with the RIGHT password ────────────────
    const bob = await connectAndJoin('Bob');
    const bobChallenge = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    bob.ws.send(JSON.stringify(createChangeRoom(ROOM)));
    const challenge = await bobChallenge;
    assert.equal(challenge.room, ROOM);
    assert.ok(challenge.nonce, 'challenge carries a nonce');

    const bobChanged = waitForMessage(bob.ws, (m) => m.type === MSG.ROOM_CHANGED);
    const alicePeerJoined = waitForMessage(alice.ws, (m) => m.type === MSG.PEER_JOINED);
    const signature = signRoomChallenge(
      rightSecrets.authSecretKey,
      challenge.room,
      challenge.nonce,
      bob.sessionId,
    );
    bob.ws.send(
      JSON.stringify(createRoomAuth(challenge.room, challenge.nonce, signature.toString('base64'))),
    );
    const bobRoom = await bobChanged;
    assert.equal(bobRoom.room, ROOM);
    assert.equal(bobRoom.private, true);
    assert.equal(bobRoom.peers.length, 1, 'Bob sees Alice inside');
    assert.equal((await alicePeerJoined).peer.nickname, 'Bob');

    // ── Carol tries the WRONG password ───────────────────
    const carol = await connectAndJoin('Carol');
    const carolChallenge = waitForMessage(carol.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    carol.ws.send(JSON.stringify(createChangeRoom(ROOM)));
    const cch = await carolChallenge;

    const carolError = waitForMessage(carol.ws, (m) => m.type === MSG.ERROR);
    const badSig = signRoomChallenge(
      wrongSecrets.authSecretKey,
      cch.room,
      cch.nonce,
      carol.sessionId,
    );
    carol.ws.send(JSON.stringify(createRoomAuth(cch.room, cch.nonce, badSig.toString('base64'))));
    assert.equal((await carolError).code, ERR.ROOM_AUTH_FAILED);

    // ── A stolen signature doesn't work for another session ──
    const carolChallenge2 = waitForMessage(carol.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    carol.ws.send(JSON.stringify(createChangeRoom(ROOM)));
    const cch2 = await carolChallenge2;
    const carolError2 = waitForMessage(carol.ws, (m) => m.type === MSG.ERROR);
    // Signature made by Bob's session (right password!) over Carol's nonce —
    // still rejected because the sessionId is bound into the signed message.
    const stolen = signRoomChallenge(
      rightSecrets.authSecretKey,
      cch2.room,
      cch2.nonce,
      bob.sessionId,
    );
    carol.ws.send(JSON.stringify(createRoomAuth(cch2.room, cch2.nonce, stolen.toString('base64'))));
    assert.equal((await carolError2).code, ERR.ROOM_AUTH_FAILED);

    // ── Room (and verifier) dies with the last member ────
    alice.ws.close();
    bob.ws.close();
    // Poll until the server has processed both disconnects.
    for (let i = 0; i < 50; i++) {
      const l = waitForMessage(carol.ws, (m) => m.type === MSG.ROOM_LIST);
      carol.ws.send(JSON.stringify(createListRooms()));
      if (!(await l).rooms.some((r) => r.name === ROOM)) {
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    // Carol can now enter freely — the old password is gone and the room is
    // recreated as public.
    const carolChanged = waitForMessage(carol.ws, (m) => m.type === MSG.ROOM_CHANGED);
    carol.ws.send(JSON.stringify(createChangeRoom(ROOM)));
    const recreated = await carolChanged;
    assert.equal(recreated.room, ROOM);
    assert.ok(!recreated.private, 'recreated room is public');
    carol.ws.close();
  });
});
