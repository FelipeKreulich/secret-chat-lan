/**
 * Kick and ban announce a departure, not just a notification (#481).
 *
 * `peer_kicked` carries a nickname and a reason — enough to print a line, and
 * nothing a client can remove a member *by*. Nicknames are not identities here:
 * `/nick` reassigns them, so a client that unwound a peer by name would drop the
 * wrong session as soon as two people had ever shared one. The result was that
 * every remaining client kept the kicked peer in its roster indefinitely.
 *
 * While the relay path seals one envelope per peer that is a stale list. Once a
 * room encrypts once to a shared sender chain it stops being cosmetic, because
 * "who is still in this room" is exactly the input that decides when a chain has
 * to be rotated away from someone. A membership change the client never hears
 * about is a chain that is never rotated.
 *
 * So every way out of a room now ends in one `peer_left`: leaving, switching,
 * disconnecting, being kicked, being banned.
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
  createKickPeer,
  createBanPeer,
  MSG,
} from '../src/protocol/messages.js';

const TEST_PORT = 3707;

function waitForOpen(ws) {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.OPEN) {
      resolve();
    } else {
      ws.on('open', resolve);
    }
  });
}

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

// Record everything a socket receives, so a test can assert on the *order* of
// two messages rather than only on their arrival.
function record(ws) {
  const seen = [];
  ws.on('message', (data) => seen.push(JSON.parse(data.toString())));
  return seen;
}

function settle(ms = 300) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('a kicked or banned peer is announced as having left', () => {
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

  const join = async (nick) => {
    const keys = new KeyManager();
    const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws);
    const ackP = waitForMessage(ws, (m) => m.type === MSG.JOIN_ACK);
    ws.send(JSON.stringify(createJoin(nick, keys.publicKeyB64)));
    const ack = await ackP;
    return { ws, keys, ack, sessionId: ack.sessionId };
  };

  // Ownership is what /kick and /ban are gated on, and `general` has no owner.
  // The first session into an empty non-general room becomes its owner.
  const openRoom = async (nick, room) => {
    const peer = await join(nick);
    const changed = waitForMessage(peer.ws, (m) => m.type === MSG.ROOM_CHANGED);
    peer.ws.send(JSON.stringify(createChangeRoom(room)));
    await changed;
    return peer;
  };

  const enterRoom = async (nick, room) => {
    const peer = await join(nick);
    const changed = waitForMessage(peer.ws, (m) => m.type === MSG.ROOM_CHANGED);
    peer.ws.send(JSON.stringify(createChangeRoom(room)));
    await changed;
    return peer;
  };

  it('a kick reaches the room as peer_left, naming the session', async () => {
    const owner = await openRoom('KickOwner', 'kick-room');
    const target = await enterRoom('KickTarget', 'kick-room');
    const bystander = await enterRoom('KickBystander', 'kick-room');

    const leftP = waitForMessage(
      bystander.ws,
      (m) => m.type === MSG.PEER_LEFT && m.sessionId === target.sessionId,
    );

    owner.ws.send(JSON.stringify(createKickPeer('KickTarget', 'spam')));
    const left = await leftP;

    assert.equal(
      left.room,
      'kick-room',
      'tagged with the room, so a multi-room client drops the peer from exactly one buffer',
    );
    assert.equal(left.nickname, 'KickTarget');

    for (const p of [owner, target, bystander]) {
      p.ws.close();
    }
  });

  it('the kick notification names the session too, so the two can be matched', async () => {
    const owner = await openRoom('MatchOwner', 'match-room');
    const target = await enterRoom('MatchTarget', 'match-room');
    const bystander = await enterRoom('MatchBystander', 'match-room');

    const kickedP = waitForMessage(bystander.ws, (m) => m.type === MSG.PEER_KICKED);
    owner.ws.send(JSON.stringify(createKickPeer('MatchTarget', 'reason here')));
    const kicked = await kickedP;

    assert.equal(
      kicked.sessionId,
      target.sessionId,
      'without this a client cannot tell which peer_left was a kick, and reports it as an ordinary departure',
    );
    assert.equal(kicked.nickname, 'MatchTarget');
    assert.equal(kicked.reason, 'reason here');

    for (const p of [owner, target, bystander]) {
      p.ws.close();
    }
  });

  it('the kick is announced before the departure', async () => {
    // Order is what lets a client report one event once. It marks the session
    // on peer_kicked and, when peer_left arrives, unwinds the member without
    // announcing a second time. Reversed, the client would print "left" and
    // then "was kicked" for a single event.
    const owner = await openRoom('OrderOwner', 'order-room');
    const target = await enterRoom('OrderTarget', 'order-room');
    const bystander = await enterRoom('OrderBystander', 'order-room');

    const seen = record(bystander.ws);
    owner.ws.send(JSON.stringify(createKickPeer('OrderTarget', '')));
    await settle();

    const kickedAt = seen.findIndex((m) => m.type === MSG.PEER_KICKED);
    const leftAt = seen.findIndex(
      (m) => m.type === MSG.PEER_LEFT && m.sessionId === target.sessionId,
    );

    assert.ok(kickedAt >= 0, 'the kick was announced');
    assert.ok(leftAt >= 0, 'the departure was announced');
    assert.ok(kickedAt < leftAt, 'peer_kicked must arrive first');

    for (const p of [owner, target, bystander]) {
      p.ws.close();
    }
  });

  it('a ban reaches the room as peer_left as well', async () => {
    // Ban moves the target exactly the way kick does, and had the same gap.
    const owner = await openRoom('BanOwner', 'ban-room');
    const target = await enterRoom('BanTarget', 'ban-room');
    const bystander = await enterRoom('BanBystander', 'ban-room');

    const leftP = waitForMessage(
      bystander.ws,
      (m) => m.type === MSG.PEER_LEFT && m.sessionId === target.sessionId,
    );

    owner.ws.send(JSON.stringify(createBanPeer('BanTarget', 'repeat offender')));
    const left = await leftP;

    assert.equal(left.room, 'ban-room');

    for (const p of [owner, target, bystander]) {
      p.ws.close();
    }
  });

  it('the departure is not echoed to the peer being removed', async () => {
    // They are told they were kicked and handed a new room; a peer_left about
    // themselves, in a room they are no longer in, would be one more thing for
    // a client to have to ignore correctly.
    const owner = await openRoom('EchoOwner', 'echo-room');
    const target = await enterRoom('EchoTarget', 'echo-room');

    const seen = record(target.ws);
    owner.ws.send(JSON.stringify(createKickPeer('EchoTarget', '')));
    await settle();

    assert.ok(
      seen.some((m) => m.type === MSG.PEER_KICKED),
      'the target still learns it was kicked',
    );
    assert.ok(
      !seen.some((m) => m.type === MSG.PEER_LEFT && m.sessionId === target.sessionId),
      'but is not told about its own departure',
    );

    for (const p of [owner, target]) {
      p.ws.close();
    }
  });
});
