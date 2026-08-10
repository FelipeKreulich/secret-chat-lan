/**
 * Sender keys on the relay — the receive half (#463, step 3).
 *
 * Two things are proven here that the client-side tests cannot reach: the
 * `keyId` machinery that lets a recipient pick a chain without the relay
 * naming a sender, and the relay's room fan-out itself.
 *
 * The property the relay must keep: it forwards what it was handed, to the room
 * the sender is in, and adds nothing. A room-addressed envelope is the one place
 * where stamping a sender would be easy and would quietly undo sealed sender.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { SessionManager } from '../src/server/SessionManager.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { SecureWSServer } from '../src/server/WebSocketServer.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { GroupSession, SenderChain, groupEncrypt } from '../src/crypto/SenderKey.js';
import { createJoin, createGroupMessage, MSG, ERR } from '../src/protocol/messages.js';
import { validateGroupMessage } from '../src/protocol/validators.js';
import { CAP } from '../src/shared/constants.js';

const TEST_PORT = 3705;

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

// Nothing arrives within the window. Used to assert an absence, which is the
// only way to state "the sender did not get its own fan-out back".
function expectNothing(ws, predicate, ms = 250) {
  return new Promise((resolve, reject) => {
    const handler = (data) => {
      if (predicate(JSON.parse(data.toString()))) {
        reject(new Error('received a message that should not have arrived'));
      }
    };
    ws.on('message', handler);
    setTimeout(() => {
      ws.off('message', handler);
      resolve();
    }, ms);
  });
}

// ── keyId: naming a chain without naming a sender ───────────────────────────

describe('GroupSession key ids', () => {
  it('hands the label out with the distribution and stamps it on every packet', () => {
    const alice = new GroupSession();
    const dist = alice.distribution();

    assert.equal(typeof dist.keyId, 'string');
    assert.equal(Buffer.from(dist.keyId, 'base64').length, 16);
    assert.equal(dist.keyId, alice.keyId);
    assert.equal(alice.encrypt('x').keyId, dist.keyId, 'a packet names the chain that sealed it');

    alice.destroy();
  });

  it('resolves a label to the member it was distributed by', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    const dist = alice.distribution();
    bob.addMember('alice-sid', dist);

    assert.equal(bob.memberForKeyId(dist.keyId), 'alice-sid');
    assert.equal(bob.memberForKeyId('unknown-label'), null, 'an unknown label resolves to nobody');

    alice.destroy();
    bob.destroy();
  });

  it('gives every chain its own label, so two senders never collide', () => {
    const a = new GroupSession();
    const b = new GroupSession();
    assert.notEqual(a.keyId, b.keyId);

    const bob = new GroupSession();
    bob.addMember('a', a.distribution());
    bob.addMember('b', b.distribution());
    assert.equal(bob.memberForKeyId(a.keyId), 'a');
    assert.equal(bob.memberForKeyId(b.keyId), 'b');

    a.destroy();
    b.destroy();
    bob.destroy();
  });

  it('draws a fresh label on rotation, and drops the old one on redistribution', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    const before = alice.distribution();
    bob.addMember('alice', before);

    alice.rotate();
    assert.notEqual(alice.keyId, before.keyId, 'the label does not outlive the chain it names');

    // Until redistribution bob still maps the stale label — he has not been told.
    assert.equal(bob.memberForKeyId(before.keyId), 'alice');

    const after = alice.distribution();
    bob.addMember('alice', after);
    assert.equal(bob.memberForKeyId(after.keyId), 'alice');
    assert.equal(
      bob.memberForKeyId(before.keyId),
      null,
      'the superseded label must not keep pointing at a chain that can no longer open it',
    );

    alice.destroy();
    bob.destroy();
  });

  it('forgets a departed member’s label', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    const dist = alice.distribution();
    bob.addMember('alice', dist);

    bob.removeMember('alice');
    assert.equal(bob.memberForKeyId(dist.keyId), null);
    assert.equal(bob.hasMember('alice'), false);

    alice.destroy();
    bob.destroy();
  });

  it('round-trips a packet chosen by its label', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    bob.addMember('alice', alice.distribution());

    const packet = alice.encrypt('hello room');
    const from = bob.memberForKeyId(packet.keyId);
    assert.equal(bob.decrypt(from, packet).toString('utf-8'), 'hello room');

    alice.destroy();
    bob.destroy();
  });
});

// ── Who wrote it, not just which room it came from ──────────────────────────
//
// A sender chain is symmetric: every member holds the key that decrypts a given
// sender, so every member can also produce ciphertext on it. Without a
// per-sender signature, "Alice said this" means only "somebody in this room said
// this" — and on a public relay that is a much wider set of somebodies than in
// the P2P mesh this code came from.

describe('group message authenticity', () => {
  it('rejects a packet forged by another member of the same room', () => {
    // Mallory is a legitimate member: she was given Alice's distribution, which
    // is exactly what lets her decrypt Alice — and, symmetrically, encrypt on
    // Alice's chain. That is the attack.
    const alice = new GroupSession();
    const bob = new GroupSession();
    const mallory = new GroupSession();

    const aliceDist = alice.distribution();
    bob.addMember('alice', aliceDist);
    mallory.addMember('alice', aliceDist);

    // Mallory rebuilds Alice's chain and produces a packet on it, labelled with
    // Alice's keyId so Bob will route it to Alice's chain.
    const forgedChain = SenderChain.deserialize(aliceDist);
    const { messageKey, counter } = forgedChain.deriveNext();
    const { ciphertext, nonce } = groupEncrypt(messageKey, 'transfer the funds');
    const forged = {
      keyId: aliceDist.keyId,
      counter,
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64'),
      signature: Buffer.alloc(64).toString('base64'),
    };

    assert.equal(bob.memberForKeyId(forged.keyId), 'alice', 'it does route to Alice…');
    assert.equal(
      bob.decrypt('alice', forged),
      null,
      '…and is refused for want of Alice’s signature',
    );

    // The genuine article still works, so the rejection is about the signature
    // and not about the chain having been disturbed.
    assert.equal(
      bob.decrypt('alice', alice.encrypt('the real thing')).toString('utf-8'),
      'the real thing',
    );

    forgedChain.destroy();
    alice.destroy();
    bob.destroy();
    mallory.destroy();
  });

  it('rejects a packet signed by the wrong member', () => {
    // Mallory signs with her own key, which is well-formed but not Alice's.
    const alice = new GroupSession();
    const bob = new GroupSession();
    const mallory = new GroupSession();
    const aliceDist = alice.distribution();
    bob.addMember('alice', aliceDist);

    const mallorysOwn = mallory.encrypt('hello');
    const wearingAlicesLabel = { ...mallorysOwn, keyId: aliceDist.keyId };
    assert.equal(bob.decrypt('alice', wearingAlicesLabel), null);

    alice.destroy();
    bob.destroy();
    mallory.destroy();
  });

  it('rejects a tampered field even though the box would still open', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    bob.addMember('alice', alice.distribution());
    const packet = alice.encrypt('original');

    // The counter is outside the AEAD, so nothing but the signature protects it.
    assert.equal(bob.decrypt('alice', { ...packet, counter: packet.counter + 5 }), null);
    // And the label likewise.
    assert.equal(bob.decrypt('alice', { ...packet, keyId: 'AAAAAAAAAAAAAAAAAAAAAA==' }), null);

    alice.destroy();
    bob.destroy();
  });

  it('refuses a forgery without disturbing the chain it was aimed at', () => {
    // The reason verification happens before messageKeyFor(): an unauthenticated
    // packet carrying a large counter must not be able to make the receiver
    // derive and cache a thousand message keys.
    const alice = new GroupSession();
    const bob = new GroupSession();
    bob.addMember('alice', alice.distribution());

    const real = alice.encrypt('first');
    const forged = { ...real, counter: 900, signature: Buffer.alloc(64).toString('base64') };
    assert.equal(bob.decrypt('alice', forged), null);

    // Counter 0 still opens, so the forgery advanced nothing.
    assert.equal(bob.decrypt('alice', real).toString('utf-8'), 'first');

    alice.destroy();
    bob.destroy();
  });

  it('a member distributed without a signing key can be heard by nobody', () => {
    // Fail closed: a distribution missing or carrying a malformed signPk leaves
    // the member registered but unverifiable, rather than silently unsigned.
    const alice = new GroupSession();
    const bob = new GroupSession();
    const { signPk: _dropped, ...noSignPk } = alice.distribution();
    bob.addMember('alice', noSignPk);

    assert.equal(bob.hasMember('alice'), true);
    assert.equal(bob.decrypt('alice', alice.encrypt('anyone there?')), null);

    bob.addMember('alice', { ...alice.distribution(), signPk: 'not-base64-of-32-bytes' });
    assert.equal(bob.decrypt('alice', alice.encrypt('still nothing')), null);

    alice.destroy();
    bob.destroy();
  });

  it('rotates the signing key with the chain', () => {
    const alice = new GroupSession();
    const before = alice.distribution();
    alice.rotate();
    const after = alice.distribution();

    assert.notEqual(after.signPk, before.signPk, 'the old key must not authenticate a new chain');
    assert.equal(Buffer.from(after.signPk, 'base64').length, 32);

    // A member still holding the pre-rotation distribution cannot be made to
    // accept post-rotation traffic by relabelling it.
    const bob = new GroupSession();
    bob.addMember('alice', before);
    assert.equal(bob.decrypt('alice', { ...alice.encrypt('after'), keyId: before.keyId }), null);

    alice.destroy();
    bob.destroy();
  });
});

// ── validateGroupMessage ────────────────────────────────────────────────────

describe('validateGroupMessage', () => {
  const good = () => ({
    room: 'General',
    keyId: 'AAAAAAAAAAAAAAAAAAAAAA==',
    counter: 0,
    ciphertext: Buffer.alloc(48, 1).toString('base64'),
    nonce: Buffer.alloc(24, 2).toString('base64'),
    signature: Buffer.alloc(64, 3).toString('base64'),
  });

  it('accepts a well-formed message and lowercases the room', () => {
    const r = validateGroupMessage(good());
    assert.equal(r.valid, true);
    assert.equal(r.room, 'general');
  });

  it('rejects what the relay cannot route on', () => {
    const bad = [
      [{ room: undefined }, /room/i],
      [{ room: '' }, /room/i],
      [{ room: 'has space' }, /room/i],
      [{ room: 'x'.repeat(31) }, /room/i],
      [{ keyId: undefined }, /key id/i],
      [{ keyId: '' }, /key id/i],
      [{ keyId: 'x'.repeat(65) }, /key id/i],
      [{ keyId: 42 }, /key id/i],
      [{ counter: -1 }, /counter/i],
      [{ counter: 1.5 }, /counter/i],
      [{ counter: '0' }, /counter/i],
      [{ counter: undefined }, /counter/i],
      [{ ciphertext: '' }, /ciphertext/i],
      [{ nonce: '' }, /ciphertext/i],
      // The relay cannot verify a signature — it holds no signing keys — but a
      // packet without a well-formed one can never be accepted by anybody, so
      // there is no reason to fan it out to a whole room first.
      [{ signature: undefined }, /signature/i],
      [{ signature: '' }, /signature/i],
      [{ signature: Buffer.alloc(63, 3).toString('base64') }, /signature/i],
      [{ signature: Buffer.alloc(65, 3).toString('base64') }, /signature/i],
      [{ signature: 42 }, /signature/i],
    ];
    for (const [patch, pattern] of bad) {
      const r = validateGroupMessage({ ...good(), ...patch });
      assert.equal(r.valid, false, `should reject ${JSON.stringify(patch)}`);
      assert.match(r.error, pattern);
    }
  });
});

// ── The relay's room fan-out ────────────────────────────────────────────────

describe('relay group fan-out', () => {
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
    ws.send(JSON.stringify(createJoin(nick, keys.publicKeyB64, null, [CAP.SENDER_KEYS])));
    const ack = await ackP;
    return { ws, keys, ack };
  };

  it('advertises its own capabilities in join_ack', async () => {
    const a = await join('CapCheck');
    assert.deepEqual(
      a.ack.serverCaps,
      [CAP.SENDER_KEYS],
      'a client cannot advertise the fan-out on the relay’s behalf, so the relay says it itself',
    );
    a.ws.close();
  });

  it('delivers one ciphertext to every other member, verbatim and unstamped', async () => {
    const alice = await join('GroupAlice');
    const bob = await join('GroupBob');
    const carol = await join('GroupCarol');

    const group = new GroupSession();
    const packet = group.encrypt('one line, one ciphertext');
    const sent = createGroupMessage('general', packet);

    const bobP = waitForMessage(bob.ws, (m) => m.type === MSG.GROUP_MESSAGE);
    const carolP = waitForMessage(carol.ws, (m) => m.type === MSG.GROUP_MESSAGE);
    // The sender must not get its own line back.
    const aliceSilence = expectNothing(alice.ws, (m) => m.type === MSG.GROUP_MESSAGE);

    alice.ws.send(JSON.stringify(sent));
    const [gotBob, gotCarol] = await Promise.all([bobP, carolP, aliceSilence]);

    for (const got of [gotBob, gotCarol]) {
      assert.equal(got.keyId, packet.keyId);
      assert.equal(got.counter, packet.counter);
      assert.equal(got.ciphertext, packet.ciphertext, 'the relay forwarded the bytes it was given');
      assert.equal(got.nonce, packet.nonce);
      assert.equal(got.from, undefined, 'the relay did not name the sender');
      assert.equal(got.to, undefined, 'nor invented a recipient');
    }
    // Both members opened the same ciphertext — that is the whole point.
    assert.equal(gotBob.ciphertext, gotCarol.ciphertext);

    group.destroy();
    for (const c of [alice, bob, carol]) {
      c.ws.close();
    }
  });

  it('refuses a room the sender is not in', async () => {
    const mallory = await join('GroupMallory');
    const bystander = await join('GroupBystander');

    const group = new GroupSession();
    const errP = waitForMessage(mallory.ws, (m) => m.type === MSG.ERROR);
    const silence = expectNothing(bystander.ws, (m) => m.type === MSG.GROUP_MESSAGE);

    mallory.ws.send(JSON.stringify(createGroupMessage('somewhere-else', group.encrypt('inject'))));

    const [err] = await Promise.all([errP, silence]);
    assert.equal(err.code, ERR.INVALID_MESSAGE);
    assert.match(err.message, /not in that room/i);

    group.destroy();
    mallory.ws.close();
    bystander.ws.close();
  });

  it('refuses a malformed group message', async () => {
    const a = await join('GroupJunk');
    const errP = waitForMessage(a.ws, (m) => m.type === MSG.ERROR);
    a.ws.send(
      JSON.stringify({
        type: MSG.GROUP_MESSAGE,
        version: 2,
        timestamp: Date.now(),
        room: 'general',
        keyId: '',
        counter: -5,
        ciphertext: '',
        nonce: '',
      }),
    );
    const err = await errP;
    assert.equal(err.code, ERR.INVALID_MESSAGE);
    a.ws.close();
  });

  it('does not queue a room message for an absent member', async () => {
    // The decision the design doc left open, made deliberately: a member who was
    // away could not read it anyway. A sender key handed over on their return
    // serialises the chain at its current counter, so the backlog stays shut —
    // queueing would store ciphertext on the relay that provably nobody can
    // open. The unicast queue survives because an envelope addressed to a peer
    // *is* still openable when they come back with the same key.
    const alice = await join('QueueAlice');
    const keys = new KeyManager();

    const bobWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(bobWs);
    const bobAckP = waitForMessage(bobWs, (m) => m.type === MSG.JOIN_ACK);
    bobWs.send(JSON.stringify(createJoin('QueueBob', keys.publicKeyB64, null, [CAP.SENDER_KEYS])));
    await bobAckP;

    // Bob drops, and the relay remembers him well enough to queue unicast.
    const gone = waitForMessage(alice.ws, (m) => m.type === MSG.PEER_LEFT);
    bobWs.close();
    await gone;

    const group = new GroupSession();
    alice.ws.send(JSON.stringify(createGroupMessage('general', group.encrypt('said while away'))));
    await new Promise((r) => setTimeout(r, 150));

    // Same nickname, same key — the conditions under which a unicast queue would
    // be handed over.
    const rejoinWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(rejoinWs);
    const rejoinAckP = waitForMessage(rejoinWs, (m) => m.type === MSG.JOIN_ACK);
    const noBacklog = expectNothing(rejoinWs, (m) => m.type === MSG.GROUP_MESSAGE, 300);
    rejoinWs.send(
      JSON.stringify(createJoin('QueueBob', keys.publicKeyB64, null, [CAP.SENDER_KEYS])),
    );
    const [rejoinAck] = await Promise.all([rejoinAckP, noBacklog]);

    assert.ok(!rejoinAck.queuedCount, 'nothing was held for him');

    group.destroy();
    keys.destroy();
    alice.ws.close();
    rejoinWs.close();
  });

  it('refuses a group message before JOIN', async () => {
    const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws);
    const group = new GroupSession();
    const errP = waitForMessage(ws, (m) => m.type === MSG.ERROR);
    ws.send(JSON.stringify(createGroupMessage('general', group.encrypt('before join'))));
    const err = await errP;
    assert.match(err.message, /join first/i);
    group.destroy();
    ws.close();
  });
});
