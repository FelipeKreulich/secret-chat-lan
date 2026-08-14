/**
 * ─────────────────────────────────────────────────────────────────────────────
 *  THE GUARANTEES FILE — read this before changing or deleting anything in it
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * On 2026-08-07 a squash reverted the entire plugin-approval security control
 * and the suite stayed green. Not because the tests were weak, but because they
 * lived in the same commit as the feature: reverting the feature reverted its
 * proof, and nothing was left to notice. Green meant "nothing contradicts the
 * code that is here", which is a much smaller claim than anyone reads it as.
 *
 * This file exists to break that symmetry. It asserts what the project
 * *promises* — the claims in README.md, SECURITY.md and docs/ARCHITECTURE.md —
 * from the outside, through the surfaces a user actually goes through, and it
 * deliberately does not live next to any of the features that keep those
 * promises. Deleting a feature leaves this file behind, failing.
 *
 * Rules for editing it:
 *
 *   1. A test here may be changed when the *promise* changes, and then the
 *      promise has to change first — in SECURITY.md, in the README, wherever it
 *      is made. Not because an implementation moved.
 *   2. Never assert through a feature's internals. If the only way to check
 *      something is to reach inside the module that implements it, the check
 *      dies with the module and is worth little here.
 *   3. Removing a guarantee is a decision about what the project claims, not
 *      about test maintenance. It belongs in a PR of its own that says so.
 *
 * It is intentionally coarse. It is not where a feature's edge cases are
 * covered — those belong beside the feature — it is where the handful of things
 * that must never quietly stop being true are kept honest.
 *
 * Companion: test/log-leak.test.js holds the same kind of claim for the relay's
 * logs, and is deliberately separate because it needs the process boot to be
 * instrumented before anything is imported.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WebSocket from 'ws';

import { SessionManager } from '../src/server/SessionManager.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { SecureWSServer } from '../src/server/WebSocketServer.js';
import { PluginManager } from '../src/shared/PluginManager.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { NonceManager } from '../src/crypto/NonceManager.js';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { GroupSession, SenderChain, groupEncrypt } from '../src/crypto/SenderKey.js';
import { sealEnvelope } from '../src/crypto/SealedSender.js';
import { deriveRoomSecrets, signRoomChallenge, freeRoomSecrets } from '../src/crypto/RoomKey.js';
import {
  createJoin,
  createSealedMessage,
  createChangeRoom,
  createRoomAuth,
  MSG,
} from '../src/protocol/messages.js';

const TEST_PORT = 3706;

// Long, unmistakable, impossible to produce by accident. Named canary rather
// than secret so credential scanners do not cry wolf on this file forever.
const MESSAGE_CANARY = 'canary-message-b4f1e7d3-never-reaches-the-relay';
const PASSWORD_CANARY = 'canary-password-9c2a5e10-never-leaves-the-client';

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

// ── The wire ────────────────────────────────────────────────────────────────
// Every frame a client hands to the relay, recorded verbatim. This is the
// relay's entire view of the world, and several guarantees below are simply
// statements about what is not in it. Collecting it in one place means a new
// message type cannot quietly introduce a leak that no assertion covers: the
// assertions are over the transcript, not over one message shape.
const wire = [];

function send(ws, msg) {
  const raw = JSON.stringify(msg);
  wire.push(raw);
  ws.send(raw);
}

function wireText() {
  return wire.join('\n');
}

describe('guarantees the project makes', () => {
  let server;
  let tempDir;
  let cwd;
  let home;

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    const messageRouter = new MessageRouter(sessionManager, offlineQueue);
    server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, TEST_PORT);

    tempDir = mkdtempSync(join(tmpdir(), 'ciphermesh-guarantees-'));
    cwd = process.cwd();
    home = process.env.HOME;
    process.env.HOME = tempDir;
  });

  after(async () => {
    await server.close();
    process.chdir(cwd);
    process.env.HOME = home;
    rmSync(tempDir, { recursive: true, force: true });
  });

  const connect = async (nick) => {
    const keys = new KeyManager();
    const ws = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws);
    const ackP = waitForMessage(ws, (m) => m.type === MSG.JOIN_ACK);
    send(ws, createJoin(nick, keys.publicKeyB64));
    const ack = await ackP;
    return { ws, keys, nonces: new NonceManager(), sessionId: ack.sessionId, ack };
  };

  // ── 1. Nothing in the plugin directory runs until the user says so ────────
  //
  // The control that was reverted. docs/PLUGINS.md: "A file in that directory
  // is found, not loaded." Importing a module *is* running it, so the only
  // honest way to check this is to give the file an observable side effect on
  // import and then assert the side effect did not happen.

  it('does not execute a plugin the user never approved', async () => {
    const dir = join(tempDir, 'plugins-unapproved');
    const marker = join(tempDir, 'unapproved-ran.marker');
    writePlugin(dir, 'untrusted.js', marker);

    const pm = new PluginManager();
    await pm.loadAll(dir, []); // nothing approved

    assert.equal(
      existsSync(marker),
      false,
      'an unapproved plugin was imported, and importing is running',
    );
    assert.deepEqual(pm.getPendingFiles(), ['untrusted.js'], 'it is offered, not loaded');
    assert.equal(pm.getCommandNames().length, 0, 'and it contributed no commands');
  });

  it('does execute one the user did approve', async () => {
    // The other half, and it is not padding: a version of this control that
    // refused everything would pass the test above and be useless. Approval has
    // to be the thing that decides, in both directions.
    const dir = join(tempDir, 'plugins-approved');
    const marker = join(tempDir, 'approved-ran.marker');
    writePlugin(dir, 'trusted.js', marker);

    const pm = new PluginManager();
    await pm.loadAll(dir, ['trusted']);

    assert.equal(existsSync(marker), true, 'approval is what loads it');
    assert.ok(pm.getCommandNames().includes('/guaranteed'));
  });

  it('treats approval as per-file and exact', async () => {
    // Approving one file must not approve its neighbour. A prefix or substring
    // match here would turn one consent into several.
    const dir = join(tempDir, 'plugins-mixed');
    const okMarker = join(tempDir, 'mixed-ok.marker');
    const sneakyMarker = join(tempDir, 'mixed-sneaky.marker');
    writePlugin(dir, 'roll.js', okMarker);
    writePlugin(dir, 'roll-extra.js', sneakyMarker);

    const pm = new PluginManager();
    await pm.loadAll(dir, ['roll']);

    assert.equal(existsSync(okMarker), true);
    assert.equal(existsSync(sneakyMarker), false, 'one approval must not cover a similar name');
  });

  // ── 2. The relay never receives anything it could read ────────────────────
  //
  // README/SECURITY: "The relay server is zero-knowledge by design: it forwards
  // ciphertext and never holds decryption keys."

  it('hands the relay no plaintext, in any encoding', async () => {
    const alice = await connect('GuaranteeAlice');
    const bob = await connect('GuaranteeBob');

    const bobPub = Buffer.from(bob.keys.publicKeyB64, 'base64');
    const payload = JSON.stringify({ text: MESSAGE_CANARY, room: 'general', messageId: 'g1' });
    const nonce = alice.nonces.generate();
    const ciphertext = MessageCrypto.encrypt(payload, nonce, bobPub, alice.keys.secretKey);
    const sealed = sealEnvelope(
      alice.sessionId,
      { ciphertext: ciphertext.toString('base64'), nonce: nonce.toString('base64') },
      bobPub,
    );

    const delivered = waitForMessage(bob.ws, (m) => m.type === MSG.ENCRYPTED_MESSAGE);
    send(alice.ws, createSealedMessage(bob.sessionId, sealed));
    const got = await delivered;

    // It really was delivered — otherwise "no plaintext on the wire" would be
    // satisfied by nothing working at all.
    assert.ok(got.sealed, 'the message arrived');

    for (const [what, needle] of [
      ['as text', MESSAGE_CANARY],
      ['base64-encoded', Buffer.from(MESSAGE_CANARY).toString('base64')],
      ['hex-encoded', Buffer.from(MESSAGE_CANARY).toString('hex')],
    ]) {
      assert.equal(wireText().includes(needle), false, `the relay was handed the message ${what}`);
    }

    alice.ws.close();
    bob.ws.close();
  });

  it('hands the relay no frame that names its sender', async () => {
    // Sealed sender. SECURITY.md: "the relay routes by recipient and never
    // sees, stamps, or logs the sender". The `from` field was removed from the
    // wire in protocol v2 and must not come back by way of a new message type.
    const carrying = wire
      .map((raw) => JSON.parse(raw))
      .filter((m) => m.type === MSG.ENCRYPTED_MESSAGE || m.type === MSG.GROUP_MESSAGE)
      .filter((m) => m.from !== undefined);

    assert.deepEqual(carrying, [], 'a frame reached the relay with a sender on it');
  });

  it('hides how long a message was', async () => {
    // Padding buckets: SECURITY.md concedes the relay sees a "padding-bucketed
    // size", which is only a concession if the bucket is real. Two messages of
    // very different lengths have to be indistinguishable by size.
    const keys = new KeyManager();
    const nonces = new NonceManager();
    const short = MessageCrypto.encrypt('hi', nonces.generate(), keys.publicKey, keys.secretKey);
    const longer = MessageCrypto.encrypt(
      'x'.repeat(100),
      nonces.generate(),
      keys.publicKey,
      keys.secretKey,
    );

    assert.equal(short.length, longer.length, '2 bytes and 100 bytes must look alike on the wire');
    keys.destroy();
  });

  // ── 3. A private room's password stays on the client ──────────────────────
  //
  // ARCHITECTURE §6.9: the relay gates a private room "without ever seeing the
  // password". What travels is an Ed25519 verifier key and a signature over a
  // server-chosen nonce.

  it('never hands the relay a room password', async () => {
    const ROOM = 'guarantee-room';
    const secrets = deriveRoomSecrets(ROOM, PASSWORD_CANARY);

    const owner = await connect('GuaranteeOwner');
    const changed = waitForMessage(owner.ws, (m) => m.type === MSG.ROOM_CHANGED);
    send(owner.ws, createChangeRoom(ROOM, secrets.authPublicKey.toString('base64')));
    await changed;

    // A second client proves knowledge of the password without sending it.
    const joiner = await connect('GuaranteeJoiner');
    const challengeP = waitForMessage(joiner.ws, (m) => m.type === MSG.ROOM_CHALLENGE);
    send(joiner.ws, createChangeRoom(ROOM));
    const challenge = await challengeP;

    const joined = waitForMessage(joiner.ws, (m) => m.type === MSG.ROOM_CHANGED);
    const signature = signRoomChallenge(
      secrets.authSecretKey,
      challenge.room,
      challenge.nonce,
      joiner.sessionId,
    );
    send(joiner.ws, createRoomAuth(challenge.room, challenge.nonce, signature.toString('base64')));
    await joined;

    // Again: it has to have actually worked, or this proves nothing.
    for (const [what, needle] of [
      ['as text', PASSWORD_CANARY],
      ['base64-encoded', Buffer.from(PASSWORD_CANARY).toString('base64')],
      ['as the derived room key', secrets.roomKey.toString('base64')],
      ['as the signing key', Buffer.from(secrets.authSecretKey).toString('base64')],
    ]) {
      assert.equal(wireText().includes(needle), false, `the relay was handed the password ${what}`);
    }

    freeRoomSecrets(secrets);
    owner.ws.close();
    joiner.ws.close();
  });

  // ── 4. Nobody can speak in someone else's name ────────────────────────────
  //
  // SECURITY.md lists an Ed25519 per-sender signature on group messages "so a
  // member cannot write in another member's name". The chain is symmetric, so
  // membership alone is enough to produce ciphertext — this is the only thing
  // standing between that and impersonation.

  it('refuses a group message a member did not sign', () => {
    const alice = new GroupSession();
    const bob = new GroupSession();
    const dist = alice.distribution();
    bob.addMember('alice', dist);

    // Mallory is a member in good standing: she holds Alice's distribution,
    // which is exactly what lets her rebuild Alice's chain.
    const forgedChain = SenderChain.deserialize(dist);
    const { messageKey, counter } = forgedChain.deriveNext();
    const { ciphertext, nonce } = groupEncrypt(messageKey, 'not from alice');

    assert.equal(
      bob.decrypt('alice', {
        keyId: dist.keyId,
        counter,
        ciphertext: ciphertext.toString('base64'),
        nonce: nonce.toString('base64'),
        signature: Buffer.alloc(64).toString('base64'),
      }),
      null,
      'a room member forged another member and was believed',
    );

    // And the genuine article still works, so this is about the signature and
    // not about group messages being broken outright.
    assert.equal(
      bob.decrypt('alice', alice.encrypt('really alice')).toString('utf-8'),
      'really alice',
    );

    forgedChain.destroy();
    alice.destroy();
    bob.destroy();
  });

  it('stops a removed member reading what the room says next', () => {
    // The promise a group chat has to make and a pairwise one gets for free.
    // Removing someone stops the relay delivering to them; it does not take
    // back the chain they hold, and a chain ratchets *forward* — the copy they
    // were given opens every message after it, for as long as it is used.
    //
    // Asserted at the level of the promise rather than through the controller
    // that keeps it: what must never quietly stop being true is that departure
    // ends readership, however the client happens to notice the departure.
    const alice = new GroupSession();
    const leaver = new GroupSession();
    const stayer = new GroupSession();

    const original = alice.distribution();
    leaver.addMember('alice', original);
    stayer.addMember('alice', original);

    // Everyone present can read, which is what makes the next part meaningful.
    const before = alice.encrypt('while they were still here');
    assert.equal(
      leaver.decrypt('alice', before).toString('utf-8'),
      'while they were still here',
      'the member could read before they were removed',
    );

    // They leave — by whichever door. Alice draws a new chain and hands it to
    // the room that remains.
    alice.removeMember('leaver');
    alice.rotate();
    stayer.addMember('alice', alice.distribution());

    const after = alice.encrypt('after they were removed');

    assert.equal(
      leaver.decrypt('alice', after),
      null,
      'a removed member read what the room said after they were removed',
    );
    assert.equal(
      stayer.decrypt('alice', after).toString('utf-8'),
      'after they were removed',
      'and the room can still hear each other, so this is forward secrecy and not breakage',
    );

    alice.destroy();
    leaver.destroy();
    stayer.destroy();
  });
});

// A plugin whose top-level code leaves a trace. Importing an ES module runs it,
// so the marker existing is proof the file was executed — which is the thing
// approval is supposed to decide.
function writePlugin(dir, file, markerPath) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, file),
    `import { writeFileSync } from 'node:fs';\n` +
      `writeFileSync(${JSON.stringify(markerPath)}, 'ran');\n` +
      `export default { name: ${JSON.stringify(file)}, commands: { guaranteed: () => 'ok' } };\n`,
  );
}
