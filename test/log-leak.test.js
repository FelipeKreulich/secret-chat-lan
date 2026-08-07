/**
 * The relay must never write message content to a log.
 *
 * This is the project's central claim — the operator cannot read anything —
 * and until now it was held up entirely by people remembering. One `log.debug`
 * added on a tired evening, printing a payload while chasing a bug, undoes it
 * silently: the tests stay green, the crypto is still correct, and the promise
 * is gone.
 *
 * So it is tested the only way it can be. Run a real relay with real clients at
 * the loudest log level, push distinctive markers through every path including
 * the failing ones, and capture everything the process writes. If a marker
 * comes out the other end, the promise is broken.
 *
 * Markers are checked in both plaintext and base64: a payload logged verbatim
 * and a payload logged as the blob it arrived in are the same leak, and the
 * second is the one somebody actually writes by accident.
 */
import { strict as assert } from 'node:assert';
import { after, before, describe, it } from 'node:test';

// The logger reads LOG_LEVEL once, at import. Set it before anything pulls the
// module in, so this runs against the most talkative configuration there is —
// testing at the default level would prove nothing about `log.debug`.
process.env.LOG_LEVEL = 'debug';

const WebSocket = (await import('ws')).default;
const { SessionManager } = await import('../src/server/SessionManager.js');
const { MessageRouter } = await import('../src/server/MessageRouter.js');
const { OfflineQueue } = await import('../src/server/OfflineQueue.js');
const { SecureWSServer } = await import('../src/server/WebSocketServer.js');
const { KeyManager } = await import('../src/crypto/KeyManager.js');
const { NonceManager } = await import('../src/crypto/NonceManager.js');
const MessageCrypto = await import('../src/crypto/MessageCrypto.js');
const { createJoin, createSealedMessage, MSG } = await import('../src/protocol/messages.js');
const { sealEnvelope } = await import('../src/crypto/SealedSender.js');

const TEST_PORT = 3702;

/**
 * Long, unmistakable, and impossible to produce by accident.
 *
 * Named canary rather than secret: a constant called SECRET trips every
 * credential scanner that reads this repository, and an alert that is always
 * there and always wrong teaches people to close alerts without reading them.
 */
const CANARY = 'canary-plaintext-8f21c9e4-must-never-be-logged';
const ROOM_CANARY = 'canary-room-51d0a7b2';

function waitForMessage(ws, predicate, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), timeoutMs);
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

const waitForOpen = (ws) =>
  new Promise((resolve) => (ws.readyState === WebSocket.OPEN ? resolve() : ws.on('open', resolve)));

describe('the relay never logs message content', () => {
  let server;
  let captured;
  let restore;

  before(() => {
    const sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    const messageRouter = new MessageRouter(sessionManager, offlineQueue);
    server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, TEST_PORT);

    captured = [];
    const original = { log: console.log, warn: console.warn, error: console.error };
    const capture =
      (stream) =>
      (...args) => {
        captured.push(args.map(String).join(' '));
        // Deliberately not forwarding to `original[stream]`: a passing run
        // should be quiet, and a failing one reports the offending line itself.
        void stream;
      };
    console.log = capture('log');
    console.warn = capture('warn');
    console.error = capture('error');
    restore = () => Object.assign(console, original);
  });

  after(async () => {
    restore();
    await server.close();
  });

  it('nothing it writes contains a payload, in any encoding', async () => {
    const alice = new KeyManager();
    const bob = new KeyManager();
    const nonces = new NonceManager();

    const aliceWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(aliceWs);
    const aliceAckPromise = waitForMessage(aliceWs, (m) => m.type === MSG.JOIN_ACK);
    aliceWs.send(JSON.stringify(createJoin('Alice', alice.publicKeyB64)));
    const aliceAck = await aliceAckPromise;

    const bobWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(bobWs);
    const alicePeerJoined = waitForMessage(aliceWs, (m) => m.type === MSG.PEER_JOINED);
    const bobAckPromise = waitForMessage(bobWs, (m) => m.type === MSG.JOIN_ACK);
    bobWs.send(JSON.stringify(createJoin('Bob', bob.publicKeyB64)));
    const [bobAck] = await Promise.all([bobAckPromise, alicePeerJoined]);

    // ── the happy path ────────────────────────────────────────────
    const payload = JSON.stringify({ text: CANARY, room: ROOM_CANARY, messageId: 'leak-1' });
    const nonce = nonces.generate();
    const ciphertext = MessageCrypto.encrypt(payload, nonce, bob.publicKey, alice.secretKey);
    const sealed = sealEnvelope(
      aliceAck.sessionId,
      { ciphertext: ciphertext.toString('base64'), nonce: nonce.toString('base64') },
      bob.publicKey,
    );

    const delivered = waitForMessage(bobWs, (m) => m.type === MSG.ENCRYPTED_MESSAGE);
    aliceWs.send(JSON.stringify(createSealedMessage(bobAck.sessionId, sealed)));
    await delivered;

    // ── and the paths that are far likelier to log ────────────────
    // Errors are where content ends up in a log: someone prints the message
    // they could not handle. Each of these should produce a complaint, and
    // none of them should quote what it was complaining about.
    aliceWs.send(`{"type":"encrypted_message","to":"nobody","sealed":"${CANARY}"}`);
    aliceWs.send(`not json at all ${CANARY}`);
    aliceWs.send(JSON.stringify({ type: 'unknown_type', text: CANARY }));
    aliceWs.send(JSON.stringify(createSealedMessage('no-such-session', sealed)));

    // Let the server finish reacting to all of that.
    await new Promise((resolve) => setTimeout(resolve, 300));

    aliceWs.close();
    bobWs.close();
    await new Promise((resolve) => setTimeout(resolve, 100));

    const output = captured.join('\n');
    const forbidden = [
      ['the message text', CANARY],
      ['the room name inside the payload', ROOM_CANARY],
      // The payload as it actually travels. Logging "the blob I could not
      // route" is the most natural debugging line in the world, and it is a
      // leak the moment the recipient's key is ever compromised.
      ['the sealed envelope', sealed],
      ['the ciphertext', ciphertext.toString('base64')],
      ['the marker, base64-encoded', Buffer.from(CANARY).toString('base64')],
    ];

    for (const [what, needle] of forbidden) {
      const offending = captured.filter((line) => line.includes(needle));
      assert.deepEqual(
        offending,
        [],
        `${what} reached a log line. The relay's whole promise is that this cannot happen.`,
      );
    }

    // A guard on the guard: if the capture broke, every assertion above passes
    // for the wrong reason and this test becomes decoration.
    assert.ok(output.length > 0, 'captured no log output at all — is LOG_LEVEL still debug?');
  });
});
