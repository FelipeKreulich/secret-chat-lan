/**
 * Integration test: starts server + 2 simulated clients,
 * exchanges encrypted messages, verifies E2EE works.
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { SessionManager } from '../src/server/SessionManager.js';
import { MessageRouter } from '../src/server/MessageRouter.js';
import { OfflineQueue } from '../src/server/OfflineQueue.js';
import { SecureWSServer } from '../src/server/WebSocketServer.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { NonceManager } from '../src/crypto/NonceManager.js';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { createJoin, createEncryptedMessage, MSG } from '../src/protocol/messages.js';

const TEST_PORT = 3699;

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

describe('SecureLAN Chat E2EE Integration', () => {
  let server;
  let sessionManager;
  let messageRouter;

  before(() => {
    sessionManager = new SessionManager();
    const offlineQueue = new OfflineQueue();
    messageRouter = new MessageRouter(sessionManager, offlineQueue);
    server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, TEST_PORT);
  });

  after(async () => {
    await server.close();
  });

  it('two clients exchange E2EE messages through the relay server', async () => {
    // ── Setup Alice ──────────────────────────────────────
    const aliceKeys = new KeyManager();
    const aliceNonces = new NonceManager();

    // ── Setup Bob ────────────────────────────────────────
    const bobKeys = new KeyManager();
    const bobNonces = new NonceManager();

    // ── Connect Alice ────────────────────────────────────
    const aliceWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(aliceWs);

    const aliceJoinAckPromise = waitForMessage(aliceWs, (m) => m.type === MSG.JOIN_ACK);
    aliceWs.send(JSON.stringify(createJoin('Alice', aliceKeys.publicKeyB64)));
    const aliceAck = await aliceJoinAckPromise;

    assert.ok(aliceAck.sessionId, 'Alice got a session ID');
    assert.equal(aliceAck.peers.length, 0, 'No peers yet');
    const aliceSessionId = aliceAck.sessionId;

    // ── Connect Bob ──────────────────────────────────────
    const bobWs = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(bobWs);

    const alicePeerJoinedPromise = waitForMessage(aliceWs, (m) => m.type === MSG.PEER_JOINED);
    const bobJoinAckPromise = waitForMessage(bobWs, (m) => m.type === MSG.JOIN_ACK);

    bobWs.send(JSON.stringify(createJoin('Bob', bobKeys.publicKeyB64)));

    const [bobAck, alicePeerJoined] = await Promise.all([
      bobJoinAckPromise,
      alicePeerJoinedPromise,
    ]);

    const bobSessionId = bobAck.sessionId;
    assert.ok(bobSessionId, 'Bob got a session ID');
    assert.equal(bobAck.peers.length, 1, 'Bob sees Alice');
    assert.equal(bobAck.peers[0].nickname, 'Alice');
    assert.equal(alicePeerJoined.peer.nickname, 'Bob');

    // ── Alice sends encrypted message to Bob ─────────────
    // Alice uses Bob's public key (from PEER_JOINED) and her own secret key
    const bobPublicKey = Buffer.from(alicePeerJoined.peer.publicKey, 'base64');
    const alicePublicKey = Buffer.from(bobAck.peers[0].publicKey, 'base64');

    const originalMessage = 'Ola Bob! Esta mensagem e criptografada E2E.';
    const payload = JSON.stringify({
      text: originalMessage,
      sentAt: Date.now(),
      messageId: 'test001',
    });

    const nonce = aliceNonces.generate();
    const ciphertext = MessageCrypto.encrypt(payload, nonce, bobPublicKey, aliceKeys.secretKey);

    // Bob waits for the message
    const bobMessagePromise = waitForMessage(bobWs, (m) => m.type === MSG.ENCRYPTED_MESSAGE);

    aliceWs.send(JSON.stringify(createEncryptedMessage(
      aliceSessionId,
      bobSessionId,
      ciphertext.toString('base64'),
      nonce.toString('base64'),
    )));

    const encMsg = await bobMessagePromise;

    // ── Bob decrypts ─────────────────────────────────────
    // Bob uses Alice's public key (from JOIN_ACK peers) and his own secret key
    const receivedCiphertext = Buffer.from(encMsg.payload.ciphertext, 'base64');
    const receivedNonce = Buffer.from(encMsg.payload.nonce, 'base64');

    assert.ok(bobNonces.validate(aliceSessionId, receivedNonce), 'Nonce is valid');

    const decrypted = MessageCrypto.decrypt(
      receivedCiphertext,
      receivedNonce,
      alicePublicKey,
      bobKeys.secretKey,
    );
    assert.ok(decrypted, 'Decryption succeeded (MAC valid)');

    const decryptedData = JSON.parse(decrypted.toString('utf-8'));
    assert.equal(decryptedData.text, originalMessage, 'Message decrypted correctly');

    console.log('  Mensagem enviada:     ', originalMessage);
    console.log('  Ciphertext (b64):     ', ciphertext.toString('base64').slice(0, 40) + '...');
    console.log('  Mensagem recebida:    ', decryptedData.text);
    console.log('  E2EE verificado!');

    // ── Verify tampered message fails MAC ────────────────
    const tampered = Buffer.from(receivedCiphertext);
    tampered[0] ^= 0xff;
    const tamperedResult = MessageCrypto.decrypt(tampered, receivedNonce, alicePublicKey, bobKeys.secretKey);
    assert.equal(tamperedResult, null, 'Tampered message correctly rejected (MAC failed)');

    // ── Verify server can't decrypt (no secret key) ──────
    // A third party with random keys can't decrypt
    const eveKeys = new KeyManager();
    const eveResult = MessageCrypto.decrypt(receivedCiphertext, receivedNonce, alicePublicKey, eveKeys.secretKey);
    assert.equal(eveResult, null, 'Third party cannot decrypt (wrong secret key)');
    eveKeys.destroy();

    // ── Cleanup ──────────────────────────────────────────
    aliceKeys.destroy();
    bobKeys.destroy();
    aliceWs.close();
    bobWs.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
  });

  it('rejects duplicate nicknames', async () => {
    const keys1 = new KeyManager();
    const keys2 = new KeyManager();

    const ws1 = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws1);

    const ackPromise = waitForMessage(ws1, (m) => m.type === MSG.JOIN_ACK);
    ws1.send(JSON.stringify(createJoin('DupeTest', keys1.publicKeyB64)));
    await ackPromise;

    const ws2 = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws2);

    const errorPromise = waitForMessage(ws2, (m) => m.type === MSG.ERROR);
    ws2.send(JSON.stringify(createJoin('DupeTest', keys2.publicKeyB64)));
    const err = await errorPromise;

    assert.equal(err.code, 'NICKNAME_TAKEN');

    keys1.destroy();
    keys2.destroy();
    ws1.close();
    ws2.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
  });

  it('notifies when peer leaves', async () => {
    const keys1 = new KeyManager();
    const keys2 = new KeyManager();

    const ws1 = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws1);
    const ack1 = waitForMessage(ws1, (m) => m.type === MSG.JOIN_ACK);
    ws1.send(JSON.stringify(createJoin('Stayer', keys1.publicKeyB64)));
    await ack1;

    const ws2 = new WebSocket(`ws://localhost:${TEST_PORT}`);
    await waitForOpen(ws2);
    const ack2 = waitForMessage(ws2, (m) => m.type === MSG.JOIN_ACK);
    const peerJoined = waitForMessage(ws1, (m) => m.type === MSG.PEER_JOINED);
    ws2.send(JSON.stringify(createJoin('Leaver', keys2.publicKeyB64)));
    await ack2;
    await peerJoined;

    const peerLeftPromise = waitForMessage(ws1, (m) => m.type === MSG.PEER_LEFT);
    ws2.close();
    const peerLeft = await peerLeftPromise;

    assert.equal(peerLeft.nickname, 'Leaver');

    keys1.destroy();
    keys2.destroy();
    ws1.close();
    await new Promise((resolve) => setTimeout(resolve, 200));
  });

  it('anti-replay: rejects duplicate nonce', async () => {
    const nonces = new NonceManager();
    const nonce = nonces.generate();

    assert.ok(nonces.validate('peer1', nonce), 'First use accepted');
    assert.equal(nonces.validate('peer1', nonce), false, 'Replay rejected');
  });

  it('fingerprint generation is deterministic', () => {
    const keys = new KeyManager();
    const fp1 = KeyManager.computeFingerprint(keys.publicKey);
    const fp2 = KeyManager.computeFingerprint(keys.publicKey);
    assert.equal(fp1, fp2, 'Same key produces same fingerprint');
    assert.match(fp1, /^[A-F0-9]{4}:[A-F0-9]{4}:[A-F0-9]{4}:[A-F0-9]{4}$/, 'Fingerprint format');
    keys.destroy();
  });
});
