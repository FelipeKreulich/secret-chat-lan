/**
 * Live E2E test — connects 2 clients to the running server,
 * exchanges encrypted messages, and verifies decryption.
 *
 * Usage: start the server first (npm run server), then run this.
 */
import WebSocket from 'ws';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { NonceManager } from '../src/crypto/NonceManager.js';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { createJoin, createEncryptedMessage } from '../src/protocol/messages.js';

const aliceKeys = new KeyManager();
const bobKeys = new KeyManager();
const aliceNonces = new NonceManager();

console.log('Alice fingerprint:', aliceKeys.fingerprint);
console.log('Bob fingerprint:', bobKeys.fingerprint);
console.log();

let aliceSessionId, bobSessionId;

// ── Connect Alice ────────────────────────────────────────
const aliceWs = new WebSocket('ws://localhost:3600');

aliceWs.on('open', () => {
  console.log('[Alice] Connected to server');
  aliceWs.send(JSON.stringify(createJoin('Alice', aliceKeys.publicKeyB64)));
});

aliceWs.on('message', (data) => {
  const msg = JSON.parse(data.toString());

  if (msg.type === 'join_ack') {
    aliceSessionId = msg.sessionId;
    console.log('[Alice] JOIN_ACK - session:', aliceSessionId.slice(0, 8));
    connectBob();
  }

  if (msg.type === 'peer_joined') {
    console.log(`[Alice] ${msg.peer.nickname} joined the chat`);
  }
});

// ── Connect Bob ──────────────────────────────────────────
function connectBob() {
  const bobWs = new WebSocket('ws://localhost:3600');

  bobWs.on('open', () => {
    console.log('[Bob] Connected to server');
    bobWs.send(JSON.stringify(createJoin('Bob', bobKeys.publicKeyB64)));
  });

  bobWs.on('message', (data) => {
    const msg = JSON.parse(data.toString());

    if (msg.type === 'join_ack') {
      bobSessionId = msg.sessionId;
      console.log('[Bob] JOIN_ACK - peers:', msg.peers.map((p) => p.nickname));
      console.log();

      // Alice sends encrypted message to Bob
      setTimeout(() => sendEncrypted(bobWs), 300);
    }

    if (msg.type === 'encrypted_message') {
      console.log('[Bob] Encrypted message received!');
      const ct = Buffer.from(msg.payload.ciphertext, 'base64');
      const n = Buffer.from(msg.payload.nonce, 'base64');

      // Bob decrypts using Alice's public key + his secret key
      const plain = MessageCrypto.decrypt(ct, n, aliceKeys.publicKey, bobKeys.secretKey);
      if (plain) {
        const decoded = JSON.parse(plain.toString());
        console.log('[Bob] DECRYPTED:', decoded.text);
        console.log();
        console.log('========================================');
        console.log('  E2EE WORKING PERFECTLY!');
        console.log('  The server could NOT read the message');
        console.log('========================================');
      } else {
        console.log('[Bob] ERROR: Decryption failed!');
      }

      setTimeout(() => {
        aliceWs.close();
        bobWs.close();
        aliceKeys.destroy();
        bobKeys.destroy();
        process.exit(0);
      }, 300);
    }
  });
}

function sendEncrypted(bobWs) {
  const nonce = aliceNonces.generate();
  const payload = JSON.stringify({
    text: 'Hi Bob! This message is end-to-end encrypted!',
    sentAt: Date.now(),
    messageId: 'live01',
  });

  // Alice encrypts with Bob's public key + her secret key
  const ciphertext = MessageCrypto.encrypt(payload, nonce, bobKeys.publicKey, aliceKeys.secretKey);

  console.log('[Alice] Sending encrypted message...');
  console.log('[Alice] Ciphertext:', ciphertext.toString('base64').slice(0, 40) + '...');
  console.log('[Alice] Nonce:', nonce.toString('base64'));
  console.log();

  aliceWs.send(
    JSON.stringify(
      createEncryptedMessage(
        aliceSessionId,
        bobSessionId,
        ciphertext.toString('base64'),
        nonce.toString('base64'),
      ),
    ),
  );
}
