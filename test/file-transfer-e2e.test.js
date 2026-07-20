import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileTransfer } from '../src/client/FileTransfer.js';
import { KeyManager } from '../src/crypto/KeyManager.js';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { createEncryptedMessage } from '../src/protocol/messages.js';
import { MAX_PAYLOAD_SIZE } from '../src/shared/constants.js';

describe('FileTransfer end-to-end', () => {
  let senderDir;
  let receiverDir;

  beforeEach(() => {
    senderDir = mkdtempSync(join(tmpdir(), 'ciphermesh-ft-snd-'));
    receiverDir = mkdtempSync(join(tmpdir(), 'ciphermesh-ft-rcv-'));
  });

  afterEach(() => {
    rmSync(senderDir, { recursive: true, force: true });
    rmSync(receiverDir, { recursive: true, force: true });
  });

  it('transfers a real multi-chunk file through encrypt/decrypt and reassembles it', async () => {
    // ~4 chunks of 16KB — exactly the path that used to overflow padMessage /
    // MAX_PAYLOAD_SIZE before FILE_CHUNK_SIZE was fixed.
    const original = randomBytes(50_000);
    const srcPath = join(senderDir, 'photo.bin');
    writeFileSync(srcPath, original);

    const senderFT = new FileTransfer({ downloadDir: senderDir });
    const receiverFT = new FileTransfer({ downloadDir: receiverDir });
    const sk = new KeyManager();
    const rk = new KeyManager();
    const SENDER = 'sess-sender';

    // Every message goes through the real encrypt→wire→decrypt path so the test
    // fails if a chunk ever exceeds the padding/payload limits again.
    const roundtrip = (payloadObj) => {
      const payload = JSON.stringify({ ...payloadObj, sentAt: Date.now() });
      const nonce = randomBytes(24);
      const ct = MessageCrypto.encrypt(payload, nonce, rk.publicKey, sk.secretKey);
      const wire = JSON.stringify(
        createEncryptedMessage(SENDER, 'sess-rcv', ct.toString('base64'), nonce.toString('base64')),
      );
      assert.ok(
        Buffer.byteLength(wire) <= MAX_PAYLOAD_SIZE,
        `wire frame ${Buffer.byteLength(wire)} must fit MAX_PAYLOAD_SIZE`,
      );
      const pt = MessageCrypto.decrypt(ct, nonce, sk.publicKey, rk.secretKey);
      return JSON.parse(pt.toString('utf-8'));
    };

    let savedPath = null;
    const pending = [];

    const senderBroadcast = (payloadObj) => {
      const data = roundtrip(payloadObj);
      if (data.action === 'file_offer') {
        receiverFT.handleFileOffer(SENDER, data, 'alice');
        // Receiver consents → tell the sender to start streaming. Deferred so it
        // arrives AFTER initSend has registered the outgoing transfer (as it
        // would over the real network).
        setTimeout(
          () => senderFT.handleFileAccept('sess-rcv', { transferId: data.transferId, have: [] }),
          30,
        );
      } else if (data.action === 'file_chunk') {
        receiverFT.handleFileChunk(SENDER, data);
      } else if (data.action === 'file_complete') {
        pending.push(
          receiverFT.handleFileComplete(SENDER, data).then((res) => {
            if (res.success) {
              savedPath = res.savePath;
            }
          }),
        );
      }
    };

    await senderFT.initSend(srcPath, senderBroadcast, {
      onProgress: () => {},
      onError: (e) => {
        throw new Error(e);
      },
      onComplete: () => {},
    });

    await Promise.all(pending);

    assert.ok(savedPath, 'receiver saved the reassembled file');
    assert.deepEqual(readFileSync(savedPath), original, 'reassembled bytes match the original');

    senderFT.destroy();
    receiverFT.destroy();
    sk.destroy();
    rk.destroy();
  });
});
