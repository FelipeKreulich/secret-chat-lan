import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash, randomFillSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileTransfer } from '../src/client/FileTransfer.js';

const SENDER = 'sess-sender';

function makeOffer(content, transferId = 'tr1') {
  const chunks = [];
  const CHUNK = 8;
  for (let i = 0; i < content.length; i += CHUNK) {
    chunks.push(Buffer.from(content.slice(i, i + CHUNK)));
  }
  return {
    offer: {
      transferId,
      fileName: 'data.txt',
      fileSize: content.length,
      totalChunks: chunks.length,
      sha256: createHash('sha256').update(Buffer.from(content)).digest('hex'),
    },
    chunks,
  };
}

describe('FileTransfer resume', () => {
  let dir;
  let ft;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ciphermesh-ft-'));
    ft = new FileTransfer({ downloadDir: dir, transferTimeoutMs: 120, resumeKeepMs: 5000 });
  });

  afterEach(() => {
    ft.destroy();
    rmSync(dir, { recursive: true, force: true });
  });

  test('a complete transfer saves the file', async () => {
    const { offer, chunks } = makeOffer('test content ok');
    const res = ft.handleFileOffer(SENDER, offer, 'davi');
    assert.match(res.message, /sending data\.txt/);
    assert.equal(res.have.length, 0);

    chunks.forEach((c, i) =>
      ft.handleFileChunk(SENDER, { transferId: 'tr1', chunkIndex: i, data: c.toString('base64') }),
    );
    const done = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    assert.equal(done.success, true);
    assert.equal(readFileSync(done.savePath, 'utf-8'), 'test content ok');
  });

  test('last-chunk padding is removed on reassembly (hides the size)', async () => {
    const content = 'a file whose size does not align to chunk boundaries!!!';
    const CHUNK = 16;
    const chunks = [];
    for (let i = 0; i < content.length; i += CHUNK) {
      chunks.push(Buffer.from(content.slice(i, i + CHUNK)));
    }
    // Simulate the wire: the last chunk arrives padded up to the full size.
    const last = chunks[chunks.length - 1];
    const padded = Buffer.alloc(CHUNK);
    last.copy(padded);
    randomFillSync(padded, last.length);
    chunks[chunks.length - 1] = padded;

    const offer = {
      transferId: 'trp',
      fileName: 'x.txt',
      fileSize: content.length, // real size, without the padding
      totalChunks: chunks.length,
      sha256: createHash('sha256').update(Buffer.from(content)).digest('hex'),
    };
    ft.handleFileOffer(SENDER, offer, 'davi');
    chunks.forEach((c, i) =>
      ft.handleFileChunk(SENDER, { transferId: 'trp', chunkIndex: i, data: c.toString('base64') }),
    );
    const done = await ft.handleFileComplete(SENDER, { transferId: 'trp' });
    assert.equal(done.success, true, 'sha256 matches after trimming the padding');
    assert.equal(readFileSync(done.savePath, 'utf-8'), content);
  });

  test('a missing chunk requests a resend instead of failing', async () => {
    const { offer, chunks } = makeOffer('a larger content spanning several chunks');
    ft.handleFileOffer(SENDER, offer, 'davi');

    // send all but chunk 1
    chunks.forEach((c, i) => {
      if (i !== 1) {
        ft.handleFileChunk(SENDER, {
          transferId: 'tr1',
          chunkIndex: i,
          data: c.toString('base64'),
        });
      }
    });

    const first = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    assert.equal(first.success, false);
    assert.equal(first.resume, true);
    assert.deepEqual(first.missing, [1]);

    // resending the lost chunk completes the transfer
    ft.handleFileChunk(SENDER, {
      transferId: 'tr1',
      chunkIndex: 1,
      data: chunks[1].toString('base64'),
    });
    const second = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    assert.equal(second.success, true);
  });

  test('gives up after the retry limit', async () => {
    const { offer } = makeOffer('abcdefghijklmnop');
    ft.handleFileOffer(SENDER, offer, 'davi');

    let last;
    for (let i = 0; i < 4; i++) {
      last = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    }
    assert.equal(last.success, false);
    assert.equal(last.resume, undefined);
    assert.match(last.message, /attempts/);
  });

  test('resumes after timeout: a new offer for the same file reuses chunks', async () => {
    const { offer, chunks } = makeOffer('part one part two part three!!');
    ft.handleFileOffer(SENDER, offer, 'davi');
    ft.handleFileChunk(SENDER, {
      transferId: 'tr1',
      chunkIndex: 0,
      data: chunks[0].toString('base64'),
    });
    ft.handleFileChunk(SENDER, {
      transferId: 'tr1',
      chunkIndex: 2,
      data: chunks[2].toString('base64'),
    });

    // let the 120ms timeout fire — the partial goes to the stash keyed by sha256
    await new Promise((r) => setTimeout(r, 250));

    // sender reconnected and offered the same file with a different transferId
    const again = ft.handleFileOffer(SENDER, { ...offer, transferId: 'tr2' }, 'davi');
    assert.deepEqual(again.have, [0, 2]);
    assert.match(again.message, /resuming \(2\//);

    // only the chunks that were missing
    for (const i of [1, 3]) {
      ft.handleFileChunk(SENDER, {
        transferId: 'tr2',
        chunkIndex: i,
        data: chunks[i].toString('base64'),
      });
    }
    const done = await ft.handleFileComplete(SENDER, { transferId: 'tr2' });
    assert.equal(done.success, true);
    assert.equal(readFileSync(done.savePath, 'utf-8'), 'part one part two part three!!');
  });

  test('does not send chunks until the receiver accepts (consent)', async () => {
    const path = join(dir, 'source2.txt');
    writeFileSync(path, 'file content');

    const sent = [];
    const done = ft.initSend(path, (p) => sent.push(p), {
      onProgress: () => {},
      onError: () => {},
      onComplete: () => {},
    });

    await new Promise((r) => setTimeout(r, 50));
    assert.ok(
      sent.some((p) => p.action === 'file_offer'),
      'the offer was sent',
    );
    assert.ok(
      !sent.some((p) => p.action === 'file_chunk'),
      'no chunk before accepting',
    );

    const transferId = sent.find((p) => p.action === 'file_offer').transferId;
    ft.handleFileAccept(SENDER, { transferId, have: [] });
    await done;

    assert.ok(sent.some((p) => p.action === 'file_chunk'), 'chunks after accepting');
    assert.ok(sent.some((p) => p.action === 'file_complete'));
  });

  test('reject aborts the transfer without sending chunks', async () => {
    const path = join(dir, 'source3.txt');
    writeFileSync(path, 'content');

    const sent = [];
    let errored = false;
    const done = ft.initSend(path, (p) => sent.push(p), {
      onProgress: () => {},
      onError: () => {
        errored = true;
      },
      onComplete: () => {},
    });

    await new Promise((r) => setTimeout(r, 50));
    const transferId = sent.find((p) => p.action === 'file_offer').transferId;
    ft.handleFileReject(SENDER, { transferId });
    await done;

    assert.equal(errored, true);
    assert.ok(!sent.some((p) => p.action === 'file_chunk'));
  });

  test('sender keeps chunks for resend after completing', async () => {
    const path = join(dir, 'source.txt');
    writeFileSync(path, 'content that will be resent later');

    const sent = [];
    const done = ft.initSend(path, (p) => sent.push(p), {
      onProgress: () => {},
      onError: () => {},
      onComplete: () => {},
    });

    await new Promise((r) => setTimeout(r, 50));
    const transferId = sent.find((p) => p.action === 'file_offer').transferId;
    ft.handleFileAccept(SENDER, { transferId, have: [] });
    await done;

    const resend = ft.getChunksForResend(transferId, [0]);
    assert.equal(resend.length, 1);
    assert.equal(resend[0].index, 0);
    assert.ok(resend[0].data.length > 0);

    // invalid indices are filtered out
    assert.deepEqual(ft.getChunksForResend(transferId, [99, -1]), []);
    assert.equal(ft.getChunksForResend('nonexistent', [0]), null);
  });
});
