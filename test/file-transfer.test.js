import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash, randomFillSync } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileTransfer } from '../src/client/FileTransfer.js';

const SENDER = 'sess-remetente';

function makeOffer(content, transferId = 'tr1') {
  const chunks = [];
  const CHUNK = 8;
  for (let i = 0; i < content.length; i += CHUNK) {
    chunks.push(Buffer.from(content.slice(i, i + CHUNK)));
  }
  return {
    offer: {
      transferId,
      fileName: 'dados.txt',
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

  test('transferencia completa salva o arquivo', async () => {
    const { offer, chunks } = makeOffer('conteudo de teste ok');
    const res = ft.handleFileOffer(SENDER, offer, 'davi');
    assert.match(res.message, /enviando dados\.txt/);
    assert.equal(res.have.length, 0);

    chunks.forEach((c, i) =>
      ft.handleFileChunk(SENDER, { transferId: 'tr1', chunkIndex: i, data: c.toString('base64') }),
    );
    const done = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    assert.equal(done.success, true);
    assert.equal(readFileSync(done.savePath, 'utf-8'), 'conteudo de teste ok');
  });

  test('padding do ultimo chunk e removido na remontagem (esconde tamanho)', async () => {
    const content = 'arquivo cujo tamanho nao alinha aos limites de chunk!!!';
    const CHUNK = 16;
    const chunks = [];
    for (let i = 0; i < content.length; i += CHUNK) {
      chunks.push(Buffer.from(content.slice(i, i + CHUNK)));
    }
    // Simula o wire: o ultimo chunk chega paddado ate o tamanho cheio.
    const last = chunks[chunks.length - 1];
    const padded = Buffer.alloc(CHUNK);
    last.copy(padded);
    randomFillSync(padded, last.length);
    chunks[chunks.length - 1] = padded;

    const offer = {
      transferId: 'trp',
      fileName: 'x.txt',
      fileSize: content.length, // tamanho real, sem o padding
      totalChunks: chunks.length,
      sha256: createHash('sha256').update(Buffer.from(content)).digest('hex'),
    };
    ft.handleFileOffer(SENDER, offer, 'davi');
    chunks.forEach((c, i) =>
      ft.handleFileChunk(SENDER, { transferId: 'trp', chunkIndex: i, data: c.toString('base64') }),
    );
    const done = await ft.handleFileComplete(SENDER, { transferId: 'trp' });
    assert.equal(done.success, true, 'sha256 confere depois de truncar o padding');
    assert.equal(readFileSync(done.savePath, 'utf-8'), content);
  });

  test('chunk faltando pede reenvio em vez de falhar', async () => {
    const { offer, chunks } = makeOffer('um conteudo maior para varios chunks');
    ft.handleFileOffer(SENDER, offer, 'davi');

    // envia todos menos o chunk 1
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

    // reenvio do chunk perdido fecha a transferencia
    ft.handleFileChunk(SENDER, {
      transferId: 'tr1',
      chunkIndex: 1,
      data: chunks[1].toString('base64'),
    });
    const second = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    assert.equal(second.success, true);
  });

  test('desiste depois do limite de tentativas', async () => {
    const { offer } = makeOffer('abcdefghijklmnop');
    ft.handleFileOffer(SENDER, offer, 'davi');

    let last;
    for (let i = 0; i < 4; i++) {
      last = await ft.handleFileComplete(SENDER, { transferId: 'tr1' });
    }
    assert.equal(last.success, false);
    assert.equal(last.resume, undefined);
    assert.match(last.message, /tentativas/);
  });

  test('retoma apos timeout: novo offer do mesmo arquivo reaproveita chunks', async () => {
    const { offer, chunks } = makeOffer('parte um parte dois parte tres!!');
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

    // deixa o timeout de 120ms estourar — parcial vai pro stash por sha256
    await new Promise((r) => setTimeout(r, 250));

    // remetente reconectou e ofereceu o mesmo arquivo com outro transferId
    const again = ft.handleFileOffer(SENDER, { ...offer, transferId: 'tr2' }, 'davi');
    assert.deepEqual(again.have, [0, 2]);
    assert.match(again.message, /retomando \(2\//);

    // so os chunks que faltavam
    for (const i of [1, 3]) {
      ft.handleFileChunk(SENDER, {
        transferId: 'tr2',
        chunkIndex: i,
        data: chunks[i].toString('base64'),
      });
    }
    const done = await ft.handleFileComplete(SENDER, { transferId: 'tr2' });
    assert.equal(done.success, true);
    assert.equal(readFileSync(done.savePath, 'utf-8'), 'parte um parte dois parte tres!!');
  });

  test('nao envia chunks ate o receptor aceitar (consentimento)', async () => {
    const path = join(dir, 'origem2.txt');
    writeFileSync(path, 'conteudo do arquivo');

    const sent = [];
    const done = ft.initSend(path, (p) => sent.push(p), {
      onProgress: () => {},
      onError: () => {},
      onComplete: () => {},
    });

    await new Promise((r) => setTimeout(r, 50));
    assert.ok(
      sent.some((p) => p.action === 'file_offer'),
      'a oferta foi enviada',
    );
    assert.ok(
      !sent.some((p) => p.action === 'file_chunk'),
      'nenhum chunk antes de aceitar',
    );

    const transferId = sent.find((p) => p.action === 'file_offer').transferId;
    ft.handleFileAccept(SENDER, { transferId, have: [] });
    await done;

    assert.ok(sent.some((p) => p.action === 'file_chunk'), 'chunks apos aceitar');
    assert.ok(sent.some((p) => p.action === 'file_complete'));
  });

  test('reject aborta a transferencia sem enviar chunks', async () => {
    const path = join(dir, 'origem3.txt');
    writeFileSync(path, 'conteudo');

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

  test('remetente guarda chunks para reenvio apos concluir', async () => {
    const path = join(dir, 'origem.txt');
    writeFileSync(path, 'conteudo que sera reenviado depois');

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

    // indices invalidos sao filtrados
    assert.deepEqual(ft.getChunksForResend(transferId, [99, -1]), []);
    assert.equal(ft.getChunksForResend('inexistente', [0]), null);
  });
});
