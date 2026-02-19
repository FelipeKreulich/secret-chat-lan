import { createReadStream, existsSync, mkdirSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { basename, resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { MAX_FILE_SIZE, FILE_CHUNK_SIZE } from '../shared/constants.js';

const TRANSFER_TIMEOUT_MS = 30_000;
const SEND_INTERVAL_MS = 40; // ~25 chunks/sec

export class FileTransfer {
  #outgoing; // Map<transferId, { interval, resolve }>
  #incoming; // Map<transferId, { fileName, fileSize, totalChunks, chunks, sha256, from, timer }>
  #downloadDir;

  constructor() {
    this.#outgoing = new Map();
    this.#incoming = new Map();
    this.#downloadDir = resolve('./downloads');
    if (!existsSync(this.#downloadDir)) {
      mkdirSync(this.#downloadDir, { recursive: true });
    }
  }

  /**
   * Send a file to all peers.
   * @param {string} filePath - Absolute or relative path to file
   * @param {Function} broadcastFn - (payloadObj) => void, broadcasts encrypted payload
   * @param {object} callbacks - { onProgress(percent, text), onError(text), onComplete(text) }
   */
  async initSend(filePath, broadcastFn, callbacks) {
    const absPath = resolve(filePath);

    if (!existsSync(absPath)) {
      callbacks.onError(`Arquivo nao encontrado: ${filePath}`);
      return;
    }

    const stat = statSync(absPath);
    if (!stat.isFile()) {
      callbacks.onError('Caminho nao e um arquivo');
      return;
    }

    if (stat.size > MAX_FILE_SIZE) {
      callbacks.onError(`Arquivo muito grande (${(stat.size / 1024 / 1024).toFixed(1)}MB). Max: 50MB`);
      return;
    }

    if (stat.size === 0) {
      callbacks.onError('Arquivo vazio');
      return;
    }

    const fileName = basename(absPath);
    const totalChunks = Math.ceil(stat.size / FILE_CHUNK_SIZE);
    const transferId = Math.random().toString(36).slice(2, 10);

    // Compute SHA-256
    const sha256 = await this.#computeSHA256(absPath);

    // Send file_offer
    broadcastFn({
      action: 'file_offer',
      transferId,
      fileName,
      fileSize: stat.size,
      totalChunks,
      sha256,
    });

    callbacks.onProgress(0, `Enviando ${fileName} (${(stat.size / 1024).toFixed(0)}KB)`);

    // Read and send chunks
    const chunks = await this.#readChunks(absPath);
    let chunkIndex = 0;

    return new Promise((resolveP) => {
      const interval = setInterval(() => {
        if (chunkIndex >= chunks.length) {
          clearInterval(interval);
          this.#outgoing.delete(transferId);

          broadcastFn({
            action: 'file_complete',
            transferId,
          });

          callbacks.onComplete(`${fileName} enviado com sucesso`);
          resolveP();
          return;
        }

        broadcastFn({
          action: 'file_chunk',
          transferId,
          chunkIndex,
          data: chunks[chunkIndex].toString('base64'),
        });

        chunkIndex++;
        const percent = Math.round((chunkIndex / totalChunks) * 100);
        callbacks.onProgress(percent, `Enviando ${fileName}`);
      }, SEND_INTERVAL_MS);

      this.#outgoing.set(transferId, { interval, resolve: resolveP });
    });
  }

  /**
   * Handle incoming file_offer action.
   */
  handleFileOffer(fromSessionId, data, peerNickname) {
    const { transferId, fileName, fileSize, totalChunks, sha256 } = data;

    // Clear any existing transfer with same id
    this.#clearIncoming(transferId);

    const timer = setTimeout(() => {
      this.#clearIncoming(transferId);
    }, TRANSFER_TIMEOUT_MS);

    this.#incoming.set(transferId, {
      fileName,
      fileSize,
      totalChunks,
      sha256,
      from: fromSessionId,
      peerNickname,
      chunks: new Array(totalChunks).fill(null),
      received: 0,
      timer,
    });

    return `${peerNickname} enviando ${fileName} (${(fileSize / 1024).toFixed(0)}KB)`;
  }

  /**
   * Handle incoming file_chunk action.
   * @returns {{ percent: number, text: string } | null}
   */
  handleFileChunk(fromSessionId, data) {
    const transfer = this.#incoming.get(data.transferId);
    if (!transfer || transfer.from !== fromSessionId) return null;

    const { chunkIndex } = data;
    if (chunkIndex < 0 || chunkIndex >= transfer.totalChunks) return null;

    if (!transfer.chunks[chunkIndex]) {
      transfer.chunks[chunkIndex] = Buffer.from(data.data, 'base64');
      transfer.received++;
    }

    // Reset timeout
    clearTimeout(transfer.timer);
    transfer.timer = setTimeout(() => {
      this.#clearIncoming(data.transferId);
    }, TRANSFER_TIMEOUT_MS);

    const percent = Math.round((transfer.received / transfer.totalChunks) * 100);
    return { percent, text: `Recebendo ${transfer.fileName}` };
  }

  /**
   * Handle incoming file_complete action.
   * @returns {{ success: boolean, message: string }}
   */
  async handleFileComplete(fromSessionId, data) {
    const transfer = this.#incoming.get(data.transferId);
    if (!transfer || transfer.from !== fromSessionId) {
      return { success: false, message: 'Transfer desconhecido' };
    }

    clearTimeout(transfer.timer);

    // Check all chunks received
    const missing = transfer.chunks.findIndex((c) => c === null);
    if (missing !== -1) {
      this.#incoming.delete(data.transferId);
      return { success: false, message: `Chunks faltando (${transfer.received}/${transfer.totalChunks})` };
    }

    // Reassemble
    const fullData = Buffer.concat(transfer.chunks);

    // Verify SHA-256
    const hash = createHash('sha256').update(fullData).digest('hex');
    if (hash !== transfer.sha256) {
      this.#incoming.delete(data.transferId);
      return { success: false, message: `SHA-256 nao confere para ${transfer.fileName}` };
    }

    // Save to downloads
    const savePath = this.#getSafePath(transfer.fileName);
    await writeFile(savePath, fullData);

    this.#incoming.delete(data.transferId);
    return { success: true, message: `${transfer.fileName} salvo em ${savePath}` };
  }

  #clearIncoming(transferId) {
    const transfer = this.#incoming.get(transferId);
    if (transfer) {
      clearTimeout(transfer.timer);
      this.#incoming.delete(transferId);
    }
  }

  #getSafePath(fileName) {
    // Sanitize filename
    const safe = fileName.replace(/[<>:"/\\|?*]/g, '_');
    let savePath = join(this.#downloadDir, safe);

    // Avoid overwrite — append (1), (2), etc.
    if (existsSync(savePath)) {
      const dot = safe.lastIndexOf('.');
      const name = dot > 0 ? safe.slice(0, dot) : safe;
      const ext = dot > 0 ? safe.slice(dot) : '';
      let i = 1;
      do {
        savePath = join(this.#downloadDir, `${name} (${i})${ext}`);
        i++;
      } while (existsSync(savePath));
    }

    return savePath;
  }

  async #readChunks(filePath) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      const stream = createReadStream(filePath, { highWaterMark: FILE_CHUNK_SIZE });
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('end', () => resolve(chunks));
      stream.on('error', reject);
    });
  }

  async #computeSHA256(filePath) {
    return new Promise((resolve, reject) => {
      const hash = createHash('sha256');
      const stream = createReadStream(filePath);
      stream.on('data', (chunk) => hash.update(chunk));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  destroy() {
    for (const [, entry] of this.#outgoing) {
      clearInterval(entry.interval);
    }
    for (const [, entry] of this.#incoming) {
      clearTimeout(entry.timer);
    }
    this.#outgoing.clear();
    this.#incoming.clear();
  }
}
