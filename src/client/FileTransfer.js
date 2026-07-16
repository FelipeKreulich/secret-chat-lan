import { createReadStream, existsSync, mkdirSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { basename, resolve, join } from 'node:path';
import { createHash, randomFillSync } from 'node:crypto';
import { MAX_FILE_SIZE, FILE_CHUNK_SIZE } from '../shared/constants.js';

const TRANSFER_TIMEOUT_MS = 30_000;
const SEND_INTERVAL_MS = 40; // ~25 chunks/sec
const RESUME_KEEP_MS = 5 * 60_000; // guarda parciais e cache de reenvio por 5 min
const MAX_RESUME_ATTEMPTS = 3;
const MAX_RESEND_BATCH = 300;

export class FileTransfer {
  #outgoing; // Map<transferId, { interval, resolve, chunks, skip }>
  #sentCache; // Map<transferId, { chunks, timer }> — p/ reenviar chunks perdidos
  #incoming; // Map<transferId, { fileName, fileSize, totalChunks, chunks, sha256, from, timer, attempts }>
  #partials; // Map<sha256, { chunks, received, fileSize, totalChunks, timer }>
  #downloadDir;
  #transferTimeoutMs;
  #resumeKeepMs;
  #acceptTimeoutMs;

  constructor(options = {}) {
    this.#outgoing = new Map();
    this.#sentCache = new Map();
    this.#incoming = new Map();
    this.#partials = new Map();
    this.#downloadDir = resolve(options.downloadDir || './downloads');
    this.#transferTimeoutMs = options.transferTimeoutMs || TRANSFER_TIMEOUT_MS;
    this.#resumeKeepMs = options.resumeKeepMs || RESUME_KEEP_MS;
    this.#acceptTimeoutMs = options.acceptTimeoutMs || 60_000;
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
      callbacks.onError(
        `Arquivo muito grande (${(stat.size / 1024 / 1024).toFixed(1)}MB). Max: 50MB`,
      );
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

    callbacks.onProgress(0, `Aguardando o destinatario aceitar ${fileName}...`);

    // Read the chunks now, but WAIT for the receiver to accept before streaming
    // (so files are never pushed without consent).
    const chunks = await this.#readChunks(absPath);

    return new Promise((resolveP) => {
      const acceptTimer = setTimeout(() => {
        this.#outgoing.delete(transferId);
        callbacks.onError(`${fileName}: oferta nao foi aceita a tempo`);
        resolveP();
      }, this.#acceptTimeoutMs);
      if (acceptTimer.unref) {
        acceptTimer.unref();
      }

      this.#outgoing.set(transferId, {
        interval: null,
        resolve: resolveP,
        chunks,
        skip: new Set(),
        pending: true,
        acceptTimer,
        broadcastFn,
        callbacks,
        fileName,
        totalChunks,
      });
    });
  }

  /** Receiver accepted the offer — start streaming (honouring resume `have`). */
  handleFileAccept(fromSessionId, data) {
    const transfer = this.#outgoing.get(data.transferId);
    if (!transfer || !transfer.pending) {
      return;
    }
    transfer.pending = false;
    clearTimeout(transfer.acceptTimer);
    if (Array.isArray(data.have)) {
      for (const i of data.have) {
        if (Number.isInteger(i) && i >= 0) {
          transfer.skip.add(i);
        }
      }
    }
    this.#beginStreaming(data.transferId);
  }

  /** Receiver rejected the offer — abort the pending transfer. */
  handleFileReject(fromSessionId, data) {
    const transfer = this.#outgoing.get(data.transferId);
    if (!transfer) {
      return;
    }
    clearTimeout(transfer.acceptTimer);
    if (transfer.interval) {
      clearInterval(transfer.interval);
    }
    this.#outgoing.delete(data.transferId);
    transfer.callbacks.onError(`${transfer.fileName}: recusado pelo destinatario`);
    transfer.resolve();
  }

  #beginStreaming(transferId) {
    const transfer = this.#outgoing.get(transferId);
    if (!transfer) {
      return;
    }
    const { chunks, skip, broadcastFn, callbacks, fileName, totalChunks, resolve } = transfer;
    let chunkIndex = 0;

    const interval = setInterval(() => {
      while (chunkIndex < chunks.length && skip.has(chunkIndex)) {
        chunkIndex++;
      }

      if (chunkIndex >= chunks.length) {
        clearInterval(interval);
        this.#outgoing.delete(transferId);
        this.#cacheSent(transferId, chunks);

        broadcastFn({ action: 'file_complete', transferId });
        callbacks.onComplete(`${fileName} enviado com sucesso`);
        resolve();
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

    transfer.interval = interval;
  }

  // Mantem os chunks apos o envio para responder file_resume_request
  #cacheSent(transferId, chunks) {
    const old = this.#sentCache.get(transferId);
    if (old) {
      clearTimeout(old.timer);
    }
    this.#sentCache.set(transferId, {
      chunks,
      timer: setTimeout(() => this.#sentCache.delete(transferId), this.#resumeKeepMs),
    });
  }

  /**
   * Receptor avisou quais chunks ja tem (resume apos re-offer) — pula no envio.
   */
  handleFileHave(fromSessionId, data) {
    const transfer = this.#outgoing.get(data.transferId);
    if (!transfer || !Array.isArray(data.have)) {
      return;
    }
    for (const i of data.have) {
      if (Number.isInteger(i) && i >= 0) {
        transfer.skip.add(i);
      }
    }
  }

  /**
   * Chunks pedidos num file_resume_request, do envio ativo ou do cache.
   * @returns {Array<{index: number, data: string}>|null}
   */
  getChunksForResend(transferId, missing) {
    const source = this.#sentCache.get(transferId) || this.#outgoing.get(transferId);
    if (!source || !Array.isArray(missing)) {
      return null;
    }
    return missing
      .filter((i) => Number.isInteger(i) && i >= 0 && i < source.chunks.length)
      .slice(0, MAX_RESEND_BATCH)
      .map((i) => ({ index: i, data: source.chunks[i].toString('base64') }));
  }

  /**
   * Handle incoming file_offer action.
   * @returns {{ message: string, have: number[] }}
   */
  handleFileOffer(fromSessionId, data, peerNickname) {
    const { transferId, fileName, fileSize, totalChunks, sha256 } = data;

    // Clear any existing transfer with same id
    this.#clearIncoming(transferId);

    // Resume: parcial guardado do mesmo arquivo (mesmo SHA-256)?
    let chunks = new Array(totalChunks).fill(null);
    let received = 0;
    let have = [];
    const partial = this.#partials.get(sha256);
    if (partial && partial.fileSize === fileSize && partial.totalChunks === totalChunks) {
      clearTimeout(partial.timer);
      this.#partials.delete(sha256);
      chunks = partial.chunks;
      received = partial.received;
      have = [];
      for (let i = 0; i < chunks.length; i++) {
        if (chunks[i]) {
          have.push(i);
        }
      }
    }

    const timer = setTimeout(() => {
      this.#stashPartial(transferId);
    }, this.#transferTimeoutMs);

    this.#incoming.set(transferId, {
      fileName,
      fileSize,
      totalChunks,
      sha256,
      from: fromSessionId,
      peerNickname,
      chunks,
      received,
      attempts: 0,
      timer,
    });

    const resumeNote = have.length ? ` — retomando (${have.length}/${totalChunks} chunks)` : '';
    return {
      message: `${peerNickname} enviando ${fileName} (${(fileSize / 1024).toFixed(0)}KB)${resumeNote}`,
      have,
    };
  }

  /**
   * Handle incoming file_chunk action.
   * @returns {{ percent: number, text: string } | null}
   */
  handleFileChunk(fromSessionId, data) {
    const transfer = this.#incoming.get(data.transferId);
    if (!transfer || transfer.from !== fromSessionId) {
      return null;
    }

    const { chunkIndex } = data;
    if (chunkIndex < 0 || chunkIndex >= transfer.totalChunks) {
      return null;
    }

    if (!transfer.chunks[chunkIndex]) {
      transfer.chunks[chunkIndex] = Buffer.from(data.data, 'base64');
      transfer.received++;
    }

    // Reset timeout
    clearTimeout(transfer.timer);
    transfer.timer = setTimeout(() => {
      this.#stashPartial(data.transferId);
    }, this.#transferTimeoutMs);

    const percent = Math.round((transfer.received / transfer.totalChunks) * 100);
    return { percent, text: `Recebendo ${transfer.fileName}` };
  }

  /**
   * Handle incoming file_complete action.
   * @returns {{ success: boolean, message: string, savePath?: string, resume?: boolean, missing?: number[] }}
   */
  async handleFileComplete(fromSessionId, data) {
    const transfer = this.#incoming.get(data.transferId);
    if (!transfer || transfer.from !== fromSessionId) {
      return { success: false, message: 'Transfer desconhecido' };
    }

    clearTimeout(transfer.timer);

    // Chunks faltando — pede reenvio em vez de descartar tudo
    const missing = [];
    for (let i = 0; i < transfer.totalChunks; i++) {
      if (!transfer.chunks[i]) {
        missing.push(i);
      }
    }

    if (missing.length > 0) {
      transfer.attempts++;
      if (transfer.attempts > MAX_RESUME_ATTEMPTS) {
        this.#incoming.delete(data.transferId);
        return {
          success: false,
          message: `${transfer.fileName}: chunks faltando apos ${MAX_RESUME_ATTEMPTS} tentativas (${transfer.received}/${transfer.totalChunks})`,
        };
      }
      transfer.timer = setTimeout(() => {
        this.#stashPartial(data.transferId);
      }, this.#transferTimeoutMs);
      return {
        success: false,
        resume: true,
        missing: missing.slice(0, MAX_RESEND_BATCH),
        message: `${transfer.fileName}: faltam ${missing.length} chunk(s) — pedindo reenvio (tentativa ${transfer.attempts}/${MAX_RESUME_ATTEMPTS})`,
      };
    }

    // Reassemble — trim any last-chunk padding back to the real file size
    // (all chunks are padded to a uniform size on the wire to hide file size).
    const reassembled = Buffer.concat(transfer.chunks);
    const fullData = Number.isInteger(transfer.fileSize)
      ? reassembled.subarray(0, transfer.fileSize)
      : reassembled;

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
    return { success: true, message: `${transfer.fileName} salvo em ${savePath}`, savePath };
  }

  // Transferencia morreu no meio — guarda o parcial indexado por SHA-256
  // para retomar se o mesmo arquivo for oferecido de novo
  #stashPartial(transferId) {
    const transfer = this.#incoming.get(transferId);
    if (!transfer) {
      return;
    }
    clearTimeout(transfer.timer);
    this.#incoming.delete(transferId);

    if (transfer.received === 0 || !transfer.sha256) {
      return;
    }

    const old = this.#partials.get(transfer.sha256);
    if (old) {
      clearTimeout(old.timer);
    }
    this.#partials.set(transfer.sha256, {
      chunks: transfer.chunks,
      received: transfer.received,
      fileSize: transfer.fileSize,
      totalChunks: transfer.totalChunks,
      timer: setTimeout(() => this.#partials.delete(transfer.sha256), this.#resumeKeepMs),
    });
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
      stream.on('end', () => {
        // Pad the final (partial) chunk up to a full chunk so every chunk is the
        // same size on the wire — the relay then can't read the exact file size,
        // only its size rounded up to the chunk. The receiver truncates back to
        // fileSize on reassembly.
        const last = chunks[chunks.length - 1];
        if (last && last.length < FILE_CHUNK_SIZE) {
          const padded = Buffer.alloc(FILE_CHUNK_SIZE);
          last.copy(padded);
          randomFillSync(padded, last.length); // random tail, not compressible zeros
          chunks[chunks.length - 1] = padded;
        }
        resolve(chunks);
      });
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
    for (const [, entry] of this.#sentCache) {
      clearTimeout(entry.timer);
    }
    for (const [, entry] of this.#partials) {
      clearTimeout(entry.timer);
    }
    this.#outgoing.clear();
    this.#incoming.clear();
    this.#sentCache.clear();
    this.#partials.clear();
  }
}
