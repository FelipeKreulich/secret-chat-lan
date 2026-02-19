import { createLogger } from '../shared/logger.js';
import {
  OFFLINE_QUEUE_MAX_PER_PEER,
  OFFLINE_QUEUE_MAX_AGE_MS,
  OFFLINE_QUEUE_MAX_TOTAL,
} from '../shared/constants.js';

const log = createLogger('offline-queue');

export class OfflineQueue {
  #queues; // Map<nickname_lower, { publicKey, messages[] }>
  #totalCount;

  constructor() {
    this.#queues = new Map();
    this.#totalCount = 0;
  }

  /**
   * Enqueue a message for an offline peer.
   * @param {string} nickname - Peer's nickname
   * @param {string} publicKey - Peer's public key (base64)
   * @param {object} msg - The raw encrypted_message to store
   */
  enqueue(nickname, publicKey, msg) {
    if (this.#totalCount >= OFFLINE_QUEUE_MAX_TOTAL) {
      log.warn('Fila offline global cheia, descartando mensagem');
      return false;
    }

    const key = nickname.toLowerCase();
    let entry = this.#queues.get(key);

    if (!entry) {
      entry = { publicKey, messages: [] };
      this.#queues.set(key, entry);
    }

    if (entry.publicKey !== publicKey) {
      log.debug(`PublicKey mudou para ${nickname}, descartando fila antiga`);
      this.#totalCount -= entry.messages.length;
      entry.publicKey = publicKey;
      entry.messages = [];
    }

    if (entry.messages.length >= OFFLINE_QUEUE_MAX_PER_PEER) {
      log.warn(`Fila cheia para ${nickname}, descartando mensagem mais antiga`);
      entry.messages.shift();
      this.#totalCount--;
    }

    entry.messages.push({ msg, queuedAt: Date.now() });
    this.#totalCount++;

    log.debug(`Mensagem enfileirada para ${nickname} (${entry.messages.length} na fila)`);
    return true;
  }

  /**
   * Dequeue all messages for a peer if publicKey matches.
   * @param {string} nickname - Peer's nickname
   * @param {string} publicKey - Peer's current public key (base64)
   * @returns {object[]} Array of stored messages (may be empty)
   */
  dequeue(nickname, publicKey) {
    const key = nickname.toLowerCase();
    const entry = this.#queues.get(key);

    if (!entry) return [];

    if (entry.publicKey !== publicKey) {
      log.info(`${nickname} reconectou com chave diferente, descartando fila`);
      this.#totalCount -= entry.messages.length;
      this.#queues.delete(key);
      return [];
    }

    const now = Date.now();
    const valid = entry.messages.filter(
      (item) => now - item.queuedAt < OFFLINE_QUEUE_MAX_AGE_MS,
    );

    const expired = entry.messages.length - valid.length;
    if (expired > 0) {
      log.debug(`${expired} mensagens expiradas descartadas para ${nickname}`);
    }

    this.#totalCount -= entry.messages.length;
    this.#queues.delete(key);

    log.info(`${valid.length} mensagens entregues para ${nickname}`);
    return valid.map((item) => item.msg);
  }

  /**
   * Remove expired entries across all queues.
   */
  cleanup() {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.#queues) {
      const before = entry.messages.length;
      entry.messages = entry.messages.filter(
        (item) => now - item.queuedAt < OFFLINE_QUEUE_MAX_AGE_MS,
      );
      const diff = before - entry.messages.length;
      removed += diff;
      this.#totalCount -= diff;

      if (entry.messages.length === 0) {
        this.#queues.delete(key);
      }
    }

    if (removed > 0) {
      log.info(`Cleanup: ${removed} mensagens expiradas removidas`);
    }
  }

  get size() {
    return this.#totalCount;
  }
}
