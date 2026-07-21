import { createLogger } from '../shared/logger.js';
import { RATE_LIMIT_PER_SECOND } from '../shared/constants.js';
import { createError, ERR } from '../protocol/messages.js';

const log = createLogger('router');

export class MessageRouter {
  #sessionManager;
  #offlineQueue;
  #rateCounts; // Map<sessionId, { count, resetAt }>

  constructor(sessionManager, offlineQueue) {
    this.#sessionManager = sessionManager;
    this.#offlineQueue = offlineQueue;
    this.#rateCounts = new Map();
  }

  /**
   * Route an encrypted_message from sender to recipient.
   * The server NEVER inspects payload contents.
   */
  route(senderSessionId, msg) {
    // Rate limit check
    if (!this.#checkRateLimit(senderSessionId)) {
      const senderSession = this.#sessionManager.getSession(senderSessionId);
      if (senderSession?.ws.readyState === 1) {
        senderSession.ws.send(
          JSON.stringify(createError(ERR.RATE_LIMITED, 'Too many messages per second')),
        );
      }
      return;
    }

    const recipientSession = this.#sessionManager.getSession(msg.to);
    if (!recipientSession) {
      // Try to enqueue for offline delivery
      const leftPeer = this.#sessionManager.getRecentlyLeft(msg.to);
      if (leftPeer) {
        this.#offlineQueue.enqueue(leftPeer.nickname, leftPeer.publicKey, msg);
        log.debug(`Message queued for ${leftPeer.nickname} (offline)`);
        return;
      }

      const senderSession = this.#sessionManager.getSession(senderSessionId);
      if (senderSession?.ws.readyState === 1) {
        senderSession.ws.send(
          JSON.stringify(createError(ERR.PEER_NOT_FOUND, 'Recipient not found')),
        );
      }
      log.warn(`Peer ${msg.to?.slice(0, 8)} not found`);
      return;
    }

    if (recipientSession.ws.readyState === 1) {
      recipientSession.ws.send(JSON.stringify(msg));
      // Sealed sender: never log who sent it — only that something was routed to
      // the recipient. Correlating sender->recipient in logs would defeat it.
      log.debug(`routed -> ${msg.to.slice(0, 8)}`);
    }
  }

  #checkRateLimit(sessionId) {
    const now = Date.now();
    const entry = this.#rateCounts.get(sessionId);

    if (!entry || now >= entry.resetAt) {
      this.#rateCounts.set(sessionId, { count: 1, resetAt: now + 1000 });
      return true;
    }

    if (entry.count >= RATE_LIMIT_PER_SECOND) {
      return false;
    }

    entry.count++;
    return true;
  }

  cleanupSession(sessionId) {
    this.#rateCounts.delete(sessionId);
  }
}
