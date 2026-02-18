import { createLogger } from '../shared/logger.js';
import { RATE_LIMIT_PER_SECOND } from '../shared/constants.js';
import { createError, ERR } from '../protocol/messages.js';

const log = createLogger('router');

export class MessageRouter {
  #sessionManager;
  #rateCounts; // Map<sessionId, { count, resetAt }>

  constructor(sessionManager) {
    this.#sessionManager = sessionManager;
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
          JSON.stringify(createError(ERR.RATE_LIMITED, 'Muitas mensagens por segundo')),
        );
      }
      return;
    }

    const recipientSession = this.#sessionManager.getSession(msg.to);
    if (!recipientSession) {
      const senderSession = this.#sessionManager.getSession(senderSessionId);
      if (senderSession?.ws.readyState === 1) {
        senderSession.ws.send(
          JSON.stringify(createError(ERR.PEER_NOT_FOUND, 'Destinatario nao encontrado')),
        );
      }
      log.warn(`Peer ${msg.to?.slice(0, 8)} nao encontrado`);
      return;
    }

    if (recipientSession.ws.readyState === 1) {
      recipientSession.ws.send(JSON.stringify(msg));
      log.debug(`${senderSessionId.slice(0, 8)} -> ${msg.to.slice(0, 8)}`);
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
