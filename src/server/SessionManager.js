import { randomUUID } from 'node:crypto';
import { createLogger } from '../shared/logger.js';

const log = createLogger('session');

export class SessionManager {
  #sessions; // Map<sessionId, { ws, nickname, publicKey, connectedAt }>
  #nicknames; // Set<nickname> for quick dupe check

  constructor() {
    this.#sessions = new Map();
    this.#nicknames = new Set();
  }

  isNicknameTaken(nickname) {
    return this.#nicknames.has(nickname.toLowerCase());
  }

  addSession(ws, nickname, publicKey) {
    const sessionId = randomUUID();
    const session = {
      ws,
      nickname,
      publicKey,
      connectedAt: Date.now(),
    };

    this.#sessions.set(sessionId, session);
    this.#nicknames.add(nickname.toLowerCase());

    log.info(`${nickname} conectado (${sessionId.slice(0, 8)})`);
    return sessionId;
  }

  removeSession(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return null;
    }

    this.#nicknames.delete(session.nickname.toLowerCase());
    this.#sessions.delete(sessionId);

    log.info(`${session.nickname} desconectado (${sessionId.slice(0, 8)})`);
    return session;
  }

  getSession(sessionId) {
    return this.#sessions.get(sessionId);
  }

  /**
   * Find sessionId by WebSocket reference (for disconnect handling).
   */
  findSessionByWs(ws) {
    for (const [id, session] of this.#sessions) {
      if (session.ws === ws) {
        return id;
      }
    }
    return null;
  }

  /**
   * Return peer list (excluding a given sessionId).
   */
  getPeers(excludeSessionId) {
    const peers = [];
    for (const [id, session] of this.#sessions) {
      if (id !== excludeSessionId) {
        peers.push({
          sessionId: id,
          nickname: session.nickname,
          publicKey: session.publicKey,
        });
      }
    }
    return peers;
  }

  /**
   * Send a JSON message to all sessions except one.
   */
  broadcast(msg, excludeSessionId) {
    const data = JSON.stringify(msg);
    for (const [id, session] of this.#sessions) {
      if (id !== excludeSessionId && session.ws.readyState === 1) {
        session.ws.send(data);
      }
    }
  }

  get size() {
    return this.#sessions.size;
  }
}
