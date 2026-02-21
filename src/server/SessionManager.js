import { randomUUID } from 'node:crypto';
import { createLogger } from '../shared/logger.js';

const log = createLogger('session');

export class SessionManager {
  #sessions; // Map<sessionId, { ws, nickname, publicKey, connectedAt, room }>
  #nicknames; // Set<nickname> for quick dupe check
  #recentlyLeft; // Map<sessionId, { nickname, publicKey, leftAt }>
  #rooms; // Map<roomName, Set<sessionId>>

  constructor() {
    this.#sessions = new Map();
    this.#nicknames = new Set();
    this.#recentlyLeft = new Map();
    this.#rooms = new Map();
    // Ensure default room exists
    this.#rooms.set('general', new Set());
  }

  isNicknameTaken(nickname) {
    return this.#nicknames.has(nickname.toLowerCase());
  }

  addSession(ws, nickname, publicKey, room = 'general') {
    const sessionId = randomUUID();
    const session = {
      ws,
      nickname,
      publicKey,
      connectedAt: Date.now(),
      room,
    };

    this.#sessions.set(sessionId, session);
    this.#nicknames.add(nickname.toLowerCase());
    this.#joinRoom(sessionId, room);

    log.info(`${nickname} conectado (${sessionId.slice(0, 8)}) na sala ${room}`);
    return sessionId;
  }

  removeSession(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return null;
    }

    this.#leaveRoom(sessionId);
    this.#nicknames.delete(session.nickname.toLowerCase());
    this.#sessions.delete(sessionId);

    // Track recently left peers for offline queue
    this.#recentlyLeft.set(sessionId, {
      nickname: session.nickname,
      publicKey: session.publicKey,
      leftAt: Date.now(),
    });

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
   * Return peer list (excluding a given sessionId), filtered by room.
   */
  getPeers(excludeSessionId, room = null) {
    const peers = [];
    for (const [id, session] of this.#sessions) {
      if (id !== excludeSessionId) {
        if (room && session.room !== room) continue;
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

  /**
   * Broadcast to members of a specific room only.
   */
  broadcastToRoom(room, msg, excludeSessionId) {
    const members = this.#rooms.get(room);
    if (!members) return;

    const data = JSON.stringify(msg);
    for (const sid of members) {
      if (sid === excludeSessionId) continue;
      const session = this.#sessions.get(sid);
      if (session && session.ws.readyState === 1) {
        session.ws.send(data);
      }
    }
  }

  // ── Room management ──────────────────────────────────────────

  #joinRoom(sessionId, room) {
    if (!this.#rooms.has(room)) {
      this.#rooms.set(room, new Set());
    }
    this.#rooms.get(room).add(sessionId);
  }

  #leaveRoom(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) return;

    const members = this.#rooms.get(session.room);
    if (members) {
      members.delete(sessionId);
      // Clean up empty rooms (except general)
      if (members.size === 0 && session.room !== 'general') {
        this.#rooms.delete(session.room);
      }
    }
  }

  switchRoom(sessionId, newRoom) {
    const session = this.#sessions.get(sessionId);
    if (!session) return null;

    const oldRoom = session.room;
    if (oldRoom === newRoom) return null;

    this.#leaveRoom(sessionId);
    session.room = newRoom;
    this.#joinRoom(sessionId, newRoom);

    log.info(`${session.nickname} mudou de sala: ${oldRoom} → ${newRoom}`);
    return { oldRoom, newRoom };
  }

  getRoomPeers(room, excludeSessionId) {
    return this.getPeers(excludeSessionId, room);
  }

  listRooms() {
    const rooms = [];
    for (const [name, members] of this.#rooms) {
      if (members.size > 0) {
        rooms.push({ name, memberCount: members.size });
      }
    }
    // Always include 'general' even if empty
    if (!rooms.some((r) => r.name === 'general')) {
      rooms.unshift({ name: 'general', memberCount: 0 });
    }
    return rooms.sort((a, b) => a.name.localeCompare(b.name));
  }

  getSessionRoom(sessionId) {
    const session = this.#sessions.get(sessionId);
    return session?.room || null;
  }

  updatePublicKey(sessionId, newPublicKey) {
    const session = this.#sessions.get(sessionId);
    if (session) {
      session.publicKey = newPublicKey;
      log.info(`${session.nickname} rotacionou chaves (${sessionId.slice(0, 8)})`);
    }
  }

  getRecentlyLeft(sessionId) {
    return this.#recentlyLeft.get(sessionId) || null;
  }

  cleanupRecentlyLeft(maxAgeMs) {
    const now = Date.now();
    for (const [key, entry] of this.#recentlyLeft) {
      if (now - entry.leftAt > maxAgeMs) {
        this.#recentlyLeft.delete(key);
      }
    }
  }

  get size() {
    return this.#sessions.size;
  }
}
