import { randomUUID } from 'node:crypto';
import { createLogger } from '../shared/logger.js';

const log = createLogger('session');

export class SessionManager {
  #sessions; // Map<sessionId, { ws, nickname, publicKey, connectedAt, rooms: Set }>
  // lowercased nickname -> the sessions holding it. A Set of names was enough
  // while a name meant one connection; multi-device means several sessions can
  // share one, and releasing the name when the *first* of them leaves would
  // hand it to a stranger while its owner is still in the room.
  #nicknames; // Map<lowerNickname, Set<sessionId>>
  #recentlyLeft; // Map<sessionId, { nickname, publicKey, leftAt }>
  #rooms; // Map<roomName, Set<sessionId>>
  #roomOwners; // Map<roomName, sessionId>
  #muteState; // Map<sessionId, { until: timestamp }>
  #banList; // Map<roomName, Set<nickname_lower>>
  #roomMeta; // Map<roomName, { authPk: base64 }> — private-room verifiers (memory only)

  constructor() {
    this.#sessions = new Map();
    this.#nicknames = new Map();
    this.#recentlyLeft = new Map();
    this.#rooms = new Map();
    this.#roomOwners = new Map();
    this.#muteState = new Map();
    this.#banList = new Map();
    this.#roomMeta = new Map();
    // Ensure default room exists
    this.#rooms.set('general', new Set());
  }

  isNicknameTaken(nickname) {
    return (this.#nicknames.get(nickname.toLowerCase())?.size ?? 0) > 0;
  }

  /**
   * The identity key the sessions under this nickname are using, or null.
   *
   * Null when they disagree — which should not happen, since a second session
   * is only admitted after matching, but a name whose holders cannot agree on
   * an identity is not a name anything else should be admitted to.
   */
  identityForNickname(nickname) {
    const holders = this.#nicknames.get(nickname.toLowerCase());
    if (!holders || holders.size === 0) {
      return null;
    }
    let identity = null;
    for (const sessionId of holders) {
      const key = this.#sessions.get(sessionId)?.identityKey ?? null;
      if (!key || (identity && identity !== key)) {
        return null;
      }
      identity = key;
    }
    return identity;
  }

  /** How many sessions currently answer to this nickname. */
  sessionsForNickname(nickname) {
    return this.#nicknames.get(nickname.toLowerCase())?.size ?? 0;
  }

  addSession(
    ws,
    nickname,
    publicKey,
    room = 'general',
    pqPublicKey = null,
    capabilities = [],
    identityKey = null,
  ) {
    const sessionId = randomUUID();
    const session = {
      ws,
      nickname,
      publicKey,
      pqPublicKey, // ML-KEM-768 key, relayed verbatim (server never uses it)
      // Ed25519 identity key, relayed verbatim like the rest. The relay cannot
      // check it belongs to this session and must not pretend to: a client
      // trusts an identity key because a signed device list says so, never
      // because a relay repeated it.
      identityKey,
      capabilities, // advertised in JOIN, relayed verbatim — the relay never acts on these
      connectedAt: Date.now(),
      rooms: new Set(),
    };

    this.#sessions.set(sessionId, session);
    const lower = nickname.toLowerCase();
    if (!this.#nicknames.has(lower)) {
      this.#nicknames.set(lower, new Set());
    }
    this.#nicknames.get(lower).add(sessionId);
    this.#joinRoom(sessionId, room);

    log.info(`${nickname} connected (${sessionId.slice(0, 8)}) in room ${room}`);
    return sessionId;
  }

  removeSession(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return null;
    }

    for (const room of [...session.rooms]) {
      this.#leaveRoom(sessionId, room);
    }
    const lower = session.nickname.toLowerCase();
    const holders = this.#nicknames.get(lower);
    if (holders) {
      holders.delete(sessionId);
      if (holders.size === 0) {
        this.#nicknames.delete(lower);
      }
    }
    this.#sessions.delete(sessionId);
    this.#muteState.delete(sessionId);

    // Track recently left peers for offline queue
    this.#recentlyLeft.set(sessionId, {
      nickname: session.nickname,
      publicKey: session.publicKey,
      leftAt: Date.now(),
    });

    log.info(`${session.nickname} disconnected (${sessionId.slice(0, 8)})`);
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
        if (room && !session.rooms.has(room)) {
          continue;
        }
        peers.push({
          sessionId: id,
          nickname: session.nickname,
          publicKey: session.publicKey,
          ...(session.pqPublicKey ? { pqPublicKey: session.pqPublicKey } : {}),
          ...(session.identityKey ? { identityKey: session.identityKey } : {}),
          ...(session.capabilities?.length ? { caps: [...session.capabilities] } : {}),
        });
      }
    }
    return peers;
  }

  /**
   * Send a message once to every session that shares at least one room with
   * the given session (deduplicated — a peer in two shared rooms gets one).
   */
  broadcastToPeersOf(sessionId, msg, excludeSessionId = sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return;
    }
    const data = JSON.stringify(msg);
    const notified = new Set();
    for (const room of session.rooms) {
      const members = this.#rooms.get(room);
      if (!members) {
        continue;
      }
      for (const sid of members) {
        if (sid === excludeSessionId || notified.has(sid)) {
          continue;
        }
        notified.add(sid);
        const peer = this.#sessions.get(sid);
        if (peer && peer.ws.readyState === 1) {
          peer.ws.send(data);
        }
      }
    }
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
    if (!members) {
      return;
    }

    const data = JSON.stringify(msg);
    for (const sid of members) {
      if (sid === excludeSessionId) {
        continue;
      }
      const session = this.#sessions.get(sid);
      if (session && session.ws.readyState === 1) {
        session.ws.send(data);
      }
    }
  }

  // ── Room management ──────────────────────────────────────────

  #joinRoom(sessionId, room) {
    const isNew = !this.#rooms.has(room) || this.#rooms.get(room).size === 0;
    if (!this.#rooms.has(room)) {
      this.#rooms.set(room, new Set());
    }
    this.#rooms.get(room).add(sessionId);
    this.#sessions.get(sessionId)?.rooms.add(room);

    // First person to create/join an empty non-general room becomes owner
    if (isNew && room !== 'general' && !this.#roomOwners.has(room)) {
      this.#roomOwners.set(room, sessionId);
      log.info(`${sessionId.slice(0, 8)} is now owner of room ${room}`);
    }
  }

  #leaveRoom(sessionId, room) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return;
    }

    session.rooms.delete(room);
    const members = this.#rooms.get(room);
    if (members) {
      members.delete(sessionId);

      if (members.size === 0 && room !== 'general') {
        // Empty non-general room — drop it and all associated moderation state
        // (otherwise a recreated room stays owner-less and unmoderatable).
        // The private-room verifier dies here too: the room and its password
        // exist only while someone is inside.
        this.#rooms.delete(room);
        this.#roomOwners.delete(room);
        this.#banList.delete(room);
        this.#roomMeta.delete(room);
      } else if (this.#roomOwners.get(room) === sessionId) {
        // Owner left but room still has members — transfer ownership so the
        // room keeps a moderator instead of becoming owner-less.
        const nextOwner = members.values().next().value;
        this.#roomOwners.set(room, nextOwner);
        log.info(`Ownership of room ${room} transferred to ${nextOwner.slice(0, 8)}`);
      }
    }
  }

  /**
   * Legacy single-room semantics (protocol `change_room`): leave every
   * current room and end up only in `newRoom`.
   */
  switchRoom(sessionId, newRoom) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return null;
    }

    if (session.rooms.size === 1 && session.rooms.has(newRoom)) {
      return null; // already exactly there
    }

    const oldRooms = [...session.rooms].filter((r) => r !== newRoom);
    for (const room of oldRooms) {
      this.#leaveRoom(sessionId, room);
    }
    this.#joinRoom(sessionId, newRoom);

    log.info(`${session.nickname} switched room: ${oldRooms.join(',') || '-'} → ${newRoom}`);
    return { oldRoom: oldRooms[0] || null, oldRooms, newRoom };
  }

  /**
   * Multi-room: join an ADDITIONAL room, keeping the current ones.
   * Returns null when already a member.
   */
  joinAdditional(sessionId, room) {
    const session = this.#sessions.get(sessionId);
    if (!session || session.rooms.has(room)) {
      return null;
    }
    this.#joinRoom(sessionId, room);
    log.info(`${session.nickname} joined room ${room} (now in ${session.rooms.size})`);
    return { room };
  }

  /**
   * Multi-room: leave one room. Refuses to leave the last one (a session is
   * always somewhere — that keeps peer visibility and moderation coherent).
   */
  leaveOneRoom(sessionId, room) {
    const session = this.#sessions.get(sessionId);
    if (!session || !session.rooms.has(room)) {
      return null;
    }
    if (session.rooms.size === 1) {
      return { lastRoom: true };
    }
    this.#leaveRoom(sessionId, room);
    log.info(`${session.nickname} left room ${room} (now in ${session.rooms.size})`);
    return { room };
  }

  getSessionRooms(sessionId) {
    const session = this.#sessions.get(sessionId);
    return session ? [...session.rooms] : [];
  }

  isInRoom(sessionId, room) {
    return this.#sessions.get(sessionId)?.rooms.has(room) === true;
  }

  getRoomPeers(room, excludeSessionId) {
    return this.getPeers(excludeSessionId, room);
  }

  listRooms() {
    const rooms = [];
    for (const [name, members] of this.#rooms) {
      if (members.size > 0) {
        rooms.push({ name, memberCount: members.size, private: this.#roomMeta.has(name) });
      }
    }
    // Always include 'general' even if empty
    if (!rooms.some((r) => r.name === 'general')) {
      rooms.unshift({ name: 'general', memberCount: 0, private: false });
    }
    return rooms.sort((a, b) => a.name.localeCompare(b.name));
  }

  // ── Private rooms ────────────────────────────────────────────

  /** Number of live rooms (used for the server-wide room cap). */
  get roomCount() {
    let n = 0;
    for (const members of this.#rooms.values()) {
      if (members.size > 0) {
        n++;
      }
    }
    return n;
  }

  roomHasMembers(room) {
    const members = this.#rooms.get(room);
    return !!members && members.size > 0;
  }

  setRoomPrivate(room, authPkB64) {
    this.#roomMeta.set(room, { authPk: authPkB64 });
  }

  isRoomPrivate(room) {
    return this.#roomMeta.has(room);
  }

  getRoomAuthPk(room) {
    return this.#roomMeta.get(room)?.authPk || null;
  }

  /**
   * Legacy helper: a session's room when it has exactly one; null otherwise.
   * Multi-room callers must pass the room explicitly instead.
   */
  getSessionRoom(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) {
      return null;
    }
    return session.rooms.size === 1 ? [...session.rooms][0] : null;
  }

  updatePublicKey(sessionId, newPublicKey) {
    const session = this.#sessions.get(sessionId);
    if (session) {
      session.publicKey = newPublicKey;
      log.info(`${session.nickname} rotated keys (${sessionId.slice(0, 8)})`);
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

  // ── Admin / Moderation ─────────────────────────────────────

  isRoomOwner(room, sessionId) {
    return this.#roomOwners.get(room) === sessionId;
  }

  getRoomOwner(room) {
    return this.#roomOwners.get(room) || null;
  }

  isMuted(sessionId) {
    const state = this.#muteState.get(sessionId);
    if (!state) {
      return false;
    }
    if (Date.now() >= state.until) {
      this.#muteState.delete(sessionId);
      return false;
    }
    return true;
  }

  mutePeer(sessionId, durationMs) {
    this.#muteState.set(sessionId, { until: Date.now() + durationMs });
  }

  /**
   * Ban someone from a room.
   *
   * Keyed on the public key, never the nickname: /nick lets anyone pick a new
   * name whenever they like, so a nickname ban was undone by typing one word.
   * The public key is what an identity actually is here — the offline queue
   * already binds delivery to it, and this was the one place that did not.
   *
   * A new keypair still gets you back in, but it costs the verified status you
   * had with every contact and shows up as unverified under TOFU. That is a
   * real price; a new nickname is not.
   *
   * @param {string} room
   * @param {string} publicKey - base64, as the session carries it
   */
  banPeer(room, publicKey) {
    if (!publicKey) {
      return;
    }
    if (!this.#banList.has(room)) {
      this.#banList.set(room, new Set());
    }
    this.#banList.get(room).add(publicKey);
  }

  /**
   * @param {string} room
   * @param {string} publicKey - base64
   */
  isBanned(room, publicKey) {
    const banned = this.#banList.get(room);
    return !!publicKey && !!banned && banned.has(publicKey);
  }

  findSessionByNickname(nickname) {
    for (const [id, session] of this.#sessions) {
      if (session.nickname.toLowerCase() === nickname.toLowerCase()) {
        return id;
      }
    }
    return null;
  }
}
