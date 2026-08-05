import { createServer as createHttpsServer } from 'node:https';
import { randomBytes } from 'node:crypto';
import { WebSocketServer as WSServer } from 'ws';
import { createLogger } from '../shared/logger.js';
import {
  HEARTBEAT_INTERVAL_MS,
  MAX_PAYLOAD_SIZE,
  JOIN_TIMEOUT_MS,
  ROOM_CHALLENGE_NONCE_SIZE,
  ROOM_CHALLENGE_TTL_MS,
  ROOM_AUTH_MAX_FAILS,
  ROOM_AUTH_FAIL_WINDOW_MS,
} from '../shared/constants.js';
import {
  MSG,
  createJoinAck,
  createPeerJoined,
  createPeerLeft,
  createPeerKeyUpdated,
  createRoomChanged,
  createRoomJoined,
  createRoomLeft,
  createRoomChallenge,
  createRoomList,
  createPeerKicked,
  createPeerMuted,
  createError,
  ERR,
} from '../protocol/messages.js';
import {
  parseMessage,
  validateJoin,
  validateEncryptedMessage,
  validateKeyUpdate,
  validateChangeRoom,
  validateJoinRoom,
  validateLeaveRoom,
  validateRoomAuth,
  validateKickPeer,
  validateMutePeer,
  validateBanPeer,
} from '../protocol/validators.js';
import { verifyRoomChallenge } from '../crypto/RoomKey.js';
import { parseServerConfig, clientAddress, normalizeIp } from './config.js';

const log = createLogger('ws-server');

export class SecureWSServer {
  #wss;
  #httpsServer;
  #sessionManager;
  #messageRouter;
  #offlineQueue;
  #heartbeatInterval;
  #connectionsByIp;
  #config;

  constructor(sessionManager, messageRouter, offlineQueue, port, tlsOptions, config = null) {
    this.#sessionManager = sessionManager;
    this.#messageRouter = messageRouter;
    this.#offlineQueue = offlineQueue;
    this.#connectionsByIp = new Map();
    this.#config = config || parseServerConfig();

    if (tlsOptions) {
      this.#httpsServer = createHttpsServer(tlsOptions);
      this.#wss = new WSServer({
        server: this.#httpsServer,
        maxPayload: MAX_PAYLOAD_SIZE,
        clientTracking: true,
      });
      this.#httpsServer.listen(port);
      log.info(`TLS enabled (wss://) on port ${port}`);
    } else {
      this.#wss = new WSServer({
        port,
        maxPayload: MAX_PAYLOAD_SIZE,
        clientTracking: true,
      });
    }

    this.#wss.on('connection', (ws, req) => this.#handleConnection(ws, req));
    this.#wss.on('error', (err) => log.error(`Server error: ${err.message}`));

    this.#startHeartbeat();
  }

  #clientIp(req) {
    return normalizeIp(clientAddress(req, this.#config.trustProxy));
  }

  #handleConnection(ws, req) {
    const ip = this.#clientIp(req);

    // Operator banlist — the one lever that does not require reading messages.
    if (this.#config.bannedIps.has(ip)) {
      log.warn(`Rejected banned address ${ip}`);
      ws.close(1008, 'Address not allowed');
      return;
    }

    // Global connection cap (the new socket is already counted in clients).
    if (this.#wss.clients.size > this.#config.maxConnectionsTotal) {
      ws.close(1013, 'Server full');
      return;
    }
    // Per-IP connection cap.
    const ipCount = this.#connectionsByIp.get(ip) || 0;
    if (ipCount >= this.#config.maxConnectionsPerIp) {
      log.warn(`Too many connections from ${ip}, rejecting`);
      ws.close(1013, 'Too many connections from this IP');
      return;
    }
    this.#connectionsByIp.set(ip, ipCount + 1);

    ws.clientIp = ip;
    ws.isAlive = true;
    ws.sessionId = null;
    ws.hasJoined = false;
    ws.msgWindowStart = Date.now();
    ws.msgCount = 0;

    // Drop sockets that connect but never JOIN (slowloris / resource hold).
    ws.joinTimer = setTimeout(() => {
      if (!ws.hasJoined) {
        log.warn(`Connection from ${ip} without JOIN within ${JOIN_TIMEOUT_MS}ms, closing`);
        ws.terminate();
      }
    }, JOIN_TIMEOUT_MS);
    if (ws.joinTimer.unref) {
      ws.joinTimer.unref();
    }

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (data) => {
      this.#handleMessage(ws, data);
    });

    ws.on('close', () => {
      clearTimeout(ws.joinTimer);
      this.#releaseIp(ws.clientIp);
      this.#handleDisconnect(ws);
    });

    ws.on('error', (err) => {
      log.error(`WS error: ${err.message}`);
    });

    log.debug(`New WebSocket connection (${ip})`);
  }

  #releaseIp(ip) {
    if (!ip) {
      return;
    }
    const count = this.#connectionsByIp.get(ip) || 0;
    if (count <= 1) {
      this.#connectionsByIp.delete(ip);
    } else {
      this.#connectionsByIp.set(ip, count - 1);
    }
  }

  // Per-connection rate limit across ALL message types (JOIN, key_update, etc.),
  // not just encrypted_message. Prevents control-message floods / amplification.
  #allowMessage(ws) {
    const now = Date.now();
    if (now - ws.msgWindowStart >= 1000) {
      ws.msgWindowStart = now;
      ws.msgCount = 0;
    }
    ws.msgCount++;
    return ws.msgCount <= this.#config.messageRateLimitPerSecond;
  }

  #handleMessage(ws, data) {
    if (!this.#allowMessage(ws)) {
      ws.send(JSON.stringify(createError(ERR.RATE_LIMITED, 'Too many messages per second')));
      return;
    }

    const raw = data.toString('utf-8');
    const { valid, error, msg } = parseMessage(raw);

    if (!valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, error)));
      return;
    }

    switch (msg.type) {
      case MSG.JOIN:
        this.#handleJoin(ws, msg);
        break;

      case MSG.ENCRYPTED_MESSAGE:
        this.#handleEncryptedMessage(ws, msg);
        break;

      case MSG.KEY_UPDATE:
        this.#handleKeyUpdate(ws, msg);
        break;

      case MSG.CHANGE_ROOM:
        this.#handleChangeRoom(ws, msg);
        break;

      case MSG.JOIN_ROOM:
        this.#handleJoinRoom(ws, msg);
        break;

      case MSG.LEAVE_ROOM:
        this.#handleLeaveRoom(ws, msg);
        break;

      case MSG.ROOM_AUTH:
        this.#handleRoomAuth(ws, msg);
        break;

      case MSG.LIST_ROOMS:
        this.#handleListRooms(ws);
        break;

      case MSG.KICK_PEER:
        this.#handleKickPeer(ws, msg);
        break;

      case MSG.MUTE_PEER:
        this.#handleMutePeer(ws, msg);
        break;

      case MSG.BAN_PEER:
        this.#handleBanPeer(ws, msg);
        break;

      case MSG.PING:
        ws.send(JSON.stringify({ type: MSG.PONG, version: msg.version, timestamp: Date.now() }));
        break;

      default:
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, `Unknown type: ${msg.type}`)));
    }
  }

  #handleJoin(ws, msg) {
    if (ws.hasJoined) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Already in the chat')));
      return;
    }

    const validation = validateJoin(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    if (this.#sessionManager.isNicknameTaken(validation.nickname)) {
      ws.send(
        JSON.stringify(
          createError(ERR.NICKNAME_TAKEN, `Nickname "${validation.nickname}" is already in use`),
        ),
      );
      return;
    }

    const room = 'general';
    const sessionId = this.#sessionManager.addSession(
      ws,
      validation.nickname,
      msg.publicKey,
      room,
      validation.pqPublicKey,
    );
    ws.sessionId = sessionId;
    ws.hasJoined = true;
    clearTimeout(ws.joinTimer);

    // Deliver queued offline messages
    const queued = this.#offlineQueue.dequeue(validation.nickname, msg.publicKey);

    // Send ACK with peer list (room-scoped)
    const peers = this.#sessionManager.getRoomPeers(room, sessionId);
    const joinAck = createJoinAck(sessionId, peers, queued.length, room);
    const ownerSid = this.#sessionManager.getRoomOwner(room);
    if (ownerSid) {
      const ownerSession = this.#sessionManager.getSession(ownerSid);
      if (ownerSession) {
        joinAck.roomOwner = ownerSession.nickname;
      }
    }
    if (this.#config.motd) {
      joinAck.motd = this.#config.motd;
    }
    ws.send(JSON.stringify(joinAck));

    // Deliver queued messages with updated recipient sessionId
    for (const queuedMsg of queued) {
      const delivered = { ...queuedMsg, to: sessionId };
      ws.send(JSON.stringify(delivered));
    }

    // Notify others in the same room
    this.#sessionManager.broadcastToRoom(
      room,
      createPeerJoined({
        sessionId,
        nickname: validation.nickname,
        publicKey: msg.publicKey,
        ...(validation.pqPublicKey ? { pqPublicKey: validation.pqPublicKey } : {}),
      }),
      sessionId,
    );

    log.info(`${validation.nickname} joined room ${room} | Online: ${this.#sessionManager.size}`);
  }

  #handleEncryptedMessage(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    // Check if sender is muted
    if (this.#sessionManager.isMuted(ws.sessionId)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are muted')));
      return;
    }

    const validation = validateEncryptedMessage(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    // Sealed sender: the relay routes purely by `to`. It deliberately does NOT
    // learn, stamp, store, or log who sent this — the sender's identity is
    // sealed inside the envelope for the recipient only. Strip any stray `from`
    // a client might set so it can never be forwarded.
    delete msg.from;

    this.#messageRouter.route(ws.sessionId, msg);
  }

  #handleKeyUpdate(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateKeyUpdate(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    this.#sessionManager.updatePublicKey(ws.sessionId, msg.publicKey);

    // Broadcast the new key once to every peer sharing at least one room.
    this.#sessionManager.broadcastToPeersOf(
      ws.sessionId,
      createPeerKeyUpdated(ws.sessionId, msg.publicKey),
    );

    log.info(`${ws.sessionId.slice(0, 8)} rotated keys`);
  }

  #handleChangeRoom(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateChangeRoom(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const session = this.#sessionManager.getSession(ws.sessionId);

    // Check if user is banned from target room
    if (this.#sessionManager.isBanned(validation.room, session.publicKey)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are banned from this room')));
      return;
    }

    if (this.#roomCapExceeded(ws, validation.room)) {
      return;
    }

    // Creating a private room: register the password verifier, but only for
    // a room that doesn't exist yet (rooms die when the last member leaves).
    if (validation.roomAuthPk) {
      if (validation.room === 'general' || this.#sessionManager.roomHasMembers(validation.room)) {
        ws.send(
          JSON.stringify(
            createError(ERR.ROOM_EXISTS, 'Room already exists — join it with /join instead'),
          ),
        );
        return;
      }
      const result = this.#sessionManager.switchRoom(ws.sessionId, validation.room);
      if (!result) {
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
        return;
      }
      this.#sessionManager.setRoomPrivate(validation.room, validation.roomAuthPk);
      this.#finishRoomSwitch(ws, session, result);
      return;
    }

    // Joining a private room: don't switch yet — issue a challenge the client
    // must sign with the password-derived key (see #handleRoomAuth).
    if (this.#sessionManager.isRoomPrivate(validation.room)) {
      this.#issueRoomChallenge(ws, validation.room, 'switch');
      return;
    }

    const result = this.#sessionManager.switchRoom(ws.sessionId, validation.room);
    if (!result) {
      // Already in this room
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
      return;
    }

    this.#finishRoomSwitch(ws, session, result);
  }

  // Room caps. Multi-room lets one connection open many rooms, so both a
  // per-session and a server-wide ceiling are needed; without them a single
  // client can exhaust the room table by itself.
  #roomCapExceeded(ws, room) {
    if (this.#sessionManager.isInRoom(ws.sessionId, room)) {
      return false; // already there, not a new room
    }
    const mine = this.#sessionManager.getSessionRooms(ws.sessionId).length;
    if (mine >= this.#config.maxRoomsPerSession) {
      ws.send(
        JSON.stringify(
          createError(
            ERR.INVALID_MESSAGE,
            `You are in too many rooms (max ${this.#config.maxRoomsPerSession}) — /leave one first`,
          ),
        ),
      );
      return true;
    }
    // Only a room that does not exist yet adds to the server total.
    if (
      !this.#sessionManager.roomHasMembers(room) &&
      this.#sessionManager.roomCount >= this.#config.maxRoomsTotal
    ) {
      ws.send(
        JSON.stringify(createError(ERR.INVALID_MESSAGE, 'The server has too many rooms right now')),
      );
      return true;
    }
    return false;
  }

  // Multi-room: join an ADDITIONAL room, keeping current memberships.
  #handleJoinRoom(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateJoinRoom(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const session = this.#sessionManager.getSession(ws.sessionId);
    if (this.#sessionManager.isBanned(validation.room, session.publicKey)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are banned from this room')));
      return;
    }
    if (this.#roomCapExceeded(ws, validation.room)) {
      return;
    }

    // Creating a private room additively.
    if (validation.roomAuthPk) {
      if (validation.room === 'general' || this.#sessionManager.roomHasMembers(validation.room)) {
        ws.send(
          JSON.stringify(
            createError(ERR.ROOM_EXISTS, 'Room already exists — join it with /join instead'),
          ),
        );
        return;
      }
      const result = this.#sessionManager.joinAdditional(ws.sessionId, validation.room);
      if (!result) {
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
        return;
      }
      this.#sessionManager.setRoomPrivate(validation.room, validation.roomAuthPk);
      this.#finishRoomJoin(ws, session, validation.room);
      return;
    }

    if (this.#sessionManager.isRoomPrivate(validation.room)) {
      this.#issueRoomChallenge(ws, validation.room, 'join');
      return;
    }

    const result = this.#sessionManager.joinAdditional(ws.sessionId, validation.room);
    if (!result) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
      return;
    }
    this.#finishRoomJoin(ws, session, validation.room);
  }

  // Multi-room: leave one room (never the last — a session is always somewhere).
  #handleLeaveRoom(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateLeaveRoom(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const session = this.#sessionManager.getSession(ws.sessionId);
    const result = this.#sessionManager.leaveOneRoom(ws.sessionId, validation.room);
    if (!result) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are not in this room')));
      return;
    }
    if (result.lastRoom) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Cannot leave your last room')));
      return;
    }

    this.#sessionManager.broadcastToRoom(
      validation.room,
      createPeerLeft(ws.sessionId, session.nickname, validation.room),
      ws.sessionId,
    );
    ws.send(JSON.stringify(createRoomLeft(validation.room)));
    log.info(`${session.nickname} left room ${validation.room}`);
  }

  #issueRoomChallenge(ws, room, mode) {
    const nonce = randomBytes(ROOM_CHALLENGE_NONCE_SIZE).toString('base64');
    ws.roomChallenge = {
      room,
      nonce,
      mode, // 'switch' (change_room) or 'join' (additive join_room)
      expiresAt: Date.now() + ROOM_CHALLENGE_TTL_MS,
    };
    ws.send(JSON.stringify(createRoomChallenge(room, nonce)));
  }

  // Shared tail of an additive join: notify the room and confirm to the joiner.
  #finishRoomJoin(ws, session, room) {
    this.#sessionManager.broadcastToRoom(
      room,
      createPeerJoined(
        {
          sessionId: ws.sessionId,
          nickname: session.nickname,
          publicKey: session.publicKey,
          ...(session.pqPublicKey ? { pqPublicKey: session.pqPublicKey } : {}),
        },
        room,
      ),
      ws.sessionId,
    );

    const peers = this.#sessionManager.getRoomPeers(room, ws.sessionId);
    const roomJoined = createRoomJoined(room, peers, this.#sessionManager.isRoomPrivate(room));
    const ownerSid = this.#sessionManager.getRoomOwner(room);
    if (ownerSid) {
      const ownerSess = this.#sessionManager.getSession(ownerSid);
      if (ownerSess) {
        roomJoined.roomOwner = ownerSess.nickname;
      }
    }
    ws.send(JSON.stringify(roomJoined));

    log.info(`${session.nickname} joined room ${room} (additive)`);
  }

  #handleRoomAuth(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateRoomAuth(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    // Throttle wrong-password attempts per connection.
    const now = Date.now();
    if (
      !ws.roomAuthFailWindowStart ||
      now - ws.roomAuthFailWindowStart >= ROOM_AUTH_FAIL_WINDOW_MS
    ) {
      ws.roomAuthFailWindowStart = now;
      ws.roomAuthFails = 0;
    }
    if (ws.roomAuthFails >= ROOM_AUTH_MAX_FAILS) {
      ws.send(
        JSON.stringify(createError(ERR.RATE_LIMITED, 'Too many failed attempts — wait a minute')),
      );
      return;
    }

    const challenge = ws.roomChallenge;
    if (
      !challenge ||
      challenge.room !== validation.room ||
      challenge.nonce !== validation.nonce ||
      now > challenge.expiresAt
    ) {
      ws.send(JSON.stringify(createError(ERR.ROOM_AUTH_FAILED, 'Challenge expired — /join again')));
      return;
    }
    ws.roomChallenge = null;

    const authPkB64 = this.#sessionManager.getRoomAuthPk(validation.room);
    if (!authPkB64) {
      // Room emptied (and died) between challenge and answer.
      ws.send(
        JSON.stringify(
          createError(ERR.ROOM_AUTH_FAILED, 'Room no longer exists — /join again to create it'),
        ),
      );
      return;
    }

    const ok = verifyRoomChallenge(
      Buffer.from(authPkB64, 'base64'),
      Buffer.from(validation.signature, 'base64'),
      validation.room,
      validation.nonce,
      ws.sessionId,
    );
    if (!ok) {
      ws.roomAuthFails++;
      ws.send(JSON.stringify(createError(ERR.ROOM_AUTH_FAILED, 'Wrong room password')));
      log.warn(`Failed room auth for ${validation.room} (${ws.sessionId.slice(0, 8)})`);
      return;
    }

    const session = this.#sessionManager.getSession(ws.sessionId);
    if (this.#sessionManager.isBanned(validation.room, session.publicKey)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are banned from this room')));
      return;
    }

    // Complete whichever action requested the challenge.
    if (challenge.mode === 'join') {
      const result = this.#sessionManager.joinAdditional(ws.sessionId, validation.room);
      if (!result) {
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
        return;
      }
      this.#finishRoomJoin(ws, session, validation.room);
      return;
    }

    const result = this.#sessionManager.switchRoom(ws.sessionId, validation.room);
    if (!result) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
      return;
    }

    this.#finishRoomSwitch(ws, session, result);
  }

  // Shared tail of a successful room switch: notify every old room and send
  // the ROOM_CHANGED (with the private flag) to the mover.
  #finishRoomSwitch(ws, session, result) {
    // Notify each old room that the peer left it
    for (const oldRoom of result.oldRooms || [result.oldRoom]) {
      if (!oldRoom) {
        continue;
      }
      this.#sessionManager.broadcastToRoom(
        oldRoom,
        createPeerLeft(ws.sessionId, session.nickname, oldRoom),
        ws.sessionId,
      );
    }

    // Notify new room that peer joined
    this.#sessionManager.broadcastToRoom(
      result.newRoom,
      createPeerJoined(
        {
          sessionId: ws.sessionId,
          nickname: session.nickname,
          publicKey: session.publicKey,
          ...(session.pqPublicKey ? { pqPublicKey: session.pqPublicKey } : {}),
        },
        result.newRoom,
      ),
      ws.sessionId,
    );

    // Send new room info to the client
    const newPeers = this.#sessionManager.getRoomPeers(result.newRoom, ws.sessionId);
    const roomChanged = createRoomChanged(
      result.newRoom,
      newPeers,
      this.#sessionManager.isRoomPrivate(result.newRoom),
    );
    const newOwnerSid = this.#sessionManager.getRoomOwner(result.newRoom);
    if (newOwnerSid) {
      const ownerSess = this.#sessionManager.getSession(newOwnerSid);
      if (ownerSess) {
        roomChanged.roomOwner = ownerSess.nickname;
      }
    }
    ws.send(JSON.stringify(roomChanged));

    log.info(`${session.nickname} switched to room ${result.newRoom}`);
  }

  #handleListRooms(ws) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const rooms = this.#sessionManager.listRooms();
    ws.send(JSON.stringify(createRoomList(rooms)));
  }

  // Which room a moderation command targets: the explicit `room` field (must
  // be one the moderator is in), else the session's only room. Owners in
  // several rooms must say which one.
  #resolveModerationRoom(ws, explicitRoom, cmdName) {
    if (explicitRoom) {
      if (!this.#sessionManager.isInRoom(ws.sessionId, explicitRoom)) {
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are not in that room')));
        return null;
      }
      return explicitRoom;
    }
    const only = this.#sessionManager.getSessionRoom(ws.sessionId);
    if (!only) {
      ws.send(
        JSON.stringify(
          createError(ERR.INVALID_MESSAGE, `You are in several rooms — specify one for ${cmdName}`),
        ),
      );
    }
    return only;
  }

  #handleKickPeer(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateKickPeer(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const room = this.#resolveModerationRoom(ws, validation.room, '/kick');
    if (!room) {
      return;
    }
    if (!this.#sessionManager.isRoomOwner(room, ws.sessionId)) {
      ws.send(
        JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Only the room owner can use /kick')),
      );
      return;
    }

    const targetSessionId = this.#sessionManager.findSessionByNickname(validation.targetNickname);
    if (!targetSessionId) {
      ws.send(
        JSON.stringify(createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" not found`)),
      );
      return;
    }

    if (!this.#sessionManager.isInRoom(targetSessionId, room)) {
      ws.send(
        JSON.stringify(
          createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" is not in this room`),
        ),
      );
      return;
    }

    // Move target to general
    const result = this.#sessionManager.switchRoom(targetSessionId, 'general');
    if (result) {
      const targetSession = this.#sessionManager.getSession(targetSessionId);

      // Notify old room
      this.#sessionManager.broadcastToRoom(
        room,
        createPeerKicked(validation.targetNickname, validation.reason),
      );

      // Notify target with room change + kick reason
      const newPeers = this.#sessionManager.getRoomPeers('general', targetSessionId);
      targetSession.ws.send(JSON.stringify(createRoomChanged('general', newPeers)));
      targetSession.ws.send(
        JSON.stringify(createPeerKicked(validation.targetNickname, validation.reason)),
      );

      log.info(
        `${validation.targetNickname} was kicked from room ${room} by ${this.#sessionManager.getSession(ws.sessionId).nickname}`,
      );
    }
  }

  #handleMutePeer(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateMutePeer(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const room = this.#resolveModerationRoom(ws, validation.room, '/mute');
    if (!room) {
      return;
    }
    if (!this.#sessionManager.isRoomOwner(room, ws.sessionId)) {
      ws.send(
        JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Only the room owner can use /mute')),
      );
      return;
    }

    const targetSessionId = this.#sessionManager.findSessionByNickname(validation.targetNickname);
    if (!targetSessionId) {
      ws.send(
        JSON.stringify(createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" not found`)),
      );
      return;
    }

    if (!this.#sessionManager.isInRoom(targetSessionId, room)) {
      ws.send(
        JSON.stringify(
          createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" is not in this room`),
        ),
      );
      return;
    }

    this.#sessionManager.mutePeer(targetSessionId, validation.durationMs);
    this.#sessionManager.broadcastToRoom(
      room,
      createPeerMuted(validation.targetNickname, validation.durationMs),
    );

    log.info(
      `${validation.targetNickname} was muted for ${validation.durationMs}ms in room ${room}`,
    );
  }

  #handleBanPeer(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'JOIN first')));
      return;
    }

    const validation = validateBanPeer(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    const room = this.#resolveModerationRoom(ws, validation.room, '/ban');
    if (!room) {
      return;
    }
    if (!this.#sessionManager.isRoomOwner(room, ws.sessionId)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Only the room owner can use /ban')));
      return;
    }

    const targetSessionId = this.#sessionManager.findSessionByNickname(validation.targetNickname);
    if (!targetSessionId) {
      ws.send(
        JSON.stringify(createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" not found`)),
      );
      return;
    }

    if (!this.#sessionManager.isInRoom(targetSessionId, room)) {
      ws.send(
        JSON.stringify(
          createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" is not in this room`),
        ),
      );
      return;
    }

    // Ban the key, not the name: /nick would otherwise undo this in one word.
    const targetSession = this.#sessionManager.getSession(targetSessionId);
    this.#sessionManager.banPeer(room, targetSession?.publicKey);

    const result = this.#sessionManager.switchRoom(targetSessionId, 'general');
    if (result) {
      this.#sessionManager.broadcastToRoom(
        room,
        createPeerKicked(validation.targetNickname, validation.reason || 'banned'),
      );

      const newPeers = this.#sessionManager.getRoomPeers('general', targetSessionId);
      targetSession.ws.send(JSON.stringify(createRoomChanged('general', newPeers)));
      targetSession.ws.send(
        JSON.stringify(createPeerKicked(validation.targetNickname, validation.reason || 'banned')),
      );

      log.info(
        `${validation.targetNickname} was banned from room ${room} by ${this.#sessionManager.getSession(ws.sessionId).nickname}`,
      );
    }
  }

  #handleDisconnect(ws) {
    if (!ws.sessionId) {
      return;
    }

    const rooms = this.#sessionManager.getSessionRooms(ws.sessionId);
    const session = this.#sessionManager.removeSession(ws.sessionId);
    this.#messageRouter.cleanupSession(ws.sessionId);

    if (session) {
      // One peer_left per former room, tagged, so multi-room clients drop the
      // peer from exactly the right buffers.
      for (const room of rooms) {
        this.#sessionManager.broadcastToRoom(
          room,
          createPeerLeft(ws.sessionId, session.nickname, room),
          ws.sessionId,
        );
      }
      log.info(`${session.nickname} left | Online: ${this.#sessionManager.size}`);
    }
  }

  #startHeartbeat() {
    this.#heartbeatInterval = setInterval(() => {
      for (const ws of this.#wss.clients) {
        if (!ws.isAlive) {
          log.warn('Client did not respond to heartbeat, disconnecting');
          ws.terminate();
          continue;
        }
        ws.isAlive = false;
        ws.ping();
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  close() {
    clearInterval(this.#heartbeatInterval);

    for (const ws of this.#wss.clients) {
      ws.close(1001, 'Server shutting down');
    }

    return new Promise((resolve) => {
      this.#wss.close(() => {
        if (this.#httpsServer) {
          this.#httpsServer.close(resolve);
        } else {
          resolve();
        }
      });
    });
  }
}
