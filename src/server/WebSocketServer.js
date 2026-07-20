import { createServer as createHttpsServer } from 'node:https';
import { WebSocketServer as WSServer } from 'ws';
import { createLogger } from '../shared/logger.js';
import {
  HEARTBEAT_INTERVAL_MS,
  MAX_PAYLOAD_SIZE,
  MAX_CONNECTIONS_TOTAL,
  MAX_CONNECTIONS_PER_IP,
  JOIN_TIMEOUT_MS,
  MESSAGE_RATE_LIMIT_PER_SECOND,
} from '../shared/constants.js';
import {
  MSG,
  createJoinAck,
  createPeerJoined,
  createPeerLeft,
  createPeerKeyUpdated,
  createRoomChanged,
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
  validateKickPeer,
  validateMutePeer,
  validateBanPeer,
} from '../protocol/validators.js';

const log = createLogger('ws-server');

export class SecureWSServer {
  #wss;
  #httpsServer;
  #sessionManager;
  #messageRouter;
  #offlineQueue;
  #heartbeatInterval;
  #connectionsByIp;

  constructor(sessionManager, messageRouter, offlineQueue, port, tlsOptions) {
    this.#sessionManager = sessionManager;
    this.#messageRouter = messageRouter;
    this.#offlineQueue = offlineQueue;
    this.#connectionsByIp = new Map();

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
    return req?.socket?.remoteAddress || 'unknown';
  }

  #handleConnection(ws, req) {
    const ip = this.#clientIp(req);

    // Global connection cap (the new socket is already counted in clients).
    if (this.#wss.clients.size > MAX_CONNECTIONS_TOTAL) {
      ws.close(1013, 'Server full');
      return;
    }
    // Per-IP connection cap.
    const ipCount = this.#connectionsByIp.get(ip) || 0;
    if (ipCount >= MAX_CONNECTIONS_PER_IP) {
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
    return ws.msgCount <= MESSAGE_RATE_LIMIT_PER_SECOND;
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
    const sessionId = this.#sessionManager.addSession(ws, validation.nickname, msg.publicKey, room);
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

    // Ensure the 'from' field matches the sender's actual session
    msg.from = ws.sessionId;

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

    // Broadcast new key to room peers
    const room = this.#sessionManager.getSessionRoom(ws.sessionId);
    if (room) {
      this.#sessionManager.broadcastToRoom(
        room,
        createPeerKeyUpdated(ws.sessionId, msg.publicKey),
        ws.sessionId,
      );
    } else {
      this.#sessionManager.broadcast(
        createPeerKeyUpdated(ws.sessionId, msg.publicKey),
        ws.sessionId,
      );
    }

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
    if (this.#sessionManager.isBanned(validation.room, session.nickname)) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are banned from this room')));
      return;
    }
    const result = this.#sessionManager.switchRoom(ws.sessionId, validation.room);
    if (!result) {
      // Already in this room
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'You are already in this room')));
      return;
    }

    // Notify old room that peer left
    this.#sessionManager.broadcastToRoom(
      result.oldRoom,
      createPeerLeft(ws.sessionId, session.nickname),
      ws.sessionId,
    );

    // Notify new room that peer joined
    this.#sessionManager.broadcastToRoom(
      result.newRoom,
      createPeerJoined({
        sessionId: ws.sessionId,
        nickname: session.nickname,
        publicKey: session.publicKey,
      }),
      ws.sessionId,
    );

    // Send new room info to the client
    const newPeers = this.#sessionManager.getRoomPeers(result.newRoom, ws.sessionId);
    const roomChanged = createRoomChanged(result.newRoom, newPeers);
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

    const room = this.#sessionManager.getSessionRoom(ws.sessionId);
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

    const targetRoom = this.#sessionManager.getSessionRoom(targetSessionId);
    if (targetRoom !== room) {
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

    const room = this.#sessionManager.getSessionRoom(ws.sessionId);
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

    const targetRoom = this.#sessionManager.getSessionRoom(targetSessionId);
    if (targetRoom !== room) {
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

    const room = this.#sessionManager.getSessionRoom(ws.sessionId);
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

    const targetRoom = this.#sessionManager.getSessionRoom(targetSessionId);
    if (targetRoom !== room) {
      ws.send(
        JSON.stringify(
          createError(ERR.PEER_NOT_FOUND, `"${validation.targetNickname}" is not in this room`),
        ),
      );
      return;
    }

    // Ban + kick to general
    this.#sessionManager.banPeer(room, validation.targetNickname);

    const result = this.#sessionManager.switchRoom(targetSessionId, 'general');
    if (result) {
      const targetSession = this.#sessionManager.getSession(targetSessionId);

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

    const room = this.#sessionManager.getSessionRoom(ws.sessionId);
    const session = this.#sessionManager.removeSession(ws.sessionId);
    this.#messageRouter.cleanupSession(ws.sessionId);

    if (session) {
      // Broadcast to former room members only
      if (room) {
        this.#sessionManager.broadcastToRoom(
          room,
          createPeerLeft(ws.sessionId, session.nickname),
          ws.sessionId,
        );
      } else {
        this.#sessionManager.broadcast(
          createPeerLeft(ws.sessionId, session.nickname),
          ws.sessionId,
        );
      }
      log.info(`${session.nickname} saiu | Online: ${this.#sessionManager.size}`);
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
