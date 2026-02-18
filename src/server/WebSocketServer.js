import { WebSocketServer as WSServer } from 'ws';
import { createLogger } from '../shared/logger.js';
import {
  HEARTBEAT_INTERVAL_MS,
  MAX_PAYLOAD_SIZE,
} from '../shared/constants.js';
import {
  MSG,
  createJoinAck,
  createPeerJoined,
  createPeerLeft,
  createError,
  ERR,
} from '../protocol/messages.js';
import { parseMessage, validateJoin, validateEncryptedMessage } from '../protocol/validators.js';

const log = createLogger('ws-server');

export class SecureWSServer {
  #wss;
  #sessionManager;
  #messageRouter;
  #heartbeatInterval;

  constructor(sessionManager, messageRouter, port) {
    this.#sessionManager = sessionManager;
    this.#messageRouter = messageRouter;

    this.#wss = new WSServer({
      port,
      maxPayload: MAX_PAYLOAD_SIZE,
      clientTracking: true,
    });

    this.#wss.on('connection', (ws) => this.#handleConnection(ws));
    this.#wss.on('error', (err) => log.error(`Server error: ${err.message}`));

    this.#startHeartbeat();
  }

  #handleConnection(ws) {
    ws.isAlive = true;
    ws.sessionId = null;
    ws.hasJoined = false;

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('message', (data) => {
      this.#handleMessage(ws, data);
    });

    ws.on('close', () => {
      this.#handleDisconnect(ws);
    });

    ws.on('error', (err) => {
      log.error(`WS error: ${err.message}`);
    });

    log.debug('Nova conexao WebSocket');
  }

  #handleMessage(ws, data) {
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

      case MSG.PING:
        ws.send(JSON.stringify({ type: MSG.PONG, version: msg.version, timestamp: Date.now() }));
        break;

      default:
        ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, `Unknown type: ${msg.type}`)));
    }
  }

  #handleJoin(ws, msg) {
    if (ws.hasJoined) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Ja esta no chat')));
      return;
    }

    const validation = validateJoin(msg);
    if (!validation.valid) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, validation.error)));
      return;
    }

    if (this.#sessionManager.isNicknameTaken(validation.nickname)) {
      ws.send(JSON.stringify(createError(ERR.NICKNAME_TAKEN, `Nickname "${validation.nickname}" ja esta em uso`)));
      return;
    }

    const sessionId = this.#sessionManager.addSession(ws, validation.nickname, msg.publicKey);
    ws.sessionId = sessionId;
    ws.hasJoined = true;

    // Send ACK with peer list
    const peers = this.#sessionManager.getPeers(sessionId);
    ws.send(JSON.stringify(createJoinAck(sessionId, peers)));

    // Notify others
    this.#sessionManager.broadcast(
      createPeerJoined({
        sessionId,
        nickname: validation.nickname,
        publicKey: msg.publicKey,
      }),
      sessionId,
    );

    log.info(`${validation.nickname} entrou | Online: ${this.#sessionManager.size}`);
  }

  #handleEncryptedMessage(ws, msg) {
    if (!ws.hasJoined || !ws.sessionId) {
      ws.send(JSON.stringify(createError(ERR.INVALID_MESSAGE, 'Faca JOIN primeiro')));
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

  #handleDisconnect(ws) {
    if (!ws.sessionId) {
      return;
    }

    const session = this.#sessionManager.removeSession(ws.sessionId);
    this.#messageRouter.cleanupSession(ws.sessionId);

    if (session) {
      this.#sessionManager.broadcast(
        createPeerLeft(ws.sessionId, session.nickname),
        ws.sessionId,
      );
      log.info(`${session.nickname} saiu | Online: ${this.#sessionManager.size}`);
    }
  }

  #startHeartbeat() {
    this.#heartbeatInterval = setInterval(() => {
      for (const ws of this.#wss.clients) {
        if (!ws.isAlive) {
          log.warn('Cliente nao respondeu ao heartbeat, desconectando');
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
      ws.close(1001, 'Servidor encerrando');
    }

    return new Promise((resolve) => {
      this.#wss.close(resolve);
    });
  }
}
