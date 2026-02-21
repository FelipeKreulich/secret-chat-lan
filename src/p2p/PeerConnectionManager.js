import WebSocket from 'ws';
import { EventEmitter } from 'node:events';
import { PROTOCOL_VERSION } from '../shared/constants.js';

const HANDSHAKE_TIMEOUT_MS = 10_000;
const RECONNECT_BASE_MS = 2_000;
const RECONNECT_MAX_MS = 30_000;

export class PeerConnectionManager extends EventEmitter {
  #myNickname;
  #getPublicKeyB64;
  #peers; // Map<nickname, { ws, host, port, isOutbound }>
  #reconnectTimers; // Map<nickname, { timer, delay, host, port }>
  #pendingOutbound; // Set<nickname>

  constructor(nickname, getPublicKeyB64) {
    super();
    this.#myNickname = nickname;
    this.#getPublicKeyB64 = getPublicKeyB64;
    this.#peers = new Map();
    this.#reconnectTimers = new Map();
    this.#pendingOutbound = new Set();
  }

  /**
   * Deduplication rule: lexicographically smaller nickname initiates.
   */
  shouldInitiate(peerNickname) {
    return this.#myNickname.toLowerCase() < peerNickname.toLowerCase();
  }

  /**
   * Connect to a discovered peer (outbound).
   */
  connectTo(peerNickname, host, port) {
    if (this.#peers.has(peerNickname) || this.#pendingOutbound.has(peerNickname)) {
      return;
    }

    if (!this.shouldInitiate(peerNickname)) {
      return; // Wait for inbound from the other side
    }

    this.#pendingOutbound.add(peerNickname);
    this.#clearReconnect(peerNickname);

    const ws = new WebSocket(`ws://${host}:${port}`);

    const handshakeTimer = setTimeout(() => {
      ws.close();
      this.#pendingOutbound.delete(peerNickname);
    }, HANDSHAKE_TIMEOUT_MS);

    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'p2p_handshake',
        nickname: this.#myNickname,
        publicKey: this.#getPublicKeyB64(),
        version: PROTOCOL_VERSION,
        timestamp: Date.now(),
      }));
    });

    let handshakeComplete = false;

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString('utf-8'));

        if (!handshakeComplete && msg.type === 'p2p_handshake') {
          clearTimeout(handshakeTimer);
          handshakeComplete = true;
          this.#pendingOutbound.delete(peerNickname);
          this.#peers.set(peerNickname, { ws, host, port, isOutbound: true });
          this.emit('peer-connected', {
            nickname: msg.nickname,
            publicKey: msg.publicKey,
          });
          return;
        }

        if (handshakeComplete) {
          this.emit('message', peerNickname, msg);
        }
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on('close', () => {
      clearTimeout(handshakeTimer);
      this.#pendingOutbound.delete(peerNickname);

      if (handshakeComplete) {
        this.#peers.delete(peerNickname);
        this.emit('peer-disconnected', peerNickname);
        this.#scheduleReconnect(peerNickname, host, port);
      }
    });

    ws.on('error', () => {
      // Error is followed by 'close'
    });
  }

  /**
   * Accept an inbound connection (from PeerServer).
   */
  acceptConnection(ws) {
    // Send handshake immediately
    ws.send(JSON.stringify({
      type: 'p2p_handshake',
      nickname: this.#myNickname,
      publicKey: this.#getPublicKeyB64(),
      version: PROTOCOL_VERSION,
      timestamp: Date.now(),
    }));

    const handshakeTimer = setTimeout(() => {
      ws.close();
    }, HANDSHAKE_TIMEOUT_MS);

    let handshakeComplete = false;
    let peerNickname = null;

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString('utf-8'));

        if (!handshakeComplete && msg.type === 'p2p_handshake') {
          clearTimeout(handshakeTimer);
          handshakeComplete = true;
          peerNickname = msg.nickname;

          // Duplicate check — close newer connection
          if (this.#peers.has(peerNickname)) {
            ws.close();
            return;
          }

          this.#peers.set(peerNickname, { ws, host: null, port: null, isOutbound: false });
          this.emit('peer-connected', {
            nickname: msg.nickname,
            publicKey: msg.publicKey,
          });
          return;
        }

        if (handshakeComplete && peerNickname) {
          this.emit('message', peerNickname, msg);
        }
      } catch {
        // Ignore malformed messages
      }
    });

    ws.on('close', () => {
      clearTimeout(handshakeTimer);
      if (handshakeComplete && peerNickname) {
        this.#peers.delete(peerNickname);
        this.emit('peer-disconnected', peerNickname);
      }
    });

    ws.on('error', () => {
      // Error triggers close
    });
  }

  #scheduleReconnect(nickname, host, port) {
    const existing = this.#reconnectTimers.get(nickname);
    const delay = existing ? Math.min(existing.delay * 2, RECONNECT_MAX_MS) : RECONNECT_BASE_MS;

    const timer = setTimeout(() => {
      this.#reconnectTimers.delete(nickname);
      this.connectTo(nickname, host, port);
    }, delay);

    this.#reconnectTimers.set(nickname, { timer, delay, host, port });
  }

  #clearReconnect(nickname) {
    const entry = this.#reconnectTimers.get(nickname);
    if (entry) {
      clearTimeout(entry.timer);
      this.#reconnectTimers.delete(nickname);
    }
  }

  send(nickname, data) {
    const peer = this.#peers.get(nickname);
    if (peer && peer.ws.readyState === WebSocket.OPEN) {
      peer.ws.send(JSON.stringify(data));
      return true;
    }
    return false;
  }

  broadcast(data) {
    const json = JSON.stringify(data);
    for (const [, peer] of this.#peers) {
      if (peer.ws.readyState === WebSocket.OPEN) {
        peer.ws.send(json);
      }
    }
  }

  hasPeer(nickname) {
    return this.#peers.has(nickname);
  }

  get peerCount() {
    return this.#peers.size;
  }

  get peerNicknames() {
    return [...this.#peers.keys()];
  }

  destroy() {
    for (const [, entry] of this.#reconnectTimers) {
      clearTimeout(entry.timer);
    }
    this.#reconnectTimers.clear();
    this.#pendingOutbound.clear();

    for (const [, peer] of this.#peers) {
      peer.ws.close();
    }
    this.#peers.clear();
  }
}
