import WebSocket from 'ws';
import { EventEmitter } from 'node:events';
import { RECONNECT_BASE_MS, RECONNECT_MAX_MS } from '../shared/constants.js';

export class Connection extends EventEmitter {
  #url;
  #ws;
  #reconnectDelay;
  #shouldReconnect;
  #connected;

  constructor(url) {
    super();
    this.#url = url;
    this.#reconnectDelay = RECONNECT_BASE_MS;
    this.#shouldReconnect = true;
    this.#connected = false;
  }

  connect() {
    this.#shouldReconnect = true;
    this.#createSocket();
  }

  #createSocket() {
    const opts = this.#url.startsWith('wss://') ? { rejectUnauthorized: false } : {};
    this.#ws = new WebSocket(this.#url, opts);

    this.#ws.on('open', () => {
      this.#connected = true;
      this.#reconnectDelay = RECONNECT_BASE_MS;
      this.emit('connected');
    });

    this.#ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString('utf-8'));
        this.emit('message', msg);
      } catch {
        // Ignore malformed messages
      }
    });

    this.#ws.on('close', () => {
      const wasConnected = this.#connected;
      this.#connected = false;

      if (wasConnected) {
        this.emit('disconnected');
      }

      if (this.#shouldReconnect) {
        this.#scheduleReconnect();
      }
    });

    this.#ws.on('error', () => {
      // Error is followed by 'close', reconnect handled there
    });

    this.#ws.on('ping', () => {
      this.#ws.pong();
    });
  }

  #scheduleReconnect() {
    setTimeout(() => {
      if (this.#shouldReconnect) {
        this.emit('reconnecting', this.#reconnectDelay);
        this.#createSocket();
        this.#reconnectDelay = Math.min(this.#reconnectDelay * 2, RECONNECT_MAX_MS);
      }
    }, this.#reconnectDelay);
  }

  send(msg) {
    if (this.#connected && this.#ws.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify(msg));
      return true;
    }
    return false;
  }

  get connected() {
    return this.#connected;
  }

  close() {
    this.#shouldReconnect = false;
    if (this.#ws) {
      this.#ws.close();
    }
  }
}
