import WebSocket from 'ws';
import { EventEmitter } from 'node:events';
import { RECONNECT_BASE_MS, RECONNECT_MAX_MS } from '../shared/constants.js';
import { CertPinStore, PinResult } from '../crypto/CertPinStore.js';

export class Connection extends EventEmitter {
  #url;
  #ws;
  #reconnectDelay;
  #shouldReconnect;
  #connected;
  #pinStore;
  #host;

  constructor(url) {
    super();
    this.#url = url;
    this.#reconnectDelay = RECONNECT_BASE_MS;
    this.#shouldReconnect = true;
    this.#connected = false;
    this.#pinStore = new CertPinStore();
    try {
      this.#host = new URL(url).host;
    } catch {
      this.#host = url;
    }
  }

  // Trust-on-first-use pin of the server TLS certificate. Emits 'cert-pinned'
  // on first sight and 'cert-mismatch' if it later changes (possible MITM).
  #checkCertPin() {
    if (!this.#url.startsWith('wss://')) {
      return;
    }
    const socket = this.#ws?._socket;
    const cert = socket?.getPeerCertificate?.();
    const fingerprint = cert?.fingerprint256 || null;
    const result = this.#pinStore.check(this.#host, fingerprint);
    if (result === PinResult.PINNED) {
      this.emit('cert-pinned', { host: this.#host, fingerprint });
    } else if (result === PinResult.MISMATCH) {
      this.emit('cert-mismatch', {
        host: this.#host,
        expected: this.#pinStore.getPinned(this.#host),
        got: fingerprint,
      });
    }
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
      this.#checkCertPin();
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

  get url() {
    return this.#url;
  }

  close() {
    this.#shouldReconnect = false;
    if (this.#ws) {
      this.#ws.close();
    }
  }
}
