import { WebSocketServer } from 'ws';
import { EventEmitter } from 'node:events';
import { MAX_PAYLOAD_SIZE } from '../shared/constants.js';
import { createLogger } from '../shared/logger.js';

const log = createLogger('peer-server');

export class PeerServer extends EventEmitter {
  #wss;
  #port;

  constructor() {
    super();
    this.#wss = null;
    this.#port = 0;
  }

  /**
   * Start listening on a random available port.
   * @returns {Promise<number>} The assigned port number.
   */
  start() {
    return new Promise((resolve, reject) => {
      this.#wss = new WebSocketServer({ port: 0, maxPayload: MAX_PAYLOAD_SIZE });
      let settled = false;

      this.#wss.on('listening', () => {
        settled = true;
        this.#port = this.#wss.address().port;
        resolve(this.#port);
      });

      this.#wss.on('connection', (ws) => {
        this.emit('connection', ws);
      });

      // Persistent error handler: reject only before 'listening'; afterwards a
      // late server error would otherwise be unhandled and crash the process.
      this.#wss.on('error', (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        } else {
          log.error(`Erro no PeerServer: ${err.message}`);
          // Only emit if someone is listening — a listener-less 'error' event
          // would itself throw and crash the process.
          if (this.listenerCount('error') > 0) {
            this.emit('error', err);
          }
        }
      });
    });
  }

  get port() {
    return this.#port;
  }

  stop() {
    if (this.#wss) {
      for (const client of this.#wss.clients) {
        client.close();
      }
      this.#wss.close();
      this.#wss = null;
    }
  }
}
