import { WebSocketServer } from 'ws';
import { EventEmitter } from 'node:events';

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
      this.#wss = new WebSocketServer({ port: 0 });

      this.#wss.on('listening', () => {
        this.#port = this.#wss.address().port;
        resolve(this.#port);
      });

      this.#wss.on('connection', (ws) => {
        this.emit('connection', ws);
      });

      this.#wss.on('error', reject);
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
