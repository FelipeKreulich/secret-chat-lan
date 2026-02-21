import { Bonjour } from 'bonjour-service';
import { EventEmitter } from 'node:events';
import { PROTOCOL_VERSION } from '../shared/constants.js';

const SERVICE_TYPE = 'ciphermesh';

export class Discovery extends EventEmitter {
  #bonjour;
  #service;
  #browser;
  #myNickname;

  constructor() {
    super();
    this.#bonjour = new Bonjour();
    this.#service = null;
    this.#browser = null;
    this.#myNickname = null;
  }

  /**
   * Publish our service and start browsing for peers.
   */
  start(nickname, port, publicKeyB64) {
    this.#myNickname = nickname;

    // Publish mDNS service
    this.#service = this.#bonjour.publish({
      name: `ciphermesh-${nickname}`,
      type: SERVICE_TYPE,
      port,
      txt: {
        nickname,
        publicKey: publicKeyB64,
        version: String(PROTOCOL_VERSION),
      },
    });

    // Browse for other CipherMesh peers
    this.#browser = this.#bonjour.find({ type: SERVICE_TYPE });

    this.#browser.on('up', (service) => {
      const peerNick = service.txt?.nickname;
      if (!peerNick || peerNick === this.#myNickname) return;

      // Prefer referer address (actual IP), fallback to host
      const host = service.referer?.address || service.host;

      this.emit('peer-discovered', {
        nickname: peerNick,
        host,
        port: service.port,
        publicKey: service.txt.publicKey,
      });
    });

    this.#browser.on('down', (service) => {
      const peerNick = service.txt?.nickname;
      if (!peerNick || peerNick === this.#myNickname) return;

      this.emit('peer-lost', { nickname: peerNick });
    });
  }

  stop() {
    if (this.#browser) {
      this.#browser.stop();
      this.#browser = null;
    }
    if (this.#service) {
      this.#service.stop();
      this.#service = null;
    }
    this.#bonjour.destroy();
  }
}
