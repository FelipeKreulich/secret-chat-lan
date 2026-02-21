import sodium from 'sodium-native';
import { KEY_ROTATION_INTERVAL_MS } from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from '../client/FileTransfer.js';

const TYPING_SEND_INTERVAL = 2000;
const TYPING_EXPIRE_TIMEOUT = 3000;

export class P2PChatController {
  #nickname;
  #connManager;
  #discovery;
  #peerServer;
  #ui;
  #keyManager;
  #handshake;
  #nonceManager;
  #peers; // Map<nickname, { publicKey }>
  #lastTypingSent;
  #peerTypingTimers;
  #fileTransfer;
  #keyRotationTimer;
  #trustStore;
  #passphrase;

  constructor(nickname, peerServer, connManager, discovery, ui, keyManager, restoredState = null) {
    this.#nickname = nickname;
    this.#connManager = connManager;
    this.#discovery = discovery;
    this.#peerServer = peerServer;
    this.#ui = ui;
    this.#passphrase = restoredState?.passphrase || null;
    this.#keyManager = keyManager;

    this.#handshake = new Handshake(this.#keyManager);
    this.#handshake.setMySessionId(nickname); // Use nickname as session ID in P2P

    if (restoredState?.handshake) {
      this.#handshake.restoreState(restoredState.handshake);
    }

    this.#nonceManager = new NonceManager();
    this.#peers = new Map();
    this.#lastTypingSent = 0;
    this.#peerTypingTimers = new Map();
    this.#fileTransfer = new FileTransfer();
    this.#keyRotationTimer = null;
    this.#trustStore = new TrustStore();

    this.#setupHandlers();
    this.#startKeyRotation();
  }

  get fingerprint() {
    return this.#keyManager.fingerprint;
  }

  get passphrase() {
    return this.#passphrase;
  }

  // ── Event handlers ─────────────────────────────────────────────
  #setupHandlers() {
    // PeerConnectionManager events
    this.#connManager.on('peer-connected', ({ nickname, publicKey }) => {
      this.#onPeerConnected(nickname, publicKey);
    });

    this.#connManager.on('peer-disconnected', (nickname) => {
      this.#onPeerDisconnected(nickname);
    });

    this.#connManager.on('message', (nickname, msg) => {
      this.#onPeerMessage(nickname, msg);
    });

    // PeerServer — delegate inbound connections to connection manager
    this.#peerServer.on('connection', (ws) => {
      this.#connManager.acceptConnection(ws);
    });

    // Discovery events
    this.#discovery.on('peer-discovered', (peer) => {
      this.#connManager.connectTo(peer.nickname, peer.host, peer.port);
    });

    // UI events
    this.#ui.on('input', (text) => {
      this.#handleUserInput(text);
    });

    this.#ui.on('activity', () => {
      this.#handleTypingActivity();
    });

    this.#ui.on('quit', () => {
      this.destroy();
      process.exit(0);
    });
  }

  // ── Peer connected (handshake complete) ────────────────────────
  #onPeerConnected(nickname, publicKey) {
    this.#peers.set(nickname, { publicKey });
    this.#handshake.registerPeer(nickname, publicKey);
    this.#checkTrust(nickname, publicKey);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.addSystemMessage(`${nickname} conectado (P2P direto)`);
  }

  // ── Peer disconnected ──────────────────────────────────────────
  #onPeerDisconnected(nickname) {
    this.#hidePeerTyping(nickname);
    this.#nonceManager.removePeer(nickname);
    this.#peers.delete(nickname);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.addSystemMessage(`${nickname} desconectou`);
  }

  // ── Handle message from peer ───────────────────────────────────
  #onPeerMessage(fromNickname, msg) {
    if (msg.type !== 'p2p_message') return;

    const peer = this.#peers.get(fromNickname);
    if (!peer) return;

    const senderPublicKey = this.#handshake.getPeerPublicKey(fromNickname);
    if (!senderPublicKey) return;

    const ciphertext = Buffer.from(msg.payload.ciphertext, 'base64');
    const nonce = Buffer.from(msg.payload.nonce, 'base64');

    let plaintext = null;

    // Ratcheted path (has ephemeralPublicKey)
    if (msg.payload.ephemeralPublicKey) {
      const ratchet = this.#handshake.getRatchet(fromNickname);
      if (ratchet) {
        const ephPub = Buffer.from(msg.payload.ephemeralPublicKey, 'base64');
        plaintext = ratchet.decrypt(
          ciphertext, nonce, ephPub,
          msg.payload.counter, msg.payload.previousCounter,
        );
      }

      // Fallback to static decrypt if ratchet failed
      if (!plaintext) {
        if (!this.#nonceManager.validate(fromNickname, nonce)) {
          this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${fromNickname}`);
          return;
        }
        plaintext = MessageCrypto.decryptWithFallback(
          ciphertext, nonce, senderPublicKey,
          this.#handshake.secretKey,
          this.#handshake.getPreviousPeerPublicKey(fromNickname),
          this.#handshake.previousSecretKey,
        );
      }
    } else {
      // Static path (no ephemeralPublicKey)
      if (!this.#nonceManager.validate(fromNickname, nonce)) {
        this.#ui.addErrorMessage(`Nonce invalido de ${fromNickname}`);
        return;
      }
      plaintext = MessageCrypto.decryptWithFallback(
        ciphertext, nonce, senderPublicKey,
        this.#handshake.secretKey,
        this.#handshake.getPreviousPeerPublicKey(fromNickname),
        this.#handshake.previousSecretKey,
      );
    }

    if (!plaintext) {
      this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${fromNickname} (MAC invalido)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));
      this.#handleDecryptedAction(fromNickname, data);
    } catch {
      this.#ui.addErrorMessage(`Payload invalido de ${fromNickname}`);
    } finally {
      if (plaintext && Buffer.isBuffer(plaintext)) {
        sodium.sodium_memzero(plaintext);
      }
    }
  }

  #handleDecryptedAction(fromNickname, data) {
    const peer = this.#peers.get(fromNickname);

    if (data.action === 'clear') {
      this.#ui.clearChat();
      return;
    }

    if (data.action === 'typing') {
      this.#showPeerTyping(fromNickname);
      return;
    }

    if (data.action === 'key_rotation') {
      this.#handshake.updatePeerKey(fromNickname, data.newPublicKey);
      if (peer) peer.publicKey = data.newPublicKey;
      this.#trustStore.autoUpdatePeer(fromNickname, data.newPublicKey);
      this.#ui.addSystemMessage(`${fromNickname} rotacionou chaves`);
      return;
    }

    if (data.action === 'file_offer') {
      const info = this.#fileTransfer.handleFileOffer(fromNickname, data, fromNickname);
      this.#ui.addSystemMessage(info);
      this.#ui.playNotification();
      return;
    }

    if (data.action === 'file_chunk') {
      const progress = this.#fileTransfer.handleFileChunk(fromNickname, data);
      if (progress && progress.percent % 10 === 0) {
        this.#ui.updateProgress(progress.text, progress.percent);
      }
      return;
    }

    if (data.action === 'file_complete') {
      this.#fileTransfer.handleFileComplete(fromNickname, data).then((result) => {
        if (result.success) {
          this.#ui.addSystemMessage(result.message);
        } else {
          this.#ui.addErrorMessage(result.message);
        }
      });
      return;
    }

    // Text message
    this.#hidePeerTyping(fromNickname);
    this.#ui.addMessage(fromNickname, data.text);
    this.#ui.playNotification();
  }

  // ── TOFU: Trust On First Use ───────────────────────────────────
  #checkTrust(nickname, publicKey) {
    const result = this.#trustStore.checkPeer(nickname, publicKey);

    switch (result) {
      case TrustResult.NEW_PEER:
        this.#trustStore.recordPeer(nickname, publicKey);
        break;

      case TrustResult.TRUSTED:
        break;

      case TrustResult.MISMATCH:
        this.#ui.addErrorMessage(
          `AVISO: A chave de ${nickname} mudou! Use /trust ${nickname} para aceitar ou /verify ${nickname} para verificar.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#ui.addErrorMessage(
          `ALERTA: A chave VERIFICADA de ${nickname} mudou! Use /verify ${nickname} para re-verificar.`,
        );
        break;
    }
  }

  // ── Typing indicator ──────────────────────────────────────────
  #handleTypingActivity() {
    const now = Date.now();
    if (now - this.#lastTypingSent < TYPING_SEND_INTERVAL) return;
    if (this.#peers.size === 0) return;

    this.#lastTypingSent = now;
    this.#sendCommandToAll('typing');
  }

  #showPeerTyping(nickname) {
    const existing = this.#peerTypingTimers.get(nickname);
    if (existing) clearTimeout(existing);

    this.#ui.showTyping(nickname);

    const timer = setTimeout(() => {
      this.#ui.hideTyping(nickname);
      this.#peerTypingTimers.delete(nickname);
    }, TYPING_EXPIRE_TIMEOUT);

    this.#peerTypingTimers.set(nickname, timer);
  }

  #hidePeerTyping(nickname) {
    const timer = this.#peerTypingTimers.get(nickname);
    if (timer) {
      clearTimeout(timer);
      this.#peerTypingTimers.delete(nickname);
    }
    this.#ui.hideTyping(nickname);
  }

  // ── User input ─────────────────────────────────────────────────
  #handleUserInput(text) {
    if (text.startsWith('/')) {
      this.#handleCommand(text);
      return;
    }

    this.#sendMessageToAll(text);
  }

  #handleCommand(text) {
    const parts = text.split(/\s+/);
    const cmd = parts[0].toLowerCase();

    switch (cmd) {
      case '/help':
        this.#ui.addInfoMessage('Comandos disponiveis (modo P2P):');
        this.#ui.addInfoMessage('  /help                - Mostra esta ajuda');
        this.#ui.addInfoMessage('  /users               - Lista peers conectados');
        this.#ui.addInfoMessage('  /fingerprint         - Mostra seu fingerprint');
        this.#ui.addInfoMessage('  /fingerprint <nick>  - Fingerprint de outro peer');
        this.#ui.addInfoMessage('  /verify <nick>       - Codigo SAS para verificacao');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirma verificacao');
        this.#ui.addInfoMessage('  /trust <nick>        - Aceita nova chave');
        this.#ui.addInfoMessage('  /trustlist           - Status de confianca');
        this.#ui.addInfoMessage('  /clear               - Limpa o chat');
        this.#ui.addInfoMessage('  /file <caminho>      - Envia arquivo (max 50MB)');
        this.#ui.addInfoMessage('  /sound [on|off]      - Notificacoes sonoras');
        this.#ui.addInfoMessage('  /quit                - Sai do chat');
        break;

      case '/users': {
        const names = [...this.#peers.keys()];
        this.#ui.addInfoMessage(
          `Online (${names.length + 1}): ${this.#nickname} (voce), ${names.join(', ') || 'ninguem mais'}`,
        );
        break;
      }

      case '/fingerprint': {
        const targetNick = parts[1];
        if (!targetNick) {
          this.#ui.addInfoMessage(`Seu fingerprint: ${this.#keyManager.fingerprint}`);
        } else {
          const found = this.#findPeer(targetNick);
          if (found) {
            const fp = KeyManager.computeFingerprint(Buffer.from(found.publicKey, 'base64'));
            this.#ui.addInfoMessage(`Fingerprint de ${found.nickname}: ${fp}`);
          } else {
            this.#ui.addErrorMessage(`Peer "${targetNick}" nao encontrado`);
          }
        }
        break;
      }

      case '/clear':
        this.#sendCommandToAll('clear');
        this.#ui.clearChat();
        break;

      case '/sound': {
        const arg = parts[1]?.toLowerCase();
        if (arg === 'off') {
          this.#ui.setSoundEnabled(false);
          this.#ui.addInfoMessage('Notificacoes sonoras desativadas');
        } else if (arg === 'on') {
          this.#ui.setSoundEnabled(true);
          this.#ui.addInfoMessage('Notificacoes sonoras ativadas');
        } else {
          const status = this.#ui.soundEnabled ? 'ativadas' : 'desativadas';
          this.#ui.addInfoMessage(`Som: ${status}. Use /sound on ou /sound off`);
        }
        break;
      }

      case '/verify': {
        const verifyNick = parts[1];
        if (!verifyNick) {
          this.#ui.addErrorMessage('Uso: /verify <nickname>');
          break;
        }
        const verifyPeer = this.#findPeer(verifyNick);
        if (!verifyPeer) {
          this.#ui.addErrorMessage(`Peer "${verifyNick}" nao encontrado`);
          break;
        }
        const sas = TrustStore.computeSAS(this.#keyManager.publicKeyB64, verifyPeer.publicKey);
        this.#ui.addInfoMessage(`Codigo SAS para ${verifyPeer.nickname}: ${sas}`);
        this.#ui.addInfoMessage(
          'Compare este codigo com o peer por voz ou outro canal. Se bater, use /verify-confirm ' +
            verifyPeer.nickname,
        );
        break;
      }

      case '/verify-confirm': {
        const confirmNick = parts[1];
        if (!confirmNick) {
          this.#ui.addErrorMessage('Uso: /verify-confirm <nickname>');
          break;
        }
        const confirmed = this.#trustStore.markVerified(confirmNick);
        if (confirmed) {
          this.#ui.addSystemMessage(`${confirmNick} marcado como verificado`);
        } else {
          this.#ui.addErrorMessage(`Peer "${confirmNick}" nao encontrado no trust store.`);
        }
        break;
      }

      case '/trust': {
        const trustNick = parts[1];
        if (!trustNick) {
          this.#ui.addErrorMessage('Uso: /trust <nickname>');
          break;
        }
        const trustPeer = this.#findPeer(trustNick);
        if (!trustPeer) {
          this.#ui.addErrorMessage(`Peer "${trustNick}" nao esta online`);
          break;
        }
        this.#trustStore.updatePeer(trustPeer.nickname, trustPeer.publicKey);
        this.#ui.addSystemMessage(`Chave de ${trustPeer.nickname} aceita (verificacao resetada)`);
        break;
      }

      case '/trustlist': {
        const peerNames = [...this.#peers.keys()];
        if (peerNames.length === 0) {
          this.#ui.addInfoMessage('Nenhum peer online');
          break;
        }
        this.#ui.addInfoMessage('Status de confianca:');
        for (const name of peerNames) {
          const record = this.#trustStore.getPeerRecord(name);
          let status;
          if (!record) status = 'desconhecido';
          else if (record.verified) status = 'verificado';
          else status = 'confiavel (TOFU)';
          this.#ui.addInfoMessage(`  ${name}: ${status}`);
        }
        break;
      }

      case '/file': {
        const filePath = parts.slice(1).join(' ');
        if (!filePath) {
          this.#ui.addErrorMessage('Uso: /file <caminho>');
          break;
        }
        if (this.#peers.size === 0) {
          this.#ui.addSystemMessage('Nenhum peer online para receber arquivos');
          break;
        }
        this.#sendFile(filePath);
        break;
      }

      case '/quit':
        this.destroy();
        process.exit(0);
        break;

      default:
        this.#ui.addErrorMessage(`Comando desconhecido: ${cmd}. Use /help`);
    }
  }

  #findPeer(nickname) {
    const direct = this.#peers.get(nickname);
    if (direct) return { ...direct, nickname };

    for (const [name, p] of this.#peers) {
      if (name.toLowerCase() === nickname.toLowerCase()) {
        return { ...p, nickname: name };
      }
    }
    return null;
  }

  // ── Key rotation ──────────────────────────────────────────────
  #startKeyRotation() {
    this.#keyRotationTimer = setInterval(() => {
      this.#rotateKeys();
    }, KEY_ROTATION_INTERVAL_MS);
  }

  #rotateKeys() {
    this.#keyManager.rotate();

    const payload = JSON.stringify({
      action: 'key_rotation',
      newPublicKey: this.#keyManager.publicKeyB64,
      sentAt: Date.now(),
    });
    this.#broadcastPayload(payload);

    this.#ui.addSystemMessage(
      `Chaves rotacionadas (novo fingerprint: ${this.#keyManager.fingerprint})`,
    );
  }

  // ── Send encrypted payload ─────────────────────────────────────
  #sendCommandToAll(action) {
    const payload = JSON.stringify({ action, sentAt: Date.now() });
    this.#broadcastPayload(payload);
  }

  #broadcastPayload(payload) {
    for (const [peerNickname] of this.#peers) {
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerNickname);
      if (!peerPublicKey) continue;

      // Try ratchet path (PFS) first
      const ratchet = this.#handshake.getRatchet(peerNickname);
      if (ratchet && ratchet.isInitialized) {
        try {
          const result = ratchet.encrypt(payload);
          this.#connManager.send(peerNickname, {
            type: 'p2p_message',
            payload: {
              ephemeralPublicKey: result.ephemeralPublicKey.toString('base64'),
              counter: result.counter,
              previousCounter: result.previousCounter,
              ciphertext: result.ciphertext.toString('base64'),
              nonce: result.nonce.toString('base64'),
            },
          });
          continue;
        } catch {
          // Fall through to static path
        }
      }

      // Static path fallback
      const nonce = this.#nonceManager.generate();
      const ciphertext = MessageCrypto.encrypt(
        payload, nonce, peerPublicKey, this.#handshake.secretKey,
      );

      this.#connManager.send(peerNickname, {
        type: 'p2p_message',
        payload: {
          ciphertext: ciphertext.toString('base64'),
          nonce: nonce.toString('base64'),
        },
      });
    }
  }

  #sendMessageToAll(text) {
    if (this.#peers.size === 0) {
      this.#ui.addSystemMessage('Nenhum peer online para receber mensagens');
      return;
    }

    const payload = JSON.stringify({
      text,
      sentAt: Date.now(),
      messageId: Math.random().toString(36).slice(2, 10),
    });

    this.#broadcastPayload(payload);
    this.#ui.addMessage(this.#nickname, text);
  }

  #sendFile(filePath) {
    const broadcastFn = (payloadObj) => {
      const payload = JSON.stringify({ ...payloadObj, sentAt: Date.now() });
      this.#broadcastPayload(payload);
    };

    this.#fileTransfer.initSend(filePath, broadcastFn, {
      onProgress: (percent, text) => this.#ui.updateProgress(text, percent),
      onError: (text) => this.#ui.addErrorMessage(text),
      onComplete: (text) => this.#ui.addSystemMessage(text),
    });
  }

  // ── State serialization ──────────────────────────────────────
  serializeState() {
    return {
      passphrase: this.#passphrase,
      keyManager: this.#keyManager.serialize(),
      handshake: this.#handshake.serializeState(),
      peers: Object.fromEntries(this.#peers),
      nickname: this.#nickname,
    };
  }

  // ── Destroy ─────────────────────────────────────────────────
  destroy() {
    if (this.#keyRotationTimer) clearInterval(this.#keyRotationTimer);
    for (const timer of this.#peerTypingTimers.values()) clearTimeout(timer);
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connManager.destroy();
    this.#peerServer.stop();
    this.#discovery.stop();
    this.#ui.destroy();
  }
}
