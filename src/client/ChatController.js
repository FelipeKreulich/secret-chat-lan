import { MSG, createJoin, createEncryptedMessage } from '../protocol/messages.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';

export class ChatController {
  #nickname;
  #connection;
  #ui;
  #keyManager;
  #handshake;
  #nonceManager;
  #sessionId;
  #peers; // Map<sessionId, { nickname, publicKey }>

  constructor(nickname, connection, ui) {
    this.#nickname = nickname;
    this.#connection = connection;
    this.#ui = ui;
    this.#keyManager = new KeyManager();
    this.#handshake = new Handshake(this.#keyManager);
    this.#nonceManager = new NonceManager();
    this.#sessionId = null;
    this.#peers = new Map();

    this.#setupConnectionHandlers();
    this.#setupUIHandlers();
  }

  get fingerprint() {
    return this.#keyManager.fingerprint;
  }

  // ── Connection event handlers ─────────────────────────────────
  #setupConnectionHandlers() {
    this.#connection.on('connected', () => {
      this.#connection.send(
        createJoin(this.#nickname, this.#keyManager.publicKeyB64),
      );
    });

    this.#connection.on('disconnected', () => {
      this.#ui.addErrorMessage('Conexao perdida com o servidor');
    });

    this.#connection.on('reconnecting', (delay) => {
      this.#ui.addSystemMessage(`Reconectando em ${delay / 1000}s...`);
    });

    this.#connection.on('message', (msg) => {
      this.#handleServerMessage(msg);
    });
  }

  // ── UI event handlers ─────────────────────────────────────────
  #setupUIHandlers() {
    this.#ui.on('input', (text) => {
      this.#handleUserInput(text);
    });

    this.#ui.on('quit', () => {
      this.destroy();
      process.exit(0);
    });
  }

  // ── Route server messages ─────────────────────────────────────
  #handleServerMessage(msg) {
    switch (msg.type) {
      case MSG.JOIN_ACK:
        this.#onJoinAck(msg);
        break;

      case MSG.PEER_JOINED:
        this.#onPeerJoined(msg);
        break;

      case MSG.PEER_LEFT:
        this.#onPeerLeft(msg);
        break;

      case MSG.ENCRYPTED_MESSAGE:
        this.#onEncryptedMessage(msg);
        break;

      case MSG.ERROR:
        this.#ui.addErrorMessage(`Erro: ${msg.message} (${msg.code})`);
        break;
    }
  }

  // ── JOIN_ACK: registered with server ──────────────────────────
  #onJoinAck(msg) {
    this.#sessionId = msg.sessionId;

    for (const peer of msg.peers) {
      this.#peers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
      });
      this.#handshake.registerPeer(peer.sessionId, peer.publicKey);
    }

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.addSystemMessage('Conectado ao servidor com criptografia E2E ativa');

    if (this.#peers.size > 0) {
      const names = [...this.#peers.values()].map((p) => p.nickname).join(', ');
      this.#ui.addSystemMessage(`Online: ${names}`);
    }
  }

  // ── New peer arrived ──────────────────────────────────────────
  #onPeerJoined(msg) {
    const { peer } = msg;
    this.#peers.set(peer.sessionId, {
      nickname: peer.nickname,
      publicKey: peer.publicKey,
    });
    this.#handshake.registerPeer(peer.sessionId, peer.publicKey);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.addSystemMessage(`${peer.nickname} entrou no chat`);
  }

  // ── Peer left ─────────────────────────────────────────────────
  #onPeerLeft(msg) {
    const peer = this.#peers.get(msg.sessionId);
    const nickname = peer?.nickname || msg.nickname || 'Desconhecido';

    this.#handshake.removePeer(msg.sessionId);
    this.#nonceManager.removePeer(msg.sessionId);
    this.#peers.delete(msg.sessionId);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.addSystemMessage(`${nickname} saiu do chat`);
  }

  // ── Received encrypted message ────────────────────────────────
  #onEncryptedMessage(msg) {
    const peer = this.#peers.get(msg.from);
    if (!peer) {
      this.#ui.addErrorMessage('Mensagem de peer desconhecido');
      return;
    }

    const senderPublicKey = this.#handshake.getPeerPublicKey(msg.from);
    if (!senderPublicKey) {
      this.#ui.addErrorMessage(`Chave publica nao encontrada para ${peer.nickname}`);
      return;
    }

    const ciphertext = Buffer.from(msg.payload.ciphertext, 'base64');
    const nonce = Buffer.from(msg.payload.nonce, 'base64');

    // Anti-replay validation
    if (!this.#nonceManager.validate(msg.from, nonce)) {
      this.#ui.addErrorMessage(`Nonce invalido de ${peer.nickname} (possivel replay)`);
      return;
    }

    const plaintext = MessageCrypto.decrypt(
      ciphertext,
      nonce,
      senderPublicKey,
      this.#handshake.secretKey,
    );
    if (!plaintext) {
      this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${peer.nickname} (MAC invalido)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));
      this.#ui.addMessage(peer.nickname, data.text);
    } catch {
      this.#ui.addErrorMessage(`Payload decifrado invalido de ${peer.nickname}`);
    }
  }

  // ── User input handling ───────────────────────────────────────
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
        this.#ui.addInfoMessage('Comandos disponiveis:');
        this.#ui.addInfoMessage('  /help          - Mostra esta ajuda');
        this.#ui.addInfoMessage('  /users         - Lista usuarios online');
        this.#ui.addInfoMessage('  /fingerprint   - Mostra seu fingerprint');
        this.#ui.addInfoMessage('  /fingerprint <nick> - Fingerprint de outro usuario');
        this.#ui.addInfoMessage('  /clear         - Limpa o chat');
        this.#ui.addInfoMessage('  /quit          - Sai do chat');
        break;

      case '/users': {
        const names = [...this.#peers.values()].map((p) => p.nickname);
        this.#ui.addInfoMessage(`Online (${names.length + 1}): ${this.#nickname} (voce), ${names.join(', ') || 'ninguem mais'}`);
        break;
      }

      case '/fingerprint': {
        const targetNick = parts[1];
        if (!targetNick) {
          this.#ui.addInfoMessage(`Seu fingerprint: ${this.#keyManager.fingerprint}`);
        } else {
          const found = [...this.#peers.values()].find(
            (p) => p.nickname.toLowerCase() === targetNick.toLowerCase(),
          );
          if (found) {
            const fp = KeyManager.computeFingerprint(Buffer.from(found.publicKey, 'base64'));
            this.#ui.addInfoMessage(`Fingerprint de ${found.nickname}: ${fp}`);
          } else {
            this.#ui.addErrorMessage(`Usuario "${targetNick}" nao encontrado`);
          }
        }
        break;
      }

      case '/clear':
        this.#ui.addSystemMessage('Chat limpo');
        break;

      case '/quit':
        this.destroy();
        process.exit(0);
        break;

      default:
        this.#ui.addErrorMessage(`Comando desconhecido: ${cmd}. Use /help`);
    }
  }

  // ── Send encrypted message to all peers ───────────────────────
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

    for (const [peerId] of this.#peers) {
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
      if (!peerPublicKey) {
        continue;
      }

      const nonce = this.#nonceManager.generate();
      const ciphertext = MessageCrypto.encrypt(
        payload,
        nonce,
        peerPublicKey,
        this.#handshake.secretKey,
      );

      this.#connection.send(
        createEncryptedMessage(
          this.#sessionId,
          peerId,
          ciphertext.toString('base64'),
          nonce.toString('base64'),
        ),
      );
    }

    // Show own message locally
    this.#ui.addMessage(this.#nickname, text);
  }

  destroy() {
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connection.close();
    this.#ui.destroy();
  }
}
