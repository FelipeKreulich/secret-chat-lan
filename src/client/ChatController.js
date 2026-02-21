import sodium from 'sodium-native';
import {
  MSG,
  createJoin,
  createEncryptedMessage,
  createRatchetedMessage,
  createKeyUpdate,
} from '../protocol/messages.js';
import { KEY_ROTATION_INTERVAL_MS } from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from './FileTransfer.js';

const TYPING_SEND_INTERVAL = 2000; // debounce: max 1 typing event per 2s
const TYPING_EXPIRE_TIMEOUT = 3000; // hide indicator after 3s of silence

export class ChatController {
  #nickname;
  #connection;
  #ui;
  #keyManager;
  #handshake;
  #nonceManager;
  #sessionId;
  #peers; // Map<sessionId, { nickname, publicKey }>
  #lastTypingSent;
  #peerTypingTimers; // Map<sessionId, timeoutId>
  #fileTransfer;
  #keyRotationTimer;
  #trustStore;
  #passphrase;

  constructor(nickname, connection, ui, restoredState = null) {
    this.#nickname = nickname;
    this.#connection = connection;
    this.#ui = ui;
    this.#passphrase = restoredState?.passphrase || null;

    if (restoredState?.keyManager) {
      this.#keyManager = KeyManager.deserialize(restoredState.keyManager);
    } else {
      this.#keyManager = new KeyManager();
    }

    this.#handshake = new Handshake(this.#keyManager);
    if (restoredState?.handshake) {
      this.#handshake.restoreState(restoredState.handshake);
    }

    this.#nonceManager = new NonceManager();
    this.#sessionId = null;
    this.#peers = new Map();

    if (restoredState?.peers) {
      for (const [sid, peer] of Object.entries(restoredState.peers)) {
        this.#peers.set(sid, peer);
      }
    }

    this.#lastTypingSent = 0;
    this.#peerTypingTimers = new Map();
    this.#fileTransfer = new FileTransfer();
    this.#keyRotationTimer = null;
    this.#trustStore = new TrustStore();

    this.#setupConnectionHandlers();
    this.#setupUIHandlers();
    this.#startKeyRotation();
  }

  get fingerprint() {
    return this.#keyManager.fingerprint;
  }

  // ── Connection event handlers ─────────────────────────────────
  #setupConnectionHandlers() {
    this.#connection.on('connected', () => {
      this.#connection.send(createJoin(this.#nickname, this.#keyManager.publicKeyB64));
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

    this.#ui.on('activity', () => {
      this.#handleTypingActivity();
    });

    this.#ui.on('quit', () => {
      this.destroy();
      process.exit(0);
    });
  }

  // ── Typing indicator (outgoing) ─────────────────────────────
  #handleTypingActivity() {
    const now = Date.now();
    if (now - this.#lastTypingSent < TYPING_SEND_INTERVAL) {
      return;
    }
    if (this.#peers.size === 0) {
      return;
    }

    this.#lastTypingSent = now;
    this.#sendCommandToAll('typing');
  }

  // ── Typing indicator (incoming) ─────────────────────────────
  #showPeerTyping(sessionId, nickname) {
    // Clear existing timer for this peer
    const existing = this.#peerTypingTimers.get(sessionId);
    if (existing) {
      clearTimeout(existing);
    }

    this.#ui.showTyping(nickname);

    // Auto-hide after timeout
    const timer = setTimeout(() => {
      this.#ui.hideTyping(nickname);
      this.#peerTypingTimers.delete(sessionId);
    }, TYPING_EXPIRE_TIMEOUT);

    this.#peerTypingTimers.set(sessionId, timer);
  }

  #hidePeerTyping(sessionId, nickname) {
    const timer = this.#peerTypingTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      this.#peerTypingTimers.delete(sessionId);
    }
    this.#ui.hideTyping(nickname);
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

      case MSG.PEER_KEY_UPDATED:
        this.#onPeerKeyUpdated(msg);
        break;

      case MSG.ERROR:
        this.#ui.addErrorMessage(`Erro: ${msg.message} (${msg.code})`);
        break;
    }
  }

  // ── TOFU: Trust On First Use ──────────────────────────────────
  #checkTrust(nickname, publicKey) {
    const result = this.#trustStore.checkPeer(nickname, publicKey);

    switch (result) {
      case TrustResult.NEW_PEER:
        this.#trustStore.recordPeer(nickname, publicKey);
        break;

      case TrustResult.TRUSTED:
        // Fingerprint matches — nothing to show
        break;

      case TrustResult.MISMATCH:
        this.#ui.addErrorMessage(
          `AVISO: A chave de ${nickname} mudou! Possivel ataque MITM. Use /trust ${nickname} para aceitar ou /verify ${nickname} para verificar.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#ui.addErrorMessage(
          `ALERTA: A chave VERIFICADA de ${nickname} mudou! Isso pode indicar um ataque. Use /verify ${nickname} para re-verificar.`,
        );
        break;
    }
  }

  // ── JOIN_ACK: registered with server ──────────────────────────
  #onJoinAck(msg) {
    this.#sessionId = msg.sessionId;

    // Build map of old sessionIds by nickname for ratchet migration
    const oldSessionByNick = new Map();
    for (const [sid, peer] of this.#peers) {
      oldSessionByNick.set(peer.nickname.toLowerCase(), sid);
    }
    this.#peers.clear();

    for (const peer of msg.peers) {
      this.#peers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
      });

      const oldSid = oldSessionByNick.get(peer.nickname.toLowerCase());
      if (oldSid && oldSid !== peer.sessionId) {
        // Migrate ratchet from old sessionId to new sessionId
        this.#handshake.migrateRatchet(oldSid, peer.sessionId);
      } else if (!oldSid) {
        this.#handshake.registerPeer(peer.sessionId, peer.publicKey);
      }

      this.#checkTrust(peer.nickname, peer.publicKey);
    }

    // Initialize ratchets now that we have our session ID
    this.#handshake.setMySessionId(msg.sessionId);

    const peerNames = [...this.#peers.values()].map((p) => p.nickname);
    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames(peerNames);
    this.#ui.addSystemMessage('Conectado ao servidor com criptografia E2E ativa');

    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }

    if (msg.queuedCount > 0) {
      this.#ui.addSystemMessage(`${msg.queuedCount} mensagem(ns) pendente(s) sendo entregue(s)`);
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
    this.#checkTrust(peer.nickname, peer.publicKey);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames([...this.#peers.values()].map((p) => p.nickname));
    this.#ui.addSystemMessage(`${peer.nickname} entrou no chat`);
  }

  // ── Peer left ─────────────────────────────────────────────────
  #onPeerLeft(msg) {
    const peer = this.#peers.get(msg.sessionId);
    const nickname = peer?.nickname || msg.nickname || 'Desconhecido';

    this.#hidePeerTyping(msg.sessionId, nickname);
    this.#handshake.removePeer(msg.sessionId);
    this.#nonceManager.removePeer(msg.sessionId);
    this.#peers.delete(msg.sessionId);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames([...this.#peers.values()].map((p) => p.nickname));
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

    let plaintext = null;

    // Ratcheted message path (has ephemeralPublicKey)
    if (msg.payload.ephemeralPublicKey) {
      const ratchet = this.#handshake.getRatchet(msg.from);
      if (ratchet) {
        const ephPub = Buffer.from(msg.payload.ephemeralPublicKey, 'base64');
        plaintext = ratchet.decrypt(
          ciphertext,
          nonce,
          ephPub,
          msg.payload.counter,
          msg.payload.previousCounter,
        );
      }

      // Fallback to static decrypt if ratchet failed
      if (!plaintext) {
        if (!this.#nonceManager.validate(msg.from, nonce)) {
          this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${peer.nickname}`);
          return;
        }
        plaintext = MessageCrypto.decryptWithFallback(
          ciphertext,
          nonce,
          senderPublicKey,
          this.#handshake.secretKey,
          this.#handshake.getPreviousPeerPublicKey(msg.from),
          this.#handshake.previousSecretKey,
        );
      }
    } else {
      // Static message path (no ephemeralPublicKey)
      if (!this.#nonceManager.validate(msg.from, nonce)) {
        this.#ui.addErrorMessage(`Nonce invalido de ${peer.nickname} (possivel replay)`);
        return;
      }

      plaintext = MessageCrypto.decryptWithFallback(
        ciphertext,
        nonce,
        senderPublicKey,
        this.#handshake.secretKey,
        this.#handshake.getPreviousPeerPublicKey(msg.from),
        this.#handshake.previousSecretKey,
      );
    }

    if (!plaintext) {
      this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${peer.nickname} (MAC invalido)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));

      if (data.action === 'clear') {
        this.#ui.clearChat();
        return;
      }

      if (data.action === 'typing') {
        this.#showPeerTyping(msg.from, peer.nickname);
        return;
      }

      if (data.action === 'key_rotation') {
        this.#handshake.updatePeerKey(msg.from, data.newPublicKey);
        const p = this.#peers.get(msg.from);
        if (p) {
          p.publicKey = data.newPublicKey;
        }
        // E2E authenticated rotation — preserve verified status
        this.#trustStore.autoUpdatePeer(peer.nickname, data.newPublicKey);
        this.#ui.addSystemMessage(`${peer.nickname} rotacionou chaves`);
        return;
      }

      if (data.action === 'file_offer') {
        const info = this.#fileTransfer.handleFileOffer(msg.from, data, peer.nickname);
        this.#ui.addSystemMessage(info);
        this.#ui.playNotification();
        return;
      }

      if (data.action === 'file_chunk') {
        const progress = this.#fileTransfer.handleFileChunk(msg.from, data);
        if (progress && progress.percent % 10 === 0) {
          this.#ui.updateProgress(progress.text, progress.percent);
        }
        return;
      }

      if (data.action === 'file_complete') {
        this.#fileTransfer.handleFileComplete(msg.from, data).then((result) => {
          if (result.success) {
            this.#ui.addSystemMessage(result.message);
          } else {
            this.#ui.addErrorMessage(result.message);
          }
        });
        return;
      }

      // Text message received — hide typing indicator for this peer
      this.#hidePeerTyping(msg.from, peer.nickname);
      this.#ui.addMessage(peer.nickname, data.text);
      this.#ui.playNotification();
    } catch {
      this.#ui.addErrorMessage(`Payload decifrado invalido de ${peer.nickname}`);
    } finally {
      // Wipe plaintext buffer from memory (V8 strings from JSON.parse cannot be wiped)
      if (plaintext && Buffer.isBuffer(plaintext)) {
        sodium.sodium_memzero(plaintext);
      }
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
        this.#ui.addInfoMessage('  /help                - Mostra esta ajuda');
        this.#ui.addInfoMessage('  /users               - Lista usuarios online');
        this.#ui.addInfoMessage('  /fingerprint         - Mostra seu fingerprint');
        this.#ui.addInfoMessage('  /fingerprint <nick>  - Fingerprint de outro usuario');
        this.#ui.addInfoMessage('  /verify <nick>       - Mostra codigo SAS para verificacao');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirma verificacao do peer');
        this.#ui.addInfoMessage('  /trust <nick>        - Aceita nova chave de um peer');
        this.#ui.addInfoMessage('  /trustlist           - Status de confianca dos peers');
        this.#ui.addInfoMessage('  /clear               - Limpa o chat');
        this.#ui.addInfoMessage('  /file <caminho>      - Envia arquivo (max 50MB)');
        this.#ui.addInfoMessage('  /sound [on|off]      - Notificacoes sonoras');
        this.#ui.addInfoMessage('  /quit                - Sai do chat');
        break;

      case '/users': {
        const names = [...this.#peers.values()].map((p) => p.nickname);
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
        const verifyPeer = [...this.#peers.values()].find(
          (p) => p.nickname.toLowerCase() === verifyNick.toLowerCase(),
        );
        if (!verifyPeer) {
          this.#ui.addErrorMessage(`Usuario "${verifyNick}" nao encontrado`);
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
          this.#ui.addErrorMessage(
            `Peer "${confirmNick}" nao encontrado no trust store. O peer precisa estar online primeiro.`,
          );
        }
        break;
      }

      case '/trust': {
        const trustNick = parts[1];
        if (!trustNick) {
          this.#ui.addErrorMessage('Uso: /trust <nickname>');
          break;
        }
        const trustPeer = [...this.#peers.values()].find(
          (p) => p.nickname.toLowerCase() === trustNick.toLowerCase(),
        );
        if (!trustPeer) {
          this.#ui.addErrorMessage(`Usuario "${trustNick}" nao esta online`);
          break;
        }
        this.#trustStore.updatePeer(trustPeer.nickname, trustPeer.publicKey);
        this.#ui.addSystemMessage(`Chave de ${trustPeer.nickname} aceita (verificacao resetada)`);
        break;
      }

      case '/trustlist': {
        const peerList = [...this.#peers.values()];
        if (peerList.length === 0) {
          this.#ui.addInfoMessage('Nenhum peer online');
          break;
        }
        this.#ui.addInfoMessage('Status de confianca:');
        for (const p of peerList) {
          const record = this.#trustStore.getPeerRecord(p.nickname);
          let status;
          if (!record) {
            status = 'desconhecido';
          } else if (record.verified) {
            status = 'verificado';
          } else {
            status = 'confiavel (TOFU)';
          }
          this.#ui.addInfoMessage(`  ${p.nickname}: ${status}`);
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

  // ── Key rotation ─────────────────────────────────────────────
  #startKeyRotation() {
    this.#keyRotationTimer = setInterval(() => {
      this.#rotateKeys();
    }, KEY_ROTATION_INTERVAL_MS);
  }

  #rotateKeys() {
    this.#keyManager.rotate();

    // Announce new key to peers via encrypted channel (authenticated)
    const payload = JSON.stringify({
      action: 'key_rotation',
      newPublicKey: this.#keyManager.publicKeyB64,
      sentAt: Date.now(),
    });
    this.#broadcastPayload(payload);

    // Update server with new public key
    this.#connection.send(createKeyUpdate(this.#keyManager.publicKeyB64));

    this.#ui.addSystemMessage(
      `Chaves rotacionadas (novo fingerprint: ${this.#keyManager.fingerprint})`,
    );
  }

  // ── Handle server PEER_KEY_UPDATED ─────────────────────────
  #onPeerKeyUpdated(msg) {
    const peer = this.#peers.get(msg.sessionId);
    if (!peer) {
      return;
    }

    // Server broadcast is NOT authenticated (could be MITM) — do NOT auto-update trust store
    this.#handshake.updatePeerKey(msg.sessionId, msg.publicKey);
    peer.publicKey = msg.publicKey;
    this.#ui.addSystemMessage(`${peer.nickname} atualizou chave (via servidor — nao autenticado)`);
  }

  // ── Send encrypted command to all peers ────────────────────────
  #sendCommandToAll(action) {
    const payload = JSON.stringify({ action, sentAt: Date.now() });
    this.#broadcastPayload(payload);
  }

  // ── Broadcast encrypted payload to all peers ───────────────────
  #broadcastPayload(payload) {
    for (const [peerId] of this.#peers) {
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
      if (!peerPublicKey) {
        continue;
      }

      // Try ratchet path (PFS) first
      const ratchet = this.#handshake.getRatchet(peerId);
      if (ratchet && ratchet.isInitialized) {
        try {
          const result = ratchet.encrypt(payload);
          this.#connection.send(createRatchetedMessage(this.#sessionId, peerId, result));
          continue;
        } catch {
          // Ratchet failed — fall through to static path
        }
      }

      // Static path (fallback: offline queue, initial msgs, ratchet failure)
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
  }

  // ── Send file to all peers ─────────────────────────────────
  #sendFile(filePath) {
    const broadcastFn = (payloadObj) => {
      const payload = JSON.stringify({ ...payloadObj, sentAt: Date.now() });
      this.#broadcastPayload(payload);
    };

    this.#fileTransfer.initSend(filePath, broadcastFn, {
      onProgress: (percent, text) => {
        this.#ui.updateProgress(text, percent);
      },
      onError: (text) => {
        this.#ui.addErrorMessage(text);
      },
      onComplete: (text) => {
        this.#ui.addSystemMessage(text);
      },
    });
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

    this.#broadcastPayload(payload);

    // Show own message locally
    this.#ui.addMessage(this.#nickname, text);
  }

  // ── State serialization ──────────────────────────────────────

  get passphrase() {
    return this.#passphrase;
  }

  serializeState() {
    return {
      passphrase: this.#passphrase,
      keyManager: this.#keyManager.serialize(),
      handshake: this.#handshake.serializeState(),
      peers: Object.fromEntries(this.#peers),
      nickname: this.#nickname,
    };
  }

  destroy() {
    if (this.#keyRotationTimer) {
      clearInterval(this.#keyRotationTimer);
    }
    for (const timer of this.#peerTypingTimers.values()) {
      clearTimeout(timer);
    }
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connection.close();
    this.#ui.destroy();
  }
}
