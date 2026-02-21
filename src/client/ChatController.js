import sodium from 'sodium-native';
import notifier from 'node-notifier';
import {
  MSG,
  createJoin,
  createEncryptedMessage,
  createRatchetedMessage,
  createKeyUpdate,
  createChangeRoom,
  createListRooms,
  createKickPeer,
  createMutePeer,
  createBanPeer,
} from '../protocol/messages.js';
import { KEY_ROTATION_INTERVAL_MS, EMOJI_MAP } from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from './FileTransfer.js';
import { AuditLog, AuditEvent } from '../shared/AuditLog.js';
import { deriveSharedKey, encryptDeniable, decryptDeniable } from '../crypto/DeniableEncrypt.js';

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
  #currentRoom;
  #auditLog;
  #ephemeralMode;
  #ephemeralDurationMs;
  #ephemeralTimers;
  #lastReceivedMessageId;
  #lastReceivedNickname;
  #lastSentMessageId;
  #messageAuthors;
  #pinnedMessages;
  #lastReceivedText;
  #deniableMode;
  #pluginManager;

  constructor(nickname, connection, ui, restoredState = null, pluginManager = null) {
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
    this.#currentRoom = 'general';
    this.#auditLog = new AuditLog();
    this.#ephemeralMode = false;
    this.#ephemeralDurationMs = 0;
    this.#ephemeralTimers = [];
    this.#lastReceivedMessageId = null;
    this.#lastReceivedNickname = null;
    this.#lastSentMessageId = null;
    this.#messageAuthors = new Map(); // Map<messageId, nickname>
    this.#pinnedMessages = [];
    this.#lastReceivedText = null;
    this.#deniableMode = false;
    this.#pluginManager = pluginManager;

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

      case MSG.ROOM_CHANGED:
        this.#onRoomChanged(msg);
        break;

      case MSG.ROOM_LIST:
        this.#onRoomList(msg);
        break;

      case MSG.PEER_KICKED:
        this.#onPeerKicked(msg);
        break;

      case MSG.PEER_MUTED:
        this.#onPeerMuted(msg);
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
        this.#auditLog.log(AuditEvent.TRUST_NEW_PEER, { nickname });
        break;

      case TrustResult.TRUSTED:
        break;

      case TrustResult.MISMATCH:
        this.#auditLog.log(AuditEvent.TRUST_MISMATCH, { nickname });
        this.#ui.addErrorMessage(
          `AVISO: A chave de ${nickname} mudou! Possivel ataque MITM. Use /trust ${nickname} para aceitar ou /verify ${nickname} para verificar.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#auditLog.log(AuditEvent.TRUST_VERIFIED_MISMATCH, { nickname });
        this.#ui.addErrorMessage(
          `ALERTA: A chave VERIFICADA de ${nickname} mudou! Isso pode indicar um ataque. Use /verify ${nickname} para re-verificar.`,
        );
        break;
    }
  }

  // ── JOIN_ACK: registered with server ──────────────────────────
  #onJoinAck(msg) {
    this.#sessionId = msg.sessionId;
    this.#currentRoom = msg.room || 'general';

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
    this.#auditLog.log(AuditEvent.PEER_CONNECTED, { nickname: peer.nickname });
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
    this.#auditLog.log(AuditEvent.PEER_DISCONNECTED, { nickname });
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
    const isDeniable = !!msg.payload.deniable;

    // Deniable message path (symmetric crypto_secretbox)
    if (isDeniable) {
      const sharedKey = deriveSharedKey(this.#handshake.secretKey, senderPublicKey);
      plaintext = decryptDeniable(ciphertext, nonce, sharedKey);
      if (!plaintext) {
        this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: peer.nickname, deniable: true });
        this.#ui.addErrorMessage(`Falha ao decifrar mensagem deniable de ${peer.nickname}`);
        return;
      }
    }

    // Ratcheted message path (has ephemeralPublicKey)
    if (!isDeniable && msg.payload.ephemeralPublicKey) {
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
          this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: peer.nickname });
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
    } else if (!isDeniable) {
      // Static message path (no ephemeralPublicKey)
      if (!this.#nonceManager.validate(msg.from, nonce)) {
        this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: peer.nickname });
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
      this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: peer.nickname });
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
        this.#auditLog.log(AuditEvent.KEY_ROTATION_PEER, { nickname: peer.nickname });
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

      if (data.action === 'reaction') {
        this.#ui.addSystemMessage(`${data.emoji} ${peer.nickname} reagiu a uma mensagem`);
        this.#ui.playNotification();
        return;
      }

      if (data.action === 'edit_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (author && author === peer.nickname) {
          this.#ui.addSystemMessage(`${peer.nickname} editou: ${data.newText} (editado)`);
        }
        return;
      }

      if (data.action === 'delete_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (author && author === peer.nickname) {
          this.#ui.addSystemMessage(`${peer.nickname} apagou uma mensagem`);
        }
        return;
      }

      if (data.action === 'pin_message') {
        this.#pinnedMessages.push({
          messageId: data.messageId,
          nickname: data.nickname,
          text: data.text,
          pinnedBy: peer.nickname,
          pinnedAt: Date.now(),
        });
        this.#ui.addSystemMessage(`\uD83D\uDCCC ${peer.nickname} fixou: "${data.text}" \u2014 ${data.nickname}`);
        return;
      }

      if (data.action === 'unpin_message') {
        this.#pinnedMessages = this.#pinnedMessages.filter((p) => p.messageId !== data.messageId);
        this.#ui.addSystemMessage(`${peer.nickname} removeu fixacao`);
        return;
      }

      // Text message received — hide typing indicator for this peer
      this.#hidePeerTyping(msg.from, peer.nickname);
      if (data.messageId) {
        this.#lastReceivedMessageId = data.messageId;
        this.#lastReceivedNickname = peer.nickname;
        this.#lastReceivedText = data.text;
        this.#messageAuthors.set(data.messageId, peer.nickname);
      }
      const ephLabel = data.ephemeral ? this.#formatDuration(data.ephemeral) : null;
      const { lineIndex } = this.#ui.addMessage(peer.nickname, data.text, !!data.isDM, ephLabel, isDeniable || !!data.deniable);
      this.#ui.playNotification();

      if (data.ephemeral && data.ephemeral > 0) {
        this.#scheduleEphemeralRemoval(lineIndex, data.ephemeral, peer.nickname);
      }

      if (this.#ui.notifyEnabled) {
        notifier.notify({
          title: data.isDM ? `DM de ${peer.nickname}` : `${peer.nickname} — CipherMesh`,
          message: data.text.slice(0, 100),
          sound: false,
        });
      }
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
        this.#ui.addInfoMessage('  /msg <nick> <texto>  - Envia mensagem privada (DM)');
        this.#ui.addInfoMessage('  /join <sala>         - Entra em uma sala');
        this.#ui.addInfoMessage('  /rooms               - Lista salas disponiveis');
        this.#ui.addInfoMessage('  /room                - Mostra sala atual');
        this.#ui.addInfoMessage('  /fingerprint         - Mostra seu fingerprint');
        this.#ui.addInfoMessage('  /fingerprint <nick>  - Fingerprint de outro usuario');
        this.#ui.addInfoMessage('  /verify <nick>       - Mostra codigo SAS para verificacao');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirma verificacao do peer');
        this.#ui.addInfoMessage('  /trust <nick>        - Aceita nova chave de um peer');
        this.#ui.addInfoMessage('  /trustlist           - Status de confianca dos peers');
        this.#ui.addInfoMessage('  /clear               - Limpa o chat');
        this.#ui.addInfoMessage('  /file <caminho>      - Envia arquivo (max 50MB)');
        this.#ui.addInfoMessage('  /sound [on|off]      - Notificacoes sonoras');
        this.#ui.addInfoMessage('  /notify [on|off]     - Notificacoes desktop');
        this.#ui.addInfoMessage('  /audit [N]           - Mostra ultimos N eventos de auditoria');
        this.#ui.addInfoMessage('  /ephemeral <tempo|off> - Mensagens efemeras (ex: 30s, 5m, 1h)');
        this.#ui.addInfoMessage('  /react <emoji>       - Reage a ultima mensagem recebida');
        this.#ui.addInfoMessage('  /edit <novo texto>   - Edita ultima mensagem enviada');
        this.#ui.addInfoMessage('  /delete              - Apaga ultima mensagem enviada');
        this.#ui.addInfoMessage('  /pin                 - Fixa ultima mensagem recebida');
        this.#ui.addInfoMessage('  /unpin               - Remove ultimo pin');
        this.#ui.addInfoMessage('  /pins                - Lista mensagens fixadas');
        this.#ui.addInfoMessage('  /deniable [on|off]   - Modo deniable (crypto simetrico)');
        this.#ui.addInfoMessage('  /kick <nick> [motivo] - Expulsa usuario da sala (owner)');
        this.#ui.addInfoMessage('  /mute <nick> [tempo] - Silencia usuario (owner, default 5m)');
        this.#ui.addInfoMessage('  /ban <nick> [motivo] - Bane usuario da sala (owner)');
        this.#ui.addInfoMessage('  /plugins             - Lista plugins carregados');
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
        this.#auditLog.log(AuditEvent.SAS_VERIFY, { nickname: verifyPeer.nickname });
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
          this.#auditLog.log(AuditEvent.SAS_CONFIRM, { nickname: confirmNick });
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

      case '/notify': {
        const notifyArg = parts[1]?.toLowerCase();
        if (notifyArg === 'off') {
          this.#ui.setNotifyEnabled(false);
          this.#ui.addInfoMessage('Notificacoes desktop desativadas');
        } else if (notifyArg === 'on') {
          this.#ui.setNotifyEnabled(true);
          this.#ui.addInfoMessage('Notificacoes desktop ativadas');
        } else {
          const status = this.#ui.notifyEnabled ? 'ativadas' : 'desativadas';
          this.#ui.addInfoMessage(`Notificacoes desktop: ${status}. Use /notify on ou /notify off`);
        }
        break;
      }

      case '/msg': {
        const msgNick = parts[1];
        if (!msgNick) {
          this.#ui.addErrorMessage('Uso: /msg <nick> <texto>');
          break;
        }
        const msgText = parts.slice(2).join(' ');
        if (!msgText) {
          this.#ui.addErrorMessage('Uso: /msg <nick> <texto>');
          break;
        }
        const msgPeer = [...this.#peers.entries()].find(
          ([, p]) => p.nickname.toLowerCase() === msgNick.toLowerCase(),
        );
        if (!msgPeer) {
          this.#ui.addErrorMessage(`Usuario "${msgNick}" nao encontrado`);
          break;
        }
        this.#sendMessageToPeer(msgPeer[0], msgPeer[1].nickname, msgText);
        break;
      }

      case '/join': {
        const roomName = parts[1];
        if (!roomName) {
          this.#ui.addErrorMessage('Uso: /join <sala>');
          break;
        }
        this.#connection.send(createChangeRoom(roomName));
        break;
      }

      case '/rooms':
        this.#connection.send(createListRooms());
        break;

      case '/room':
        this.#ui.addInfoMessage(`Sala atual: #${this.#currentRoom}`);
        break;

      case '/deniable': {
        const denArg = parts[1]?.toLowerCase();
        if (denArg === 'off') {
          this.#deniableMode = false;
          this.#ui.removeHeaderIndicator('deniable');
          this.#ui.addInfoMessage('Modo deniable desativado');
        } else if (denArg === 'on') {
          this.#deniableMode = true;
          this.#ui.setHeaderIndicator('deniable', '{magenta-fg}[D]{/magenta-fg}');
          this.#ui.addInfoMessage('Modo deniable ativado (crypto simetrico — plausible deniability)');
        } else {
          const status = this.#deniableMode ? 'ativado' : 'desativado';
          this.#ui.addInfoMessage(`Modo deniable: ${status}. Use /deniable on ou /deniable off`);
        }
        break;
      }

      case '/audit': {
        const auditCount = parseInt(parts[1]) || 20;
        const events = this.#auditLog.readLast(auditCount);
        if (events.length === 0) {
          this.#ui.addInfoMessage('Nenhum evento de auditoria registrado');
        } else {
          this.#ui.addInfoMessage(`Ultimos ${events.length} evento(s) de auditoria:`);
          for (const e of events) {
            const { ts, event, ...rest } = e;
            const details = Object.keys(rest).length > 0 ? ` — ${JSON.stringify(rest)}` : '';
            this.#ui.addInfoMessage(`  [${ts}] ${event}${details}`);
          }
        }
        break;
      }

      case '/react': {
        const emojiArg = parts[1];
        if (!emojiArg) {
          this.#ui.addErrorMessage('Uso: /react <emoji>  (ex: :fire: :thumbsup: :heart:)');
          break;
        }
        if (!this.#lastReceivedMessageId) {
          this.#ui.addErrorMessage('Nenhuma mensagem para reagir');
          break;
        }
        const emoji = EMOJI_MAP[emojiArg] || emojiArg;
        const reactionPayload = JSON.stringify({
          action: 'reaction',
          targetMessageId: this.#lastReceivedMessageId,
          emoji,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(reactionPayload);
        this.#ui.addSystemMessage(`${emoji} Voce reagiu a mensagem de ${this.#lastReceivedNickname}`);
        break;
      }

      case '/edit': {
        const editText = parts.slice(1).join(' ');
        if (!editText) {
          this.#ui.addErrorMessage('Uso: /edit <novo texto>');
          break;
        }
        if (!this.#lastSentMessageId) {
          this.#ui.addErrorMessage('Nenhuma mensagem para editar');
          break;
        }
        const editPayload = JSON.stringify({
          action: 'edit_message',
          messageId: this.#lastSentMessageId,
          newText: editText,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(editPayload);
        this.#ui.addSystemMessage(`Voce editou: ${editText} (editado)`);
        break;
      }

      case '/delete': {
        if (!this.#lastSentMessageId) {
          this.#ui.addErrorMessage('Nenhuma mensagem para apagar');
          break;
        }
        const deletePayload = JSON.stringify({
          action: 'delete_message',
          messageId: this.#lastSentMessageId,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(deletePayload);
        this.#lastSentMessageId = null;
        this.#ui.addSystemMessage('Voce apagou uma mensagem');
        break;
      }

      case '/pin': {
        if (!this.#lastReceivedMessageId || !this.#lastReceivedText) {
          this.#ui.addErrorMessage('Nenhuma mensagem para fixar');
          break;
        }
        const pinPayload = JSON.stringify({
          action: 'pin_message',
          messageId: this.#lastReceivedMessageId,
          nickname: this.#lastReceivedNickname,
          text: this.#lastReceivedText,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(pinPayload);
        this.#pinnedMessages.push({
          messageId: this.#lastReceivedMessageId,
          nickname: this.#lastReceivedNickname,
          text: this.#lastReceivedText,
          pinnedBy: this.#nickname,
          pinnedAt: Date.now(),
        });
        this.#ui.addSystemMessage(`\uD83D\uDCCC Voce fixou: "${this.#lastReceivedText}" \u2014 ${this.#lastReceivedNickname}`);
        break;
      }

      case '/unpin': {
        if (this.#pinnedMessages.length === 0) {
          this.#ui.addErrorMessage('Nenhuma mensagem fixada');
          break;
        }
        const removed = this.#pinnedMessages.pop();
        const unpinPayload = JSON.stringify({
          action: 'unpin_message',
          messageId: removed.messageId,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(unpinPayload);
        this.#ui.addSystemMessage('Voce removeu a fixacao');
        break;
      }

      case '/pins': {
        if (this.#pinnedMessages.length === 0) {
          this.#ui.addInfoMessage('Nenhuma mensagem fixada');
        } else {
          this.#ui.addInfoMessage('Mensagens fixadas:');
          for (const pin of this.#pinnedMessages) {
            this.#ui.addInfoMessage(`  \uD83D\uDCCC "${pin.text}" \u2014 ${pin.nickname} (fixado por ${pin.pinnedBy})`);
          }
        }
        break;
      }

      case '/ephemeral': {
        const ephArg = parts[1]?.toLowerCase();
        if (!ephArg || ephArg === 'off') {
          this.#ephemeralMode = false;
          this.#ephemeralDurationMs = 0;
          this.#ui.removeHeaderIndicator('ephemeral');
          this.#ui.addInfoMessage('Modo efemero desativado');
        } else {
          const ms = this.#parseEphemeralTime(ephArg);
          if (!ms) {
            this.#ui.addErrorMessage('Formato invalido. Use: 30s, 5m, 1h ou off');
            break;
          }
          if (ms > 3_600_000) {
            this.#ui.addErrorMessage('Maximo: 1h (3600s)');
            break;
          }
          this.#ephemeralMode = true;
          this.#ephemeralDurationMs = ms;
          this.#ui.setHeaderIndicator('ephemeral', `{yellow-fg}[E ${ephArg}]{/yellow-fg}`);
          this.#ui.addInfoMessage(`Modo efemero ativado: ${ephArg}`);
        }
        break;
      }

      case '/kick': {
        const kickNick = parts[1];
        if (!kickNick) {
          this.#ui.addErrorMessage('Uso: /kick <nick> [motivo]');
          break;
        }
        const kickReason = parts.slice(2).join(' ');
        this.#connection.send(createKickPeer(kickNick, kickReason));
        break;
      }

      case '/mute': {
        const muteNick = parts[1];
        if (!muteNick) {
          this.#ui.addErrorMessage('Uso: /mute <nick> [tempo]');
          break;
        }
        const muteTimeStr = parts[2] || '5m';
        const muteDuration = this.#parseEphemeralTime(muteTimeStr);
        if (!muteDuration) {
          this.#ui.addErrorMessage('Formato de tempo invalido. Use: 30s, 5m, 1h');
          break;
        }
        this.#connection.send(createMutePeer(muteNick, muteDuration));
        break;
      }

      case '/ban': {
        const banNick = parts[1];
        if (!banNick) {
          this.#ui.addErrorMessage('Uso: /ban <nick> [motivo]');
          break;
        }
        const banReason = parts.slice(2).join(' ');
        this.#connection.send(createBanPeer(banNick, banReason));
        break;
      }

      case '/plugins': {
        if (!this.#pluginManager || this.#pluginManager.pluginCount === 0) {
          this.#ui.addInfoMessage('Nenhum plugin carregado. Coloque .js em ~/.ciphermesh/plugins/');
        } else {
          const names = this.#pluginManager.getPluginNames();
          this.#ui.addInfoMessage(`Plugins carregados (${names.length}): ${names.join(', ')}`);
          const cmds = this.#pluginManager.getCommandNames();
          if (cmds.length > 0) {
            this.#ui.addInfoMessage(`Comandos: ${cmds.join(', ')}`);
          }
        }
        break;
      }

      case '/quit':
        this.destroy();
        process.exit(0);
        break;

      default: {
        // Try plugin commands before reporting unknown
        if (this.#pluginManager) {
          const result = this.#pluginManager.handleCommand(cmd, parts.slice(1));
          if (result) {
            this.#ui.addInfoMessage(result);
            break;
          }
        }
        this.#ui.addErrorMessage(`Comando desconhecido: ${cmd}. Use /help`);
      }
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

    this.#auditLog.log(AuditEvent.KEY_ROTATION_OWN, { fingerprint: this.#keyManager.fingerprint });
    this.#ui.addSystemMessage(
      `Chaves rotacionadas (novo fingerprint: ${this.#keyManager.fingerprint})`,
    );
  }

  // ── Ephemeral helpers ────────────────────────────────────────
  #parseEphemeralTime(str) {
    const match = str.match(/^(\d+)(s|m|h)$/);
    if (!match) return null;
    const val = parseInt(match[1]);
    if (val <= 0) return null;
    const multiplier = { s: 1000, m: 60_000, h: 3_600_000 };
    return val * multiplier[match[2]];
  }

  #scheduleEphemeralRemoval(lineIndex, durationMs, nickname) {
    const timer = setTimeout(() => {
      this.#ui.removeLine(lineIndex);
      this.#ui.addSystemMessage(`Mensagem efemera de ${nickname} expirou`);
    }, durationMs);
    this.#ephemeralTimers.push(timer);
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

  // ── Handle ROOM_CHANGED (after /join) ──────────────────────
  #onRoomChanged(msg) {
    this.#currentRoom = msg.room;

    // Clear old peers and pins
    this.#peers.clear();
    this.#pinnedMessages = [];

    // Populate with new room peers
    for (const peer of msg.peers) {
      this.#peers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
      });

      // Register ratchet if new peer
      if (!this.#handshake.getRatchet(peer.sessionId)) {
        this.#handshake.registerPeer(peer.sessionId, peer.publicKey);
      }

      this.#checkTrust(peer.nickname, peer.publicKey);
    }

    const peerNames = [...this.#peers.values()].map((p) => p.nickname);
    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames(peerNames);
    this.#auditLog.log(AuditEvent.ROOM_CHANGED, { room: msg.room });
    this.#ui.addSystemMessage(`Voce entrou na sala #${msg.room}`);

    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }
  }

  // ── Handle ROOM_LIST ───────────────────────────────────────
  #onRoomList(msg) {
    this.#ui.addInfoMessage('Salas disponiveis:');
    for (const room of msg.rooms) {
      const current = room.name === this.#currentRoom ? ' (atual)' : '';
      this.#ui.addInfoMessage(`  #${room.name} — ${room.memberCount} membro(s)${current}`);
    }
  }

  // ── Handle PEER_KICKED ────────────────────────────────────
  #onPeerKicked(msg) {
    if (msg.nickname.toLowerCase() === this.#nickname.toLowerCase()) {
      const reason = msg.reason ? ` (motivo: ${msg.reason})` : '';
      this.#ui.addErrorMessage(`Voce foi expulso da sala${reason}`);
      this.#auditLog.log(AuditEvent.ADMIN_KICK, { nickname: msg.nickname, reason: msg.reason });
    } else {
      const reason = msg.reason ? ` (${msg.reason})` : '';
      this.#ui.addSystemMessage(`${msg.nickname} foi expulso da sala${reason}`);
      this.#auditLog.log(AuditEvent.ADMIN_KICK, { nickname: msg.nickname, reason: msg.reason });
    }
  }

  // ── Handle PEER_MUTED ─────────────────────────────────────
  #onPeerMuted(msg) {
    const duration = this.#formatDuration(msg.durationMs);
    if (msg.nickname.toLowerCase() === this.#nickname.toLowerCase()) {
      this.#ui.addErrorMessage(`Voce foi silenciado por ${duration}`);
      this.#auditLog.log(AuditEvent.ADMIN_MUTE, { nickname: msg.nickname, durationMs: msg.durationMs });
    } else {
      this.#ui.addSystemMessage(`${msg.nickname} foi silenciado por ${duration}`);
      this.#auditLog.log(AuditEvent.ADMIN_MUTE, { nickname: msg.nickname, durationMs: msg.durationMs });
    }
  }

  // ── Send encrypted command to all peers ────────────────────────
  #sendCommandToAll(action) {
    const payload = JSON.stringify({ action, sentAt: Date.now() });
    this.#broadcastPayload(payload);
  }

  // ── Broadcast encrypted payload to all peers ───────────────────
  #broadcastPayload(payload, deniable = false) {
    for (const [peerId] of this.#peers) {
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
      if (!peerPublicKey) {
        continue;
      }

      // Deniable path: crypto_secretbox (symmetric)
      if (deniable) {
        const nonce = this.#nonceManager.generate();
        const sharedKey = deriveSharedKey(this.#handshake.secretKey, peerPublicKey);
        const ciphertext = encryptDeniable(payload, nonce, sharedKey);
        const msg = createEncryptedMessage(
          this.#sessionId,
          peerId,
          ciphertext.toString('base64'),
          nonce.toString('base64'),
        );
        msg.payload.deniable = true;
        this.#connection.send(msg);
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

    const messageId = Math.random().toString(36).slice(2, 10);
    const msgObj = {
      text,
      sentAt: Date.now(),
      messageId,
    };

    if (this.#ephemeralMode) {
      msgObj.ephemeral = this.#ephemeralDurationMs;
    }
    if (this.#deniableMode) {
      msgObj.deniable = true;
    }

    this.#lastSentMessageId = messageId;
    this.#broadcastPayload(JSON.stringify(msgObj), this.#deniableMode);

    // Show own message locally
    const ephLabel = this.#ephemeralMode ? this.#formatDuration(this.#ephemeralDurationMs) : null;
    const { lineIndex } = this.#ui.addMessage(this.#nickname, text, false, ephLabel, this.#deniableMode);

    if (this.#ephemeralMode) {
      this.#scheduleEphemeralRemoval(lineIndex, this.#ephemeralDurationMs, this.#nickname);
    }
  }

  #formatDuration(ms) {
    if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)}h`;
    if (ms >= 60_000) return `${Math.round(ms / 60_000)}m`;
    return `${Math.round(ms / 1000)}s`;
  }

  // ── Send encrypted DM to one peer ────────────────────────────
  #sendMessageToPeer(peerId, peerNickname, text) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
    if (!peerPublicKey) {
      this.#ui.addErrorMessage(`Chave publica nao encontrada para ${peerNickname}`);
      return;
    }

    const payload = JSON.stringify({
      text,
      sentAt: Date.now(),
      messageId: Math.random().toString(36).slice(2, 10),
      isDM: true,
    });

    // Try ratchet path (PFS) first
    const ratchet = this.#handshake.getRatchet(peerId);
    if (ratchet && ratchet.isInitialized) {
      try {
        const result = ratchet.encrypt(payload);
        this.#connection.send(createRatchetedMessage(this.#sessionId, peerId, result));
        this.#ui.addMessage(`${this.#nickname} \u2192 ${peerNickname}`, text, true);
        return;
      } catch {
        // Fall through to static path
      }
    }

    // Static path fallback
    const nonce = this.#nonceManager.generate();
    const ciphertext = MessageCrypto.encrypt(payload, nonce, peerPublicKey, this.#handshake.secretKey);
    this.#connection.send(
      createEncryptedMessage(this.#sessionId, peerId, ciphertext.toString('base64'), nonce.toString('base64')),
    );
    this.#ui.addMessage(`${this.#nickname} \u2192 ${peerNickname}`, text, true);
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
    for (const timer of this.#ephemeralTimers) {
      clearTimeout(timer);
    }
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connection.close();
    this.#ui.destroy();
  }
}
