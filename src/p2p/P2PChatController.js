import sodium from 'sodium-native';
import notifier from 'node-notifier';
import { KEY_ROTATION_INTERVAL_MS, EMOJI_MAP } from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from '../client/FileTransfer.js';
import { AuditLog, AuditEvent } from '../shared/AuditLog.js';
import { deriveSharedKey, encryptDeniable, decryptDeniable } from '../crypto/DeniableEncrypt.js';

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

  constructor(nickname, peerServer, connManager, discovery, ui, keyManager, restoredState = null, pluginManager = null) {
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
    this.#auditLog = new AuditLog();
    this.#ephemeralMode = false;
    this.#ephemeralDurationMs = 0;
    this.#ephemeralTimers = [];
    this.#lastReceivedMessageId = null;
    this.#lastReceivedNickname = null;
    this.#lastSentMessageId = null;
    this.#messageAuthors = new Map();
    this.#pinnedMessages = [];
    this.#lastReceivedText = null;
    this.#deniableMode = false;
    this.#pluginManager = pluginManager;

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
    this.#ui.setPeerNames([...this.#peers.keys()]);
    this.#ui.addSystemMessage(`${nickname} conectado (P2P direto)`);
    this.#auditLog.log(AuditEvent.PEER_CONNECTED, { nickname });
  }

  // ── Peer disconnected ──────────────────────────────────────────
  #onPeerDisconnected(nickname) {
    this.#hidePeerTyping(nickname);
    this.#nonceManager.removePeer(nickname);
    this.#peers.delete(nickname);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames([...this.#peers.keys()]);
    this.#ui.addSystemMessage(`${nickname} desconectou`);
    this.#auditLog.log(AuditEvent.PEER_DISCONNECTED, { nickname });
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
    const isDeniable = !!msg.payload.deniable;

    // Deniable message path (symmetric crypto_secretbox)
    if (isDeniable) {
      const sharedKey = deriveSharedKey(this.#handshake.secretKey, senderPublicKey);
      plaintext = decryptDeniable(ciphertext, nonce, sharedKey);
      if (!plaintext) {
        this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: fromNickname, deniable: true });
        this.#ui.addErrorMessage(`Falha ao decifrar mensagem deniable de ${fromNickname}`);
        return;
      }
    }

    // Ratcheted path (has ephemeralPublicKey)
    if (!isDeniable && msg.payload.ephemeralPublicKey) {
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
          this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: fromNickname });
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
    } else if (!isDeniable) {
      // Static path (no ephemeralPublicKey)
      if (!this.#nonceManager.validate(fromNickname, nonce)) {
        this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: fromNickname });
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
      this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: fromNickname });
      this.#ui.addErrorMessage(`Falha ao decifrar mensagem de ${fromNickname} (MAC invalido)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));
      this.#handleDecryptedAction(fromNickname, data, isDeniable);
    } catch {
      this.#ui.addErrorMessage(`Payload invalido de ${fromNickname}`);
    } finally {
      if (plaintext && Buffer.isBuffer(plaintext)) {
        sodium.sodium_memzero(plaintext);
      }
    }
  }

  #handleDecryptedAction(fromNickname, data, isDeniable = false) {
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
      this.#auditLog.log(AuditEvent.KEY_ROTATION_PEER, { nickname: fromNickname });
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

    if (data.action === 'reaction') {
      this.#ui.addSystemMessage(`${data.emoji} ${fromNickname} reagiu a uma mensagem`);
      this.#ui.playNotification();
      return;
    }

    if (data.action === 'edit_message') {
      const author = this.#messageAuthors.get(data.messageId);
      if (author && author === fromNickname) {
        this.#ui.addSystemMessage(`${fromNickname} editou: ${data.newText} (editado)`);
      }
      return;
    }

    if (data.action === 'delete_message') {
      const author = this.#messageAuthors.get(data.messageId);
      if (author && author === fromNickname) {
        this.#ui.addSystemMessage(`${fromNickname} apagou uma mensagem`);
      }
      return;
    }

    if (data.action === 'pin_message') {
      this.#pinnedMessages.push({
        messageId: data.messageId,
        nickname: data.nickname,
        text: data.text,
        pinnedBy: fromNickname,
        pinnedAt: Date.now(),
      });
      this.#ui.addSystemMessage(`\uD83D\uDCCC ${fromNickname} fixou: "${data.text}" \u2014 ${data.nickname}`);
      return;
    }

    if (data.action === 'unpin_message') {
      this.#pinnedMessages = this.#pinnedMessages.filter((p) => p.messageId !== data.messageId);
      this.#ui.addSystemMessage(`${fromNickname} removeu fixacao`);
      return;
    }

    // Text message
    this.#hidePeerTyping(fromNickname);
    if (data.messageId) {
      this.#lastReceivedMessageId = data.messageId;
      this.#lastReceivedNickname = fromNickname;
      this.#lastReceivedText = data.text;
      this.#messageAuthors.set(data.messageId, fromNickname);
    }
    const ephLabel = data.ephemeral ? this.#formatDuration(data.ephemeral) : null;
    const { lineIndex } = this.#ui.addMessage(fromNickname, data.text, !!data.isDM, ephLabel, isDeniable || !!data.deniable);
    this.#ui.playNotification();

    if (data.ephemeral && data.ephemeral > 0) {
      this.#scheduleEphemeralRemoval(lineIndex, data.ephemeral, fromNickname);
    }

    if (this.#ui.notifyEnabled) {
      notifier.notify({
        title: data.isDM ? `DM de ${fromNickname}` : `${fromNickname} — CipherMesh`,
        message: data.text.slice(0, 100),
        sound: false,
      });
    }
  }

  // ── TOFU: Trust On First Use ───────────────────────────────────
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
          `AVISO: A chave de ${nickname} mudou! Use /trust ${nickname} para aceitar ou /verify ${nickname} para verificar.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#auditLog.log(AuditEvent.TRUST_VERIFIED_MISMATCH, { nickname });
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
        this.#ui.addInfoMessage('  /msg <nick> <texto>  - Envia mensagem privada (DM)');
        this.#ui.addInfoMessage('  /fingerprint         - Mostra seu fingerprint');
        this.#ui.addInfoMessage('  /fingerprint <nick>  - Fingerprint de outro peer');
        this.#ui.addInfoMessage('  /verify <nick>       - Codigo SAS para verificacao');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirma verificacao');
        this.#ui.addInfoMessage('  /trust <nick>        - Aceita nova chave');
        this.#ui.addInfoMessage('  /trustlist           - Status de confianca');
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
        this.#ui.addInfoMessage('  /kick, /mute, /ban   - (apenas modo servidor)');
        this.#ui.addInfoMessage('  /plugins             - Lista plugins carregados');
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
        const msgPeer = this.#findPeer(msgNick);
        if (!msgPeer) {
          this.#ui.addErrorMessage(`Peer "${msgNick}" nao encontrado`);
          break;
        }
        this.#sendMessageToPeer(msgPeer.nickname, msgText);
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

      case '/join':
      case '/rooms':
      case '/room':
        this.#ui.addErrorMessage('Salas nao estao disponiveis no modo P2P');
        break;

      case '/kick':
      case '/mute':
      case '/ban':
        this.#ui.addErrorMessage('Moderacao nao disponivel no modo P2P');
        break;

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

  // ── Ephemeral helpers ────────────────────────────────────────
  #parseEphemeralTime(str) {
    const match = str.match(/^(\d+)(s|m|h)$/);
    if (!match) return null;
    const val = parseInt(match[1]);
    if (val <= 0) return null;
    const multiplier = { s: 1000, m: 60_000, h: 3_600_000 };
    return val * multiplier[match[2]];
  }

  #formatDuration(ms) {
    if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)}h`;
    if (ms >= 60_000) return `${Math.round(ms / 60_000)}m`;
    return `${Math.round(ms / 1000)}s`;
  }

  #scheduleEphemeralRemoval(lineIndex, durationMs, nickname) {
    const timer = setTimeout(() => {
      this.#ui.removeLine(lineIndex);
      this.#ui.addSystemMessage(`Mensagem efemera de ${nickname} expirou`);
    }, durationMs);
    this.#ephemeralTimers.push(timer);
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

    this.#auditLog.log(AuditEvent.KEY_ROTATION_OWN, { fingerprint: this.#keyManager.fingerprint });
    this.#ui.addSystemMessage(
      `Chaves rotacionadas (novo fingerprint: ${this.#keyManager.fingerprint})`,
    );
  }

  // ── Send encrypted payload ─────────────────────────────────────
  #sendCommandToAll(action) {
    const payload = JSON.stringify({ action, sentAt: Date.now() });
    this.#broadcastPayload(payload);
  }

  #broadcastPayload(payload, deniable = false) {
    for (const [peerNickname] of this.#peers) {
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerNickname);
      if (!peerPublicKey) continue;

      // Deniable path: crypto_secretbox (symmetric)
      if (deniable) {
        const nonce = this.#nonceManager.generate();
        const sharedKey = deriveSharedKey(this.#handshake.secretKey, peerPublicKey);
        const ciphertext = encryptDeniable(payload, nonce, sharedKey);
        this.#connManager.send(peerNickname, {
          type: 'p2p_message',
          payload: {
            ciphertext: ciphertext.toString('base64'),
            nonce: nonce.toString('base64'),
            deniable: true,
          },
        });
        continue;
      }

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

    const messageId = Math.random().toString(36).slice(2, 10);
    const msgObj = {
      text,
      sentAt: Date.now(),
      messageId,
    };

    this.#lastSentMessageId = messageId;

    if (this.#ephemeralMode) {
      msgObj.ephemeral = this.#ephemeralDurationMs;
    }
    if (this.#deniableMode) {
      msgObj.deniable = true;
    }

    this.#broadcastPayload(JSON.stringify(msgObj), this.#deniableMode);

    const ephLabel = this.#ephemeralMode ? this.#formatDuration(this.#ephemeralDurationMs) : null;
    const { lineIndex } = this.#ui.addMessage(this.#nickname, text, false, ephLabel, this.#deniableMode);

    if (this.#ephemeralMode) {
      this.#scheduleEphemeralRemoval(lineIndex, this.#ephemeralDurationMs, this.#nickname);
    }
  }

  // ── Send encrypted DM to one peer ────────────────────────────
  #sendMessageToPeer(peerNickname, text) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerNickname);
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
        this.#ui.addMessage(`${this.#nickname} \u2192 ${peerNickname}`, text, true);
        return;
      } catch {
        // Fall through to static path
      }
    }

    // Static path fallback
    const nonce = this.#nonceManager.generate();
    const ciphertext = MessageCrypto.encrypt(payload, nonce, peerPublicKey, this.#handshake.secretKey);
    this.#connManager.send(peerNickname, {
      type: 'p2p_message',
      payload: {
        ciphertext: ciphertext.toString('base64'),
        nonce: nonce.toString('base64'),
      },
    });
    this.#ui.addMessage(`${this.#nickname} \u2192 ${peerNickname}`, text, true);
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
    for (const timer of this.#ephemeralTimers) clearTimeout(timer);
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connManager.destroy();
    this.#peerServer.stop();
    this.#discovery.stop();
    this.#ui.destroy();
  }
}
