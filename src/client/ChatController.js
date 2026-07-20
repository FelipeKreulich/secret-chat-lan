import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import sodium from 'sodium-native';
import notifier from 'node-notifier';
import qrcode from 'qrcode-terminal';
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
  ERR,
} from '../protocol/messages.js';
import { KEY_ROTATION_INTERVAL_MS, EMOJI_MAP, COVER_CONSTANT_MS } from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from './FileTransfer.js';
import { AuditLog, AuditEvent } from '../shared/AuditLog.js';
import { deriveSharedKey, encryptDeniable, decryptDeniable } from '../crypto/DeniableEncrypt.js';
import { buildInvite } from '../shared/invite.js';
import { exportBackup } from '../crypto/IdentityBackup.js';
import { keyArt } from '../shared/keyArt.js';
import { applyShortcodes } from '../shared/emoji.js';
import { isImageFile, renderImagePreview, loadImageBuffers } from './ImagePreview.js';
import { detectImageProtocol, encodeInlineImage } from '../shared/terminalGraphics.js';
import { suggestCommand } from '../shared/commandSuggest.js';
import { nextCoverDelay, coverPayload, isCover } from '../shared/coverTraffic.js';
import { recordVoiceNote, playVoiceNote, isAudioFile } from '../shared/voiceNote.js';
import { setTheme, getThemeName, themeNames } from '../shared/themes.js';
import { panicWipe } from '../shared/panic.js';
import { parseDndWindow, shouldNotify, nowMinutes, mentionsMe } from '../shared/dnd.js';
import { COMMANDS } from './UI.js';

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
  #pendingFileOffers = new Map(); // transferId -> { from, data, nickname }
  #lastImagePath = null; // last received image (for /img full-res render)
  #lastAudioPath = null; // last received voice note (for /play)
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
  #currentRoomOwner;
  #inviteRoom;
  #historyStore;
  #receiptsEnabled;
  #sentMessageLines; // Map<messageId, { lineIndex, baseLine }>
  #messageReaders; // Map<messageId, Set<nickname>>
  #away;
  #awayReason;
  #statusText;
  #coverMode; // 'off' | 'jitter' | 'constant'
  #coverTimer;
  #paceQueue;
  #dndMode = 'off'; // 'off' | 'mentions' | 'on'
  #dndWindow = null; // quiet-hours { start, end } in minutes, or null
  #autoAwayMs = 0; // idle timeout in ms (0 = off)
  #autoAwayTimer = null;
  #autoAwaySet = false; // whether the current away was set automatically

  constructor(
    nickname,
    connection,
    ui,
    restoredState = null,
    pluginManager = null,
    inviteRoom = null,
    historyStore = null,
  ) {
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
    if (restoredState?.trust) {
      this.#trustStore.importData(restoredState.trust);
    }
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
    this.#currentRoomOwner = null;
    this.#inviteRoom = inviteRoom;
    this.#historyStore = historyStore;
    this.#receiptsEnabled = true;
    this.#sentMessageLines = new Map();
    this.#messageReaders = new Map();
    this.#away = false;
    this.#awayReason = null;
    this.#statusText = null;
    this.#coverMode = 'off';
    this.#coverTimer = null;
    this.#paceQueue = [];

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
      this.#ui.setConnectionState('online');
      this.#connection.send(createJoin(this.#nickname, this.#keyManager.publicKeyB64));
    });

    this.#connection.on('disconnected', () => {
      this.#ui.setConnectionState('offline');
      this.#ui.setOnlineCount(0);
      this.#ui.addErrorMessage('Connection lost to the server');
    });

    this.#connection.on('reconnecting', (delay) => {
      this.#ui.setConnectionState('reconnecting');
      this.#ui.addSystemMessage(`Reconnecting in ${delay / 1000}s...`);
    });

    this.#connection.on('cert-pinned', ({ fingerprint }) => {
      const fp = fingerprint ? fingerprint.slice(0, 17) + '...' : '?';
      this.#ui.addSystemMessage(`Server certificate pinned (trust on first use): ${fp}`);
    });

    this.#connection.on('cert-mismatch', ({ got }) => {
      this.#ui.addErrorMessage(
        'ALERT: the server TLS certificate CHANGED since the last connection ' +
          `(possible MITM). Current fingerprint: ${got || '?'}. ` +
          'E2E verification (/verify) remains the definitive protection.',
      );
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

  // ── Auto-away (idle) ────────────────────────────────────────
  #noteActive() {
    // Coming back from an auto-set away → auto-return.
    if (this.#autoAwaySet && this.#away) {
      this.#away = false;
      this.#awayReason = null;
      this.#autoAwaySet = false;
      this.#ui.removeHeaderIndicator('away');
      this.#ui.addSystemMessage("You're back (auto)");
      this.#broadcastPresence();
    }
    this.#armAutoAway();
  }

  #armAutoAway() {
    if (this.#autoAwayTimer) {
      clearTimeout(this.#autoAwayTimer);
      this.#autoAwayTimer = null;
    }
    if (this.#autoAwayMs > 0) {
      this.#autoAwayTimer = setTimeout(() => this.#triggerAutoAway(), this.#autoAwayMs);
      if (this.#autoAwayTimer.unref) {
        this.#autoAwayTimer.unref();
      }
    }
  }

  #triggerAutoAway() {
    if (this.#away) {
      return; // already away (manual) — leave it
    }
    this.#away = true;
    this.#awayReason = 'away (idle)';
    this.#autoAwaySet = true;
    this.#ui.setHeaderIndicator('away', '{yellow-fg}[away]{/yellow-fg}');
    this.#ui.addSystemMessage('Auto-away: marked as away due to inactivity');
    this.#broadcastPresence();
  }

  // ── Typing indicator (outgoing) ─────────────────────────────
  #handleTypingActivity() {
    this.#noteActive();
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
        if (msg.code === ERR.NICKNAME_TAKEN) {
          this.#ui.addErrorMessage(
            `${msg.message}. Use /nick <other> to pick a different nickname.`,
          );
        } else {
          this.#ui.addErrorMessage(`Error: ${msg.message} (${msg.code})`);
        }
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
          `WARNING: ${nickname}'s key changed! Possible MITM attack. Use /trust ${nickname} to accept or /verify ${nickname} to verify.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#auditLog.log(AuditEvent.TRUST_VERIFIED_MISMATCH, { nickname });
        this.#ui.addErrorMessage(
          `ALERT: ${nickname}'s VERIFIED key changed! This may indicate an attack. Use /verify ${nickname} to re-verify.`,
        );
        break;
    }
  }

  // ── JOIN_ACK: registered with server ──────────────────────────
  #onJoinAck(msg) {
    this.#sessionId = msg.sessionId;
    this.#currentRoom = msg.room || 'general';
    this.#ui.setRoom(this.#currentRoom);
    this.#currentRoomOwner = msg.roomOwner || null;

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
    this.#ui.addSystemMessage('Connected to server with E2E encryption active');

    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }

    if (msg.queuedCount > 0) {
      this.#ui.addSystemMessage(`${msg.queuedCount} pending message(s) being delivered`);
    }

    // Invite included a room — join it once after the first connect
    if (this.#inviteRoom && this.#inviteRoom !== this.#currentRoom) {
      this.#connection.send(createChangeRoom(this.#inviteRoom));
      this.#inviteRoom = null;
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
    this.#ui.handshakeConnect(peer.nickname);
    this.#auditLog.log(AuditEvent.PEER_CONNECTED, { nickname: peer.nickname });

    // A newcomer doesn't know my presence — send only to them
    if (this.#away || this.#statusText) {
      this.#sendPayloadToPeer(peer.sessionId, this.#presencePayload());
    }
  }

  // ── Peer left ─────────────────────────────────────────────────
  #onPeerLeft(msg) {
    const peer = this.#peers.get(msg.sessionId);
    const nickname = peer?.nickname || msg.nickname || 'Unknown';

    this.#hidePeerTyping(msg.sessionId, nickname);
    this.#handshake.removePeer(msg.sessionId);
    this.#nonceManager.removePeer(msg.sessionId);
    this.#peers.delete(msg.sessionId);

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames([...this.#peers.values()].map((p) => p.nickname));
    this.#ui.addSystemMessage(`${nickname} left the chat`);
    this.#auditLog.log(AuditEvent.PEER_DISCONNECTED, { nickname });
  }

  // ── Received encrypted message ────────────────────────────────
  #onEncryptedMessage(msg) {
    const peer = this.#peers.get(msg.from);
    if (!peer) {
      this.#ui.addErrorMessage('Message from unknown peer');
      return;
    }

    const senderPublicKey = this.#handshake.getPeerPublicKey(msg.from);
    if (!senderPublicKey) {
      this.#ui.addErrorMessage(`Public key not found for ${peer.nickname}`);
      return;
    }

    const ciphertext = Buffer.from(msg.payload.ciphertext, 'base64');
    const nonce = Buffer.from(msg.payload.nonce, 'base64');

    let plaintext = null;
    const isDeniable = !!msg.payload.deniable;

    // Deniable message path (symmetric crypto_secretbox)
    if (isDeniable) {
      // Anti-replay: deniable sends already use a structured NonceManager nonce.
      if (!this.#nonceManager.validate(msg.from, nonce)) {
        this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: peer.nickname, deniable: true });
        this.#ui.addErrorMessage(`Invalid nonce from ${peer.nickname} (possible replay)`);
        return;
      }
      const sharedKey = deriveSharedKey(this.#handshake.secretKey, senderPublicKey);
      plaintext = decryptDeniable(ciphertext, nonce, sharedKey);
      if (!plaintext) {
        this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: peer.nickname, deniable: true });
        this.#ui.addErrorMessage(`Failed to decrypt deniable message from ${peer.nickname}`);
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
          this.#ui.addErrorMessage(`Failed to decrypt message from ${peer.nickname}`);
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
        this.#ui.addErrorMessage(`Invalid nonce from ${peer.nickname} (possible replay)`);
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
      this.#ui.addErrorMessage(`Failed to decrypt message from ${peer.nickname} (invalid MAC)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));

      // Cover traffic: a decoy — drop it silently (no UI, no history, no receipt).
      if (isCover(data)) {
        return;
      }

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
        this.#ui.addSystemMessage(`${peer.nickname} rotated keys`);
        return;
      }

      if (data.action === 'file_offer') {
        // Require explicit consent — do NOT start receiving automatically.
        this.#pendingFileOffers.set(data.transferId, {
          from: msg.from,
          data,
          nickname: peer.nickname,
        });
        const kb = (data.fileSize / 1024).toFixed(0);
        this.#ui.addSystemMessage(
          `${peer.nickname} wants to send "${data.fileName}" (${kb}KB). ` +
            `Use /accept ${data.transferId} or /reject ${data.transferId}.`,
        );
        this.#ui.playNotification();
        return;
      }

      if (data.action === 'file_accept') {
        this.#fileTransfer.handleFileAccept(msg.from, data);
        return;
      }

      if (data.action === 'file_reject') {
        this.#fileTransfer.handleFileReject(msg.from, data);
        this.#ui.finishProgress();
        return;
      }

      if (data.action === 'file_have') {
        this.#fileTransfer.handleFileHave(msg.from, data);
        return;
      }

      if (data.action === 'file_resume_request') {
        const resend = this.#fileTransfer.getChunksForResend(data.transferId, data.missing);
        if (resend && resend.length > 0) {
          for (const c of resend) {
            this.#sendPayloadToPeer(
              msg.from,
              JSON.stringify({
                action: 'file_chunk',
                transferId: data.transferId,
                chunkIndex: c.index,
                data: c.data,
                sentAt: Date.now(),
              }),
            );
          }
          this.#sendPayloadToPeer(
            msg.from,
            JSON.stringify({
              action: 'file_complete',
              transferId: data.transferId,
              sentAt: Date.now(),
            }),
          );
          this.#ui.addSystemMessage(
            `${peer.nickname} requested resend of ${resend.length} chunk(s) — resending`,
          );
        }
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
        this.#fileTransfer.handleFileComplete(msg.from, data).then(async (result) => {
          this.#ui.finishProgress();
          if (result.success) {
            this.#ui.addSystemMessage(result.message);
            if (result.savePath && isImageFile(result.savePath)) {
              this.#lastImagePath = result.savePath;
              try {
                const preview = await renderImagePreview(result.savePath);
                this.#ui.addImagePreview(preview);
              } catch {
                // Preview is best-effort — the file is already saved in downloads/
              }
              if (detectImageProtocol()) {
                this.#ui.addInfoMessage('Tip: /img to view this image in high resolution');
              }
            } else if (result.savePath && isAudioFile(result.savePath)) {
              this.#lastAudioPath = result.savePath;
              this.#ui.addInfoMessage('🔊 Voice note received — /play to listen');
            }
          } else if (result.resume) {
            // Lost chunks — request only what's missing
            this.#ui.addSystemMessage(result.message);
            this.#sendPayloadToPeer(
              msg.from,
              JSON.stringify({
                action: 'file_resume_request',
                transferId: data.transferId,
                missing: result.missing,
                sentAt: Date.now(),
              }),
            );
          } else {
            this.#ui.addErrorMessage(result.message);
          }
        });
        return;
      }

      if (data.action === 'read_receipt') {
        this.#onReadReceipt(peer.nickname, data.messageId);
        return;
      }

      if (data.action === 'presence') {
        const p = this.#peers.get(msg.from);
        if (p) {
          const wasAway = !!p.away;
          const oldStatus = p.status || null;
          p.away = !!data.away;
          p.awayReason = typeof data.reason === 'string' ? data.reason.slice(0, 60) : null;
          p.status = typeof data.status === 'string' ? data.status.slice(0, 60) : null;

          if (p.away && !wasAway) {
            const why = p.awayReason ? ` (${p.awayReason})` : '';
            this.#ui.addSystemMessage(`${peer.nickname} is away${why}`);
          } else if (!p.away && wasAway) {
            this.#ui.addSystemMessage(`${peer.nickname} is back`);
          }
          if (p.status && p.status !== oldStatus) {
            this.#ui.addSystemMessage(`${peer.nickname} set status: ${p.status}`);
          }
        }
        return;
      }

      if (data.action === 'reaction') {
        this.#ui.addSystemMessage(`${data.emoji} ${peer.nickname} reacted to a message`);
        this.#ui.playNotification();
        return;
      }

      if (data.action === 'edit_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (author && author === peer.nickname) {
          this.#ui.addSystemMessage(`${peer.nickname} edited: ${data.newText} (edited)`);
        }
        return;
      }

      if (data.action === 'delete_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (author && author === peer.nickname) {
          this.#ui.addSystemMessage(`${peer.nickname} deleted a message`);
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
        this.#ui.addSystemMessage(
          `\uD83D\uDCCC ${peer.nickname} pinned: "${data.text}" \u2014 ${data.nickname}`,
        );
        return;
      }

      if (data.action === 'unpin_message') {
        this.#pinnedMessages = this.#pinnedMessages.filter((p) => p.messageId !== data.messageId);
        this.#ui.addSystemMessage(`${peer.nickname} removed a pin`);
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
      // Persist to encrypted history — never ephemeral or deniable messages
      if (this.#historyStore?.isOpen && !data.ephemeral && !isDeniable && !data.deniable) {
        this.#historyStore.append({
          room: this.#currentRoom,
          nickname: peer.nickname,
          text: data.text,
          isDM: !!data.isDM,
        });
      }

      if (data.replyTo?.nickname && typeof data.replyTo.excerpt === 'string') {
        this.#ui.addQuoteLine(String(data.replyTo.nickname), data.replyTo.excerpt.slice(0, 80));
      }

      const mentioned = this.#mentionsMe(data.text) && !data.isDM;
      const ephLabel = data.ephemeral ? this.#formatDuration(data.ephemeral) : null;
      const { lineIndex } = this.#ui.addMessage(
        peer.nickname,
        data.text,
        !!data.isDM,
        ephLabel,
        isDeniable || !!data.deniable,
        mentioned,
      );
      const notify = shouldNotify(this.#dndMode, this.#dndWindow, nowMinutes(), mentioned);
      if (notify) {
        this.#ui.playNotification();
      }

      if (data.ephemeral && data.ephemeral > 0) {
        this.#scheduleEphemeralRemoval(lineIndex, data.ephemeral, peer.nickname);
      }

      // Confirm read to the author — E2EE payload, the server can't tell it from a message
      if (
        this.#receiptsEnabled &&
        data.messageId &&
        !data.ephemeral &&
        !isDeniable &&
        !data.deniable
      ) {
        this.#sendPayloadToPeer(
          msg.from,
          JSON.stringify({ action: 'read_receipt', messageId: data.messageId, sentAt: Date.now() }),
        );
      }

      // DND / mentions-only gates desktop notifications too.
      if (notify && (this.#ui.notifyEnabled || mentioned)) {
        notifier.notify({
          title: mentioned
            ? `🔔 ${peer.nickname} mentioned you`
            : data.isDM
              ? `DM from ${peer.nickname}`
              : `${peer.nickname} — CipherMesh`,
          message: data.text.slice(0, 100),
          sound: mentioned,
        });
      }
    } catch {
      this.#ui.addErrorMessage(`Invalid decrypted payload from ${peer.nickname}`);
    } finally {
      // Wipe plaintext buffer from memory (V8 strings from JSON.parse cannot be wiped)
      if (plaintext && Buffer.isBuffer(plaintext)) {
        sodium.sodium_memzero(plaintext);
      }
    }
  }

  // True if an incoming message references my nickname (@nick or standalone word).
  #mentionsMe(text) {
    return mentionsMe(text, this.#nickname);
  }

  // ── User input handling ───────────────────────────────────────
  #handleUserInput(text) {
    this.#noteActive();
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
        this.#ui.addInfoMessage('Available commands:');
        this.#ui.addInfoMessage('  /help                - Show this help');
        this.#ui.addInfoMessage('  /users               - List online users');
        this.#ui.addInfoMessage('  /msg <nick> <text>   - Send a private message (DM)');
        this.#ui.addInfoMessage('  /reply <text>        - Reply to the last received message');
        this.#ui.addInfoMessage('  /away [reason]       - Mark yourself as away');
        this.#ui.addInfoMessage('  /back                - Clear the away status');
        this.#ui.addInfoMessage('  /autoaway <min|off>  - Auto-away on inactivity');
        this.#ui.addInfoMessage('  /status <text|off>   - Set a status (accepts :emoji:)');
        this.#ui.addInfoMessage('  /join <room>         - Join a room');
        this.#ui.addInfoMessage('  /invite [host:port]  - Generate an invite with QR code');
        this.#ui.addInfoMessage('  /rooms               - List available rooms');
        this.#ui.addInfoMessage('  /room                - Show the current room');
        this.#ui.addInfoMessage('  /fingerprint         - Show your fingerprint');
        this.#ui.addInfoMessage("  /fingerprint <nick>  - Another user's fingerprint");
        this.#ui.addInfoMessage('  /verify <nick>       - Show SAS code for verification');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirm peer verification');
        this.#ui.addInfoMessage("  /trust <nick>        - Accept a peer's new key");
        this.#ui.addInfoMessage("  /trustlist           - Peers' trust status");
        this.#ui.addInfoMessage('  /clear               - Clear the chat');
        this.#ui.addInfoMessage('  /file <path>         - Send a file (max 50MB)');
        this.#ui.addInfoMessage(
          '  /voice [sec]         - Record and send a voice note (default 10s)',
        );
        this.#ui.addInfoMessage('  /play [path]         - Play the last received voice note');
        this.#ui.addInfoMessage('  /sound [on|off]      - Sound notifications');
        this.#ui.addInfoMessage('  /notify [on|off]     - Desktop notifications');
        this.#ui.addInfoMessage(
          '  /dnd [on|off|mentions|HH:MM-HH:MM] - Do not disturb / mentions only',
        );
        this.#ui.addInfoMessage('  /search <term>       - Search the encrypted local history');
        this.#ui.addInfoMessage('  /history [n]         - Last n messages from history');
        this.#ui.addInfoMessage('  /export [path]       - Export the history (.txt or .json)');
        this.#ui.addInfoMessage('  /audit [N]           - Show the last N audit events');
        this.#ui.addInfoMessage('  /ephemeral <time|off> - Ephemeral messages (e.g. 30s, 5m, 1h)');
        this.#ui.addInfoMessage('  /react <emoji>       - React to the last received message');
        this.#ui.addInfoMessage('  /edit <new text>     - Edit the last sent message');
        this.#ui.addInfoMessage('  /delete              - Delete the last sent message');
        this.#ui.addInfoMessage('  /pin                 - Pin the last received message');
        this.#ui.addInfoMessage('  /unpin               - Remove the last pin');
        this.#ui.addInfoMessage('  /pins                - List pinned messages');
        this.#ui.addInfoMessage('  /deniable [on|off]   - Deniable mode (symmetric crypto)');
        this.#ui.addInfoMessage('  /receipts [on|off]   - Read receipts (✓✓)');
        this.#ui.addInfoMessage('  /cover [on|constant|off] - Cover traffic (masks timing/volume)');
        this.#ui.addInfoMessage('  /kick <nick> [reason] - Kick a user from the room (owner)');
        this.#ui.addInfoMessage('  /mute <nick> [time]  - Mute a user (owner, default 5m)');
        this.#ui.addInfoMessage('  /ban <nick> [reason] - Ban a user from the room (owner)');
        this.#ui.addInfoMessage('  /owner               - Show the current room owner');
        this.#ui.addInfoMessage('  /theme [name]        - Nick color theme');
        this.#ui.addInfoMessage(
          '  /panic [yes]         - Wipe EVERYTHING from disk and exit (duress)',
        );
        this.#ui.addInfoMessage('  /plugins             - List loaded plugins');
        this.#ui.addInfoMessage('  /quit                - Leave the chat');
        this.#ui.addInfoMessage('Tip: PageUp/PageDown scroll the chat history');
        this.#ui.addInfoMessage('Tip: shortcodes like :fire: become emoji — Tab autocompletes');
        break;

      case '/users': {
        const names = [...this.#peers.values()].map((p) => {
          let label = p.nickname;
          if (p.away) {
            label += ` [away${p.awayReason ? `: ${p.awayReason}` : ''}]`;
          }
          if (p.status) {
            label += ` — ${p.status}`;
          }
          return label;
        });
        let me = `${this.#nickname} (you)`;
        if (this.#away) {
          me += ` [away${this.#awayReason ? `: ${this.#awayReason}` : ''}]`;
        }
        if (this.#statusText) {
          me += ` — ${this.#statusText}`;
        }
        this.#ui.addInfoMessage(
          `Online (${names.length + 1}): ${me}, ${names.join(', ') || 'no one else'}`,
        );
        break;
      }

      case '/fingerprint': {
        const targetNick = parts[1];
        if (!targetNick) {
          this.#ui.addInfoMessage(`Your fingerprint: ${this.#keyManager.fingerprint}`);
          this.#ui.addPlainLines(
            keyArt(Buffer.from(this.#keyManager.publicKeyB64, 'base64'), this.#nickname).split(
              '\n',
            ),
          );
        } else {
          const found = [...this.#peers.values()].find(
            (p) => p.nickname.toLowerCase() === targetNick.toLowerCase(),
          );
          if (found) {
            const fp = KeyManager.computeFingerprint(Buffer.from(found.publicKey, 'base64'));
            this.#ui.addInfoMessage(`${found.nickname}'s fingerprint: ${fp}`);
            this.#ui.addPlainLines(
              keyArt(Buffer.from(found.publicKey, 'base64'), found.nickname).split('\n'),
            );
          } else {
            this.#ui.addErrorMessage(`User "${targetNick}" not found`);
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
          this.#ui.addInfoMessage('Sound notifications disabled');
        } else if (arg === 'on') {
          this.#ui.setSoundEnabled(true);
          this.#ui.addInfoMessage('Sound notifications enabled');
        } else {
          const status = this.#ui.soundEnabled ? 'enabled' : 'disabled';
          this.#ui.addInfoMessage(`Sound: ${status}. Use /sound on or /sound off`);
        }
        break;
      }

      case '/verify': {
        const verifyNick = parts[1];
        if (!verifyNick) {
          this.#ui.addErrorMessage('Usage: /verify <nickname>');
          break;
        }
        const verifyPeer = [...this.#peers.values()].find(
          (p) => p.nickname.toLowerCase() === verifyNick.toLowerCase(),
        );
        if (!verifyPeer) {
          this.#ui.addErrorMessage(`User "${verifyNick}" not found`);
          break;
        }
        const sas = TrustStore.computeSAS(this.#keyManager.publicKeyB64, verifyPeer.publicKey);
        this.#auditLog.log(AuditEvent.SAS_VERIFY, { nickname: verifyPeer.nickname });
        this.#ui.addInfoMessage(`SAS code for ${verifyPeer.nickname}: ${sas}`);
        this.#ui.addPlainLines(
          keyArt(Buffer.from(verifyPeer.publicKey, 'base64'), verifyPeer.nickname).split('\n'),
        );
        this.#ui.addInfoMessage(
          'Compare the code (or the art) with the peer by voice or another channel. If it matches, use /verify-confirm ' +
            verifyPeer.nickname,
        );
        qrcode.generate(sas, { small: true }, (qr) => {
          this.#ui.addPlainLines(qr.split('\n'));
        });
        break;
      }

      case '/verify-confirm': {
        const confirmNick = parts[1];
        if (!confirmNick) {
          this.#ui.addErrorMessage('Usage: /verify-confirm <nickname>');
          break;
        }
        const confirmed = this.#trustStore.markVerified(confirmNick);
        if (confirmed) {
          this.#auditLog.log(AuditEvent.SAS_CONFIRM, { nickname: confirmNick });
          this.#ui.addSystemMessage(`${confirmNick} marked as verified`);
        } else {
          this.#ui.addErrorMessage(
            `Peer "${confirmNick}" not found in the trust store. The peer must be online first.`,
          );
        }
        break;
      }

      case '/trust': {
        const trustNick = parts[1];
        if (!trustNick) {
          this.#ui.addErrorMessage('Usage: /trust <nickname>');
          break;
        }
        const trustPeer = [...this.#peers.values()].find(
          (p) => p.nickname.toLowerCase() === trustNick.toLowerCase(),
        );
        if (!trustPeer) {
          this.#ui.addErrorMessage(`User "${trustNick}" is not online`);
          break;
        }
        this.#trustStore.updatePeer(trustPeer.nickname, trustPeer.publicKey);
        this.#ui.addSystemMessage(`${trustPeer.nickname}'s key accepted (verification reset)`);
        break;
      }

      case '/trustlist': {
        const peerList = [...this.#peers.values()];
        if (peerList.length === 0) {
          this.#ui.addInfoMessage('No peers online');
          break;
        }
        this.#ui.addInfoMessage('Trust status:');
        for (const p of peerList) {
          const record = this.#trustStore.getPeerRecord(p.nickname);
          let status;
          if (!record) {
            status = 'unknown';
          } else if (record.verified) {
            status = 'verified';
          } else {
            status = 'trusted (TOFU)';
          }
          this.#ui.addInfoMessage(`  ${p.nickname}: ${status}`);
        }
        break;
      }

      case '/file': {
        const filePath = parts.slice(1).join(' ');
        if (!filePath) {
          this.#ui.addErrorMessage('Usage: /file <path>');
          break;
        }
        if (this.#peers.size === 0) {
          this.#ui.addSystemMessage('No peers online to receive files');
          break;
        }
        this.#sendFile(filePath);
        break;
      }

      case '/notify': {
        const notifyArg = parts[1]?.toLowerCase();
        if (notifyArg === 'off') {
          this.#ui.setNotifyEnabled(false);
          this.#ui.addInfoMessage('Desktop notifications disabled');
        } else if (notifyArg === 'on') {
          this.#ui.setNotifyEnabled(true);
          this.#ui.addInfoMessage('Desktop notifications enabled');
        } else {
          const status = this.#ui.notifyEnabled ? 'enabled' : 'disabled';
          this.#ui.addInfoMessage(
            `Desktop notifications: ${status}. Use /notify on or /notify off`,
          );
        }
        break;
      }

      case '/msg': {
        const msgNick = parts[1];
        if (!msgNick) {
          this.#ui.addErrorMessage('Usage: /msg <nick> <text>');
          break;
        }
        const msgText = parts.slice(2).join(' ');
        if (!msgText) {
          this.#ui.addErrorMessage('Usage: /msg <nick> <text>');
          break;
        }
        const msgPeer = [...this.#peers.entries()].find(
          ([, p]) => p.nickname.toLowerCase() === msgNick.toLowerCase(),
        );
        if (!msgPeer) {
          this.#ui.addErrorMessage(`User "${msgNick}" not found`);
          break;
        }
        this.#sendMessageToPeer(msgPeer[0], msgPeer[1].nickname, msgText);
        break;
      }

      case '/join': {
        const roomName = parts[1];
        if (!roomName) {
          this.#ui.addErrorMessage('Usage: /join <room>');
          break;
        }
        this.#connection.send(createChangeRoom(roomName));
        break;
      }

      case '/rooms':
        this.#connection.send(createListRooms());
        break;

      case '/invite': {
        let hostPort = parts[1];
        if (!hostPort) {
          hostPort = (this.#connection.url || '').replace(/^wss?:\/\//, '');
        }
        const inviteUri = buildInvite(hostPort, this.#currentRoom);
        if (!inviteUri) {
          this.#ui.addErrorMessage('Invalid address. Usage: /invite [host:port]');
          break;
        }
        if (/^(localhost|127\.)/.test(hostPort)) {
          this.#ui.addErrorMessage(
            'You are connected via localhost — this invite only works on your own machine.',
          );
          this.#ui.addInfoMessage(
            'Pass the address the peer can reach: /invite <ip>:<port> (e.g. Tailscale IP)',
          );
        }
        this.#ui.addInfoMessage(`Invite: ${inviteUri}`);
        this.#ui.addInfoMessage(
          'The peer pastes this string (or scans the QR) at the "Server" prompt',
        );
        qrcode.generate(inviteUri, { small: true }, (qr) => {
          this.#ui.addPlainLines(qr.split('\n'));
        });
        break;
      }

      case '/room':
        this.#ui.addInfoMessage(`Current room: #${this.#currentRoom}`);
        break;

      case '/deniable': {
        const denArg = parts[1]?.toLowerCase();
        if (denArg === 'off') {
          this.#deniableMode = false;
          this.#ui.removeHeaderIndicator('deniable');
          this.#ui.addInfoMessage('Deniable mode disabled');
        } else if (denArg === 'on') {
          this.#deniableMode = true;
          this.#ui.setHeaderIndicator('deniable', '{magenta-fg}[D]{/magenta-fg}');
          this.#ui.addInfoMessage(
            'Deniable mode enabled (symmetric crypto — plausible deniability)',
          );
        } else {
          const status = this.#deniableMode ? 'enabled' : 'disabled';
          this.#ui.addInfoMessage(`Deniable mode: ${status}. Use /deniable on or /deniable off`);
        }
        break;
      }

      case '/away': {
        this.#away = true;
        this.#autoAwaySet = false; // an explicit /away is not auto
        this.#awayReason = applyShortcodes(parts.slice(1).join(' ')).slice(0, 60) || null;
        this.#ui.setHeaderIndicator('away', '{yellow-fg}[away]{/yellow-fg}');
        this.#ui.addInfoMessage(
          this.#awayReason ? `You are away: ${this.#awayReason}` : 'You are away',
        );
        this.#broadcastPresence();
        break;
      }

      case '/back': {
        if (!this.#away) {
          this.#ui.addInfoMessage('You are not away');
          break;
        }
        this.#away = false;
        this.#awayReason = null;
        this.#autoAwaySet = false;
        this.#ui.removeHeaderIndicator('away');
        this.#ui.addInfoMessage("You're back");
        this.#broadcastPresence();
        break;
      }

      case '/autoaway': {
        const aaArg = parts[1]?.toLowerCase();
        if (aaArg === 'off' || aaArg === '0') {
          this.#autoAwayMs = 0;
          this.#armAutoAway();
          this.#ui.addInfoMessage('Auto-away disabled');
        } else {
          const min = parseInt(aaArg, 10);
          if (!Number.isInteger(min) || min < 1 || min > 240) {
            this.#ui.addInfoMessage(
              `Auto-away: ${this.#autoAwayMs ? `${this.#autoAwayMs / 60000}min` : 'off'}. Usage: /autoaway <minutes|off>`,
            );
            break;
          }
          this.#autoAwayMs = min * 60_000;
          this.#armAutoAway();
          this.#ui.addInfoMessage(`Auto-away after ${min}min of inactivity`);
        }
        break;
      }

      case '/status': {
        const statusArg = parts.slice(1).join(' ');
        if (!statusArg || statusArg.toLowerCase() === 'off') {
          this.#statusText = null;
          this.#ui.addInfoMessage('Status cleared');
        } else {
          this.#statusText = applyShortcodes(statusArg).slice(0, 60);
          this.#ui.addInfoMessage(`Status: ${this.#statusText}`);
        }
        this.#broadcastPresence();
        break;
      }

      case '/reply': {
        const replyText = parts.slice(1).join(' ');
        if (!replyText) {
          this.#ui.addErrorMessage('Usage: /reply <text>');
          break;
        }
        if (!this.#lastReceivedMessageId || !this.#lastReceivedText) {
          this.#ui.addErrorMessage('No message to reply to');
          break;
        }
        const excerpt =
          this.#lastReceivedText.length > 60
            ? `${this.#lastReceivedText.slice(0, 57)}...`
            : this.#lastReceivedText;
        this.#sendMessageToAll(replyText, {
          messageId: this.#lastReceivedMessageId,
          nickname: this.#lastReceivedNickname,
          excerpt,
        });
        break;
      }

      case '/receipts': {
        const receiptsArg = parts[1]?.toLowerCase();
        if (receiptsArg === 'off') {
          this.#receiptsEnabled = false;
          this.#ui.addInfoMessage('Read receipts disabled — you no longer send read confirmations');
        } else if (receiptsArg === 'on') {
          this.#receiptsEnabled = true;
          this.#ui.addInfoMessage('Read receipts enabled');
        } else {
          const receiptsStatus = this.#receiptsEnabled ? 'enabled' : 'disabled';
          this.#ui.addInfoMessage(
            `Read receipts: ${receiptsStatus}. Use /receipts on or /receipts off`,
          );
        }
        break;
      }

      case '/dnd': {
        const dndArg = parts[1]?.toLowerCase();
        if (!dndArg) {
          const win = this.#dndWindow ? ' + quiet window' : '';
          this.#ui.addInfoMessage(
            `DND: ${this.#dndMode}${win}. Usage: /dnd on | off | mentions | HH:MM-HH:MM`,
          );
        } else if (dndArg === 'on' || dndArg === 'off' || dndArg === 'mentions') {
          this.#dndMode = dndArg;
          if (dndArg === 'off' && !this.#dndWindow) {
            this.#ui.removeHeaderIndicator('dnd');
          } else {
            this.#ui.setHeaderIndicator('dnd', '{yellow-fg}[🔕]{/yellow-fg}');
          }
          this.#ui.addInfoMessage(
            dndArg === 'mentions'
              ? 'DND: mentions only notify'
              : dndArg === 'on'
                ? 'DND: total silence'
                : 'DND disabled',
          );
        } else {
          const win = parseDndWindow(dndArg);
          if (!win) {
            this.#ui.addErrorMessage('Invalid format. Usage: /dnd HH:MM-HH:MM (e.g. 22:00-08:00)');
            break;
          }
          this.#dndWindow = win;
          this.#ui.setHeaderIndicator('dnd', '{yellow-fg}[🔕]{/yellow-fg}');
          this.#ui.addInfoMessage(`Quiet hours ${dndArg} — mentions only during the window`);
        }
        break;
      }

      case '/cover': {
        const coverArg = parts[1]?.toLowerCase();
        if (coverArg === 'on' || coverArg === 'jitter') {
          this.#setCoverMode('jitter');
          this.#ui.setHeaderIndicator('cover', '{cyan-fg}[C]{/cyan-fg}');
          this.#ui.addInfoMessage(
            'Cover traffic (jitter) enabled — encrypted decoys at random intervals',
          );
        } else if (coverArg === 'constant') {
          this.#setCoverMode('constant');
          this.#ui.setHeaderIndicator('cover', '{cyan-fg}[C=]{/cyan-fg}');
          this.#ui.addInfoMessage(
            'Cover traffic (constant rate) enabled — uniform encrypted flow; ' +
              'your messages go out in the next slot (up to ~3s delay)',
          );
        } else if (coverArg === 'off') {
          this.#setCoverMode('off');
          this.#ui.removeHeaderIndicator('cover');
          this.#ui.addInfoMessage('Cover traffic disabled');
        } else {
          this.#ui.addInfoMessage(
            `Cover traffic: ${this.#coverMode}. Use /cover on (jitter), /cover constant or /cover off`,
          );
        }
        break;
      }

      case '/search': {
        if (!this.#historyStore?.isOpen) {
          this.#ui.addErrorMessage('History disabled — start the client with a passphrase');
          break;
        }
        const term = parts.slice(1).join(' ');
        if (!term) {
          this.#ui.addErrorMessage('Usage: /search <term>');
          break;
        }
        const results = this.#historyStore.search(term);
        if (results.length === 0) {
          this.#ui.addInfoMessage(`Nothing found for "${term}"`);
          break;
        }
        this.#ui.addInfoMessage(`${results.length} result(s) for "${term}":`);
        for (const e of results) {
          this.#ui.addInfoMessage(`  ${this.#formatHistoryEntry(e)}`);
        }
        break;
      }

      case '/history': {
        if (!this.#historyStore?.isOpen) {
          this.#ui.addErrorMessage('History disabled — start the client with a passphrase');
          break;
        }
        const count = parseInt(parts[1]) || 20;
        const entries = this.#historyStore.recent(count);
        if (entries.length === 0) {
          this.#ui.addInfoMessage('History empty');
          break;
        }
        this.#ui.addInfoMessage(`Last ${entries.length} message(s) from history:`);
        for (const e of entries) {
          this.#ui.addInfoMessage(`  ${this.#formatHistoryEntry(e)}`);
        }
        break;
      }

      case '/export': {
        if (!this.#historyStore?.isOpen) {
          this.#ui.addErrorMessage('History disabled — start the client with a passphrase');
          break;
        }
        if (this.#historyStore.size === 0) {
          this.#ui.addInfoMessage('History empty, nothing to export');
          break;
        }
        let target = parts.slice(1).join(' ');
        if (!target) {
          const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
          target = `exports/ciphermesh-${stamp}.txt`;
        }
        try {
          const fullPath = resolve(target);
          mkdirSync(dirname(fullPath), { recursive: true });
          const count = this.#historyStore.exportTo(fullPath);
          this.#ui.addSystemMessage(`${count} message(s) exported to ${fullPath}`);
          this.#ui.addErrorMessage('Warning: the exported file is in plain text');
        } catch (err) {
          this.#ui.addErrorMessage(`Export failed: ${err.message}`);
        }
        break;
      }

      case '/audit': {
        const auditCount = parseInt(parts[1]) || 20;
        const events = this.#auditLog.readLast(auditCount);
        if (events.length === 0) {
          this.#ui.addInfoMessage('No audit events recorded');
        } else {
          this.#ui.addInfoMessage(`Last ${events.length} audit event(s):`);
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
          this.#ui.addErrorMessage('Usage: /react <emoji>  (e.g. :fire: :thumbsup: :heart:)');
          break;
        }
        if (!this.#lastReceivedMessageId) {
          this.#ui.addErrorMessage('No message to react to');
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
        this.#ui.addSystemMessage(
          `${emoji} You reacted to ${this.#lastReceivedNickname}'s message`,
        );
        break;
      }

      case '/edit': {
        const editText = parts.slice(1).join(' ');
        if (!editText) {
          this.#ui.addErrorMessage('Usage: /edit <new text>');
          break;
        }
        if (!this.#lastSentMessageId) {
          this.#ui.addErrorMessage('No message to edit');
          break;
        }
        const editPayload = JSON.stringify({
          action: 'edit_message',
          messageId: this.#lastSentMessageId,
          newText: editText,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(editPayload);
        this.#ui.addSystemMessage(`You edited: ${editText} (edited)`);
        break;
      }

      case '/delete': {
        if (!this.#lastSentMessageId) {
          this.#ui.addErrorMessage('No message to delete');
          break;
        }
        const deletePayload = JSON.stringify({
          action: 'delete_message',
          messageId: this.#lastSentMessageId,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(deletePayload);
        this.#lastSentMessageId = null;
        this.#ui.addSystemMessage('You deleted a message');
        break;
      }

      case '/pin': {
        if (!this.#lastReceivedMessageId || !this.#lastReceivedText) {
          this.#ui.addErrorMessage('No message to pin');
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
        this.#ui.addSystemMessage(
          `\uD83D\uDCCC You pinned: "${this.#lastReceivedText}" \u2014 ${this.#lastReceivedNickname}`,
        );
        break;
      }

      case '/unpin': {
        if (this.#pinnedMessages.length === 0) {
          this.#ui.addErrorMessage('No pinned messages');
          break;
        }
        const removed = this.#pinnedMessages.pop();
        const unpinPayload = JSON.stringify({
          action: 'unpin_message',
          messageId: removed.messageId,
          sentAt: Date.now(),
        });
        this.#broadcastPayload(unpinPayload);
        this.#ui.addSystemMessage('You removed the pin');
        break;
      }

      case '/pins': {
        if (this.#pinnedMessages.length === 0) {
          this.#ui.addInfoMessage('No pinned messages');
        } else {
          this.#ui.addInfoMessage('Pinned messages:');
          for (const pin of this.#pinnedMessages) {
            this.#ui.addInfoMessage(
              `  \uD83D\uDCCC "${pin.text}" \u2014 ${pin.nickname} (pinned by ${pin.pinnedBy})`,
            );
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
          this.#ui.addInfoMessage('Ephemeral mode disabled');
        } else {
          const ms = this.#parseEphemeralTime(ephArg);
          if (!ms) {
            this.#ui.addErrorMessage('Invalid format. Use: 30s, 5m, 1h or off');
            break;
          }
          if (ms > 3_600_000) {
            this.#ui.addErrorMessage('Maximum: 1h (3600s)');
            break;
          }
          this.#ephemeralMode = true;
          this.#ephemeralDurationMs = ms;
          this.#ui.setHeaderIndicator('ephemeral', `{yellow-fg}[E ${ephArg}]{/yellow-fg}`);
          this.#ui.addInfoMessage(`Ephemeral mode enabled: ${ephArg}`);
        }
        break;
      }

      case '/kick': {
        const kickNick = parts[1];
        if (!kickNick) {
          this.#ui.addErrorMessage('Usage: /kick <nick> [reason]');
          break;
        }
        const kickReason = parts.slice(2).join(' ');
        this.#connection.send(createKickPeer(kickNick, kickReason));
        break;
      }

      case '/mute': {
        const muteNick = parts[1];
        if (!muteNick) {
          this.#ui.addErrorMessage('Usage: /mute <nick> [time]');
          break;
        }
        const muteTimeStr = parts[2] || '5m';
        const muteDuration = this.#parseEphemeralTime(muteTimeStr);
        if (!muteDuration) {
          this.#ui.addErrorMessage('Invalid time format. Use: 30s, 5m, 1h');
          break;
        }
        this.#connection.send(createMutePeer(muteNick, muteDuration));
        break;
      }

      case '/ban': {
        const banNick = parts[1];
        if (!banNick) {
          this.#ui.addErrorMessage('Usage: /ban <nick> [reason]');
          break;
        }
        const banReason = parts.slice(2).join(' ');
        this.#connection.send(createBanPeer(banNick, banReason));
        break;
      }

      case '/owner': {
        if (this.#currentRoom === 'general') {
          this.#ui.addInfoMessage('The #general room has no owner');
        } else if (this.#currentRoomOwner) {
          const isYou =
            this.#currentRoomOwner.toLowerCase() === this.#nickname.toLowerCase() ? ' (you)' : '';
          this.#ui.addInfoMessage(
            `Owner of room #${this.#currentRoom}: ${this.#currentRoomOwner}${isYou}`,
          );
        } else {
          this.#ui.addInfoMessage(`Room #${this.#currentRoom} has no owner`);
        }
        break;
      }

      case '/plugins': {
        if (!this.#pluginManager || this.#pluginManager.pluginCount === 0) {
          this.#ui.addInfoMessage('No plugins loaded. Place .js files in ~/.ciphermesh/plugins/');
        } else {
          const names = this.#pluginManager.getPluginNames();
          this.#ui.addInfoMessage(`Plugins loaded (${names.length}): ${names.join(', ')}`);
          const cmds = this.#pluginManager.getCommandNames();
          if (cmds.length > 0) {
            this.#ui.addInfoMessage(`Commands: ${cmds.join(', ')}`);
          }
        }
        break;
      }

      case '/accept': {
        const pending = parts[1]
          ? this.#pendingFileOffers.get(parts[1])
          : this.#pendingFileOffers.values().next().value;
        if (!pending) {
          this.#ui.addErrorMessage('No pending file offer.');
          break;
        }
        const offer = this.#fileTransfer.handleFileOffer(
          pending.from,
          pending.data,
          pending.nickname,
        );
        this.#ui.addSystemMessage(`Accepting: ${offer.message}`);
        this.#sendPayloadToPeer(
          pending.from,
          JSON.stringify({
            action: 'file_accept',
            transferId: pending.data.transferId,
            have: offer.have,
            sentAt: Date.now(),
          }),
        );
        this.#pendingFileOffers.delete(pending.data.transferId);
        break;
      }

      case '/reject': {
        const pending = parts[1]
          ? this.#pendingFileOffers.get(parts[1])
          : this.#pendingFileOffers.values().next().value;
        if (!pending) {
          this.#ui.addErrorMessage('No pending file offer.');
          break;
        }
        this.#sendPayloadToPeer(
          pending.from,
          JSON.stringify({
            action: 'file_reject',
            transferId: pending.data.transferId,
            sentAt: Date.now(),
          }),
        );
        this.#pendingFileOffers.delete(pending.data.transferId);
        this.#ui.addSystemMessage(`Offer from ${pending.nickname} rejected.`);
        break;
      }

      case '/img': {
        const imgPath = parts.slice(1).join(' ').trim() || this.#lastImagePath;
        if (!imgPath) {
          this.#ui.addErrorMessage('No recent image. Usage: /img [path]');
          break;
        }
        const protocol = detectImageProtocol();
        if (!protocol) {
          this.#ui.addInfoMessage(
            `Your terminal doesn't support inline images (kitty/iTerm2). File saved at: ${imgPath}`,
          );
          break;
        }
        loadImageBuffers(imgPath)
          .then((bufs) => {
            const widthCells = Math.min((process.stdout.columns || 80) - 4, 80);
            this.#ui.showRealImage(encodeInlineImage(protocol, bufs, { widthCells }));
          })
          .catch((e) => this.#ui.addErrorMessage(`Could not render: ${e.message}`));
        break;
      }

      case '/voice': {
        const secs = Math.min(60, Math.max(1, parseInt(parts[1]) || 10));
        if (this.#peers.size === 0) {
          this.#ui.addSystemMessage('No peers online to receive the voice note');
          break;
        }
        this.#ui.addSystemMessage(`🎤 Recording voice note for ${secs}s... (speak now)`);
        recordVoiceNote(tmpdir(), secs, Date.now())
          .then((path) => {
            this.#ui.addSystemMessage('Sending voice note...');
            this.#sendFile(path);
          })
          .catch((e) => this.#ui.addErrorMessage(`Voice note: ${e.message}`));
        break;
      }

      case '/play': {
        const audioPath = parts.slice(1).join(' ').trim() || this.#lastAudioPath;
        if (!audioPath) {
          this.#ui.addErrorMessage('No recent voice note. Usage: /play [path]');
          break;
        }
        this.#ui.addSystemMessage('🔊 Playing voice note...');
        playVoiceNote(audioPath).catch((e) => this.#ui.addErrorMessage(`Play: ${e.message}`));
        break;
      }

      case '/theme': {
        const themeArg = parts[1]?.toLowerCase();
        if (!themeArg) {
          this.#ui.addInfoMessage(
            `Current theme: ${getThemeName()}. Available: ${themeNames().join(', ')}`,
          );
        } else if (themeNames().includes(themeArg)) {
          setTheme(themeArg);
          this.#ui.addInfoMessage(
            `Theme "${themeArg}" applied — new messages use the new nick colors`,
          );
        } else {
          this.#ui.addErrorMessage(`Unknown theme. Available: ${themeNames().join(', ')}`);
        }
        break;
      }

      case '/backup': {
        const path = parts.slice(1).join(' ').trim() || './ciphermesh-backup.json';
        if (!this.#passphrase) {
          this.#ui.addErrorMessage(
            'The backup is encrypted with the session passphrase — restart and set a passphrase.',
          );
          break;
        }
        try {
          const envelope = exportBackup(
            {
              identity: this.#keyManager.serialize(),
              trust: this.#trustStore.exportData(),
            },
            this.#passphrase,
          );
          writeFileSync(resolve(path), envelope, { encoding: 'utf-8', mode: 0o600 });
          this.#ui.addSystemMessage(
            `Identity + trust backup saved to ${path} (encrypted). ` +
              'Restore it on another machine at startup.',
          );
        } catch (e) {
          this.#ui.addErrorMessage(`Failed to save backup: ${e.message}`);
        }
        break;
      }

      case '/nick': {
        const newNick = (parts[1] || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
        if (newNick.length < 1 || newNick.length > 20) {
          this.#ui.addErrorMessage('Usage: /nick <new> (1-20 characters: a-z, 0-9, _, -)');
          break;
        }
        if (this.#sessionId) {
          this.#ui.addErrorMessage("Can't change nickname after joining — reconnect to change it.");
          break;
        }
        // Only useful before a successful JOIN (e.g. recovering from
        // "nickname taken"): the server still accepts a JOIN on this socket.
        this.#nickname = newNick;
        this.#ui.setNickname(newNick);
        this.#connection.send(createJoin(newNick, this.#keyManager.publicKeyB64));
        this.#ui.addSystemMessage(`Trying to join as ${newNick}...`);
        break;
      }

      case '/retention': {
        if (!this.#historyStore?.isOpen) {
          this.#ui.addErrorMessage('History is not active (open the session with a passphrase).');
          break;
        }
        const ms = this.#parseRetentionTime(parts[1]?.toLowerCase());
        if (!ms) {
          this.#ui.addErrorMessage(
            'Usage: /retention <time> (e.g. 7d, 24h, 30m) — wipes history older than that from disk',
          );
          break;
        }
        const removed = this.#historyStore.purgeOlderThan(ms);
        this.#ui.addSystemMessage(
          `Retention applied: ${removed} old message(s) removed from local history.`,
        );
        break;
      }

      case '/panic': {
        const panicArg = parts[1]?.toLowerCase();
        if (panicArg === 'sim' || panicArg === 'yes' || panicArg === 'wipe') {
          this.#doPanic();
        } else {
          this.#ui.addErrorMessage(
            'PANIC wipes EVERYTHING from disk (session, history, trust, keys) and exits. ' +
              'Confirm with /panic yes',
          );
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
        const suggestion = suggestCommand(cmd, COMMANDS);
        const hint = suggestion ? ` Did you mean ${suggestion}?` : ' Use /help';
        this.#ui.addErrorMessage(`Unknown command: ${cmd}.${hint}`);
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
    this.#ui.addSystemMessage(`Keys rotated (new fingerprint: ${this.#keyManager.fingerprint})`);
  }

  // ── Ephemeral helpers ────────────────────────────────────────
  #parseEphemeralTime(str) {
    const match = str.match(/^(\d+)(s|m|h)$/);
    if (!match) {
      return null;
    }
    const val = parseInt(match[1]);
    if (val <= 0) {
      return null;
    }
    const multiplier = { s: 1000, m: 60_000, h: 3_600_000 };
    return val * multiplier[match[2]];
  }

  // Like #parseEphemeralTime but also supports days (for /retention).
  #parseRetentionTime(str) {
    if (!str) {
      return null;
    }
    const match = str.match(/^(\d+)(m|h|d)$/);
    if (!match) {
      return null;
    }
    const val = parseInt(match[1]);
    if (val <= 0) {
      return null;
    }
    const multiplier = { m: 60_000, h: 3_600_000, d: 86_400_000 };
    return val * multiplier[match[2]];
  }

  #scheduleEphemeralRemoval(lineIndex, durationMs, nickname) {
    const timer = setTimeout(() => {
      this.#ui.burnLine(lineIndex, () => {
        this.#ui.addSystemMessage(`Ephemeral message from ${nickname} burned`);
      });
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
    this.#ui.addSystemMessage(`${peer.nickname} updated key (via server — unauthenticated)`);
  }

  // ── Handle ROOM_CHANGED (after /join) ──────────────────────
  #onRoomChanged(msg) {
    this.#currentRoom = msg.room;
    this.#ui.setRoom(this.#currentRoom);
    this.#currentRoomOwner = msg.roomOwner || null;

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
    this.#ui.addSystemMessage(`You joined room #${msg.room}`);

    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }

    // The new room doesn't know my presence
    if (this.#away || this.#statusText) {
      this.#broadcastPresence();
    }
  }

  // ── Handle ROOM_LIST ───────────────────────────────────────
  #onRoomList(msg) {
    this.#ui.addInfoMessage('Available rooms:');
    for (const room of msg.rooms) {
      const current = room.name === this.#currentRoom ? ' (current)' : '';
      this.#ui.addInfoMessage(`  #${room.name} — ${room.memberCount} member(s)${current}`);
    }
  }

  // ── Handle PEER_KICKED ────────────────────────────────────
  #onPeerKicked(msg) {
    if (msg.nickname.toLowerCase() === this.#nickname.toLowerCase()) {
      const reason = msg.reason ? ` (reason: ${msg.reason})` : '';
      this.#ui.addErrorMessage(`You were kicked from the room${reason}`);
      this.#auditLog.log(AuditEvent.ADMIN_KICK, { nickname: msg.nickname, reason: msg.reason });
    } else {
      const reason = msg.reason ? ` (${msg.reason})` : '';
      this.#ui.addSystemMessage(`${msg.nickname} was kicked from the room${reason}`);
      this.#auditLog.log(AuditEvent.ADMIN_KICK, { nickname: msg.nickname, reason: msg.reason });
    }
  }

  // ── Handle PEER_MUTED ─────────────────────────────────────
  #onPeerMuted(msg) {
    const duration = this.#formatDuration(msg.durationMs);
    if (msg.nickname.toLowerCase() === this.#nickname.toLowerCase()) {
      this.#ui.addErrorMessage(`You were muted for ${duration}`);
      this.#auditLog.log(AuditEvent.ADMIN_MUTE, {
        nickname: msg.nickname,
        durationMs: msg.durationMs,
      });
    } else {
      this.#ui.addSystemMessage(`${msg.nickname} was muted for ${duration}`);
      this.#auditLog.log(AuditEvent.ADMIN_MUTE, {
        nickname: msg.nickname,
        durationMs: msg.durationMs,
      });
    }
  }

  // ── Presence ─────────────────────────────────────────────────
  #presencePayload() {
    return JSON.stringify({
      action: 'presence',
      away: this.#away,
      reason: this.#awayReason,
      status: this.#statusText,
      sentAt: Date.now(),
    });
  }

  #broadcastPresence() {
    this.#broadcastPayload(this.#presencePayload());
  }

  // ── Read receipts ────────────────────────────────────────────
  #onReadReceipt(nickname, messageId) {
    const tracked = this.#sentMessageLines.get(messageId);
    if (!tracked) {
      return;
    }

    let readers = this.#messageReaders.get(messageId);
    if (!readers) {
      readers = new Set();
      this.#messageReaders.set(messageId, readers);
    }
    if (readers.has(nickname)) {
      return;
    }
    readers.add(nickname);

    const marker = readers.size > 1 ? `✓✓ ${readers.size}` : '✓✓';
    this.#ui.appendBadge(tracked.lineIndex, tracked.baseLine, `{green-fg}${marker}{/green-fg}`);
  }

  #trackSentMessage(messageId, lineIndex) {
    const baseLine = this.#ui.getLine(lineIndex);
    if (baseLine === null || baseLine === undefined) {
      return;
    }
    this.#sentMessageLines.set(messageId, { lineIndex, baseLine });

    // Bound memory: keep only the most recent 200 tracked messages
    if (this.#sentMessageLines.size > 200) {
      const oldest = this.#sentMessageLines.keys().next().value;
      this.#sentMessageLines.delete(oldest);
      this.#messageReaders.delete(oldest);
    }
  }

  // ── Send encrypted payload to a single peer ────────────────────
  #sendPayloadToPeer(peerId, payload) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
    if (!peerPublicKey) {
      return;
    }

    const ratchet = this.#handshake.getRatchet(peerId);
    if (ratchet && ratchet.isInitialized) {
      try {
        const result = ratchet.encrypt(payload);
        this.#connection.send(createRatchetedMessage(this.#sessionId, peerId, result));
        return;
      } catch {
        // Fall through to static path
      }
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

  // ── Send encrypted command to all peers ────────────────────────
  #sendCommandToAll(action) {
    const payload = JSON.stringify({ action, sentAt: Date.now() });
    this.#broadcastPayload(payload);
  }

  // ── Cover traffic ──────────────────────────────────────────────
  #setCoverMode(mode) {
    this.#clearCoverTimer();
    this.#flushPace(); // never strand queued real messages when leaving a mode
    this.#coverMode = mode;
    if (mode === 'jitter') {
      this.#scheduleJitterDecoy();
    } else if (mode === 'constant') {
      this.#coverTimer = setInterval(() => this.coverTick(), COVER_CONSTANT_MS);
      if (this.#coverTimer.unref) {
        this.#coverTimer.unref();
      }
    }
  }

  #scheduleJitterDecoy() {
    const tick = () => {
      if (this.#coverMode === 'jitter') {
        this.sendCoverNow();
        this.#coverTimer = setTimeout(tick, nextCoverDelay());
        if (this.#coverTimer.unref) {
          this.#coverTimer.unref();
        }
      }
    };
    this.#coverTimer = setTimeout(tick, nextCoverDelay());
    if (this.#coverTimer.unref) {
      this.#coverTimer.unref();
    }
  }

  #clearCoverTimer() {
    if (this.#coverTimer) {
      clearTimeout(this.#coverTimer);
      clearInterval(this.#coverTimer);
      this.#coverTimer = null;
    }
  }

  #stopCover() {
    this.#clearCoverTimer();
    this.#flushPace();
    this.#coverMode = 'off';
  }

  // One constant-rate slot: send a queued real message if there is one, else a
  // decoy — so the wire cadence is identical whether or not you're chatting.
  coverTick() {
    const item = this.#paceQueue.shift();
    if (item) {
      this.#broadcastPayload(item.payload, item.deniable);
    } else {
      this.sendCoverNow();
    }
  }

  // Route an outgoing payload: paced through slots in constant mode, immediate
  // otherwise.
  #paceOrSend(payload, deniable = false) {
    if (this.#coverMode === 'constant') {
      this.#paceQueue.push({ payload, deniable });
    } else {
      this.#broadcastPayload(payload, deniable);
    }
  }

  #flushPace() {
    while (this.#paceQueue.length > 0) {
      const { payload, deniable } = this.#paceQueue.shift();
      this.#broadcastPayload(payload, deniable);
    }
  }

  // Sends a single decoy immediately (used by tests and by the timers).
  sendCoverNow() {
    if (this.#connection.connected && this.#peers.size > 0) {
      this.#broadcastPayload(coverPayload(Date.now()));
    }
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
        this.#ui.finishProgress();
        this.#ui.addErrorMessage(text);
      },
      onComplete: (text) => {
        this.#ui.finishProgress();
        this.#ui.addSystemMessage(text);
      },
    });
  }

  // ── Send encrypted message to all peers ───────────────────────
  #sendMessageToAll(text, replyTo = null) {
    if (!this.#connection.connected) {
      this.#ui.addErrorMessage('No connection to the server — message not sent');
      return;
    }
    if (this.#peers.size === 0) {
      this.#ui.addSystemMessage('No peers online to receive messages');
      return;
    }

    text = applyShortcodes(text);
    const messageId = Math.random().toString(36).slice(2, 10);
    const msgObj = {
      text,
      sentAt: Date.now(),
      messageId,
    };
    if (replyTo) {
      msgObj.replyTo = replyTo;
    }

    if (this.#ephemeralMode) {
      msgObj.ephemeral = this.#ephemeralDurationMs;
    }
    if (this.#deniableMode) {
      msgObj.deniable = true;
    }

    this.#lastSentMessageId = messageId;
    this.#paceOrSend(JSON.stringify(msgObj), this.#deniableMode);

    if (this.#historyStore?.isOpen && !this.#ephemeralMode && !this.#deniableMode) {
      this.#historyStore.append({
        room: this.#currentRoom,
        nickname: this.#nickname,
        text,
        isDM: false,
      });
    }

    // Show own message locally
    if (replyTo) {
      this.#ui.addQuoteLine(replyTo.nickname, replyTo.excerpt, true);
    }
    const ephLabel = this.#ephemeralMode ? this.#formatDuration(this.#ephemeralDurationMs) : null;
    const { lineIndex } = this.#ui.addMessage(
      this.#nickname,
      text,
      false,
      ephLabel,
      this.#deniableMode,
    );

    if (this.#ephemeralMode) {
      this.#scheduleEphemeralRemoval(lineIndex, this.#ephemeralDurationMs, this.#nickname);
    } else if (!this.#deniableMode) {
      this.#trackSentMessage(messageId, lineIndex);
    }
  }

  #formatHistoryEntry(e) {
    const when = new Date(e.ts).toLocaleString('en-US', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
    const dm = e.isDM ? ' (DM)' : '';
    return `[${when}] [#${e.room}]${dm} ${e.nickname}: ${e.text}`;
  }

  #formatDuration(ms) {
    if (ms >= 3_600_000) {
      return `${Math.round(ms / 3_600_000)}h`;
    }
    if (ms >= 60_000) {
      return `${Math.round(ms / 60_000)}m`;
    }
    return `${Math.round(ms / 1000)}s`;
  }

  // ── Send encrypted DM to one peer ────────────────────────────
  #sendMessageToPeer(peerId, peerNickname, text) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
    if (!peerPublicKey) {
      this.#ui.addErrorMessage(`Public key not found for ${peerNickname}`);
      return;
    }

    text = applyShortcodes(text);

    if (this.#historyStore?.isOpen) {
      this.#historyStore.append({
        room: this.#currentRoom,
        nickname: `${this.#nickname} → ${peerNickname}`,
        text,
        isDM: true,
      });
    }

    const messageId = Math.random().toString(36).slice(2, 10);
    const payload = JSON.stringify({
      text,
      sentAt: Date.now(),
      messageId,
      isDM: true,
    });

    this.#sendPayloadToPeer(peerId, payload);
    const { lineIndex } = this.#ui.addMessage(
      `${this.#nickname} \u2192 ${peerNickname}`,
      text,
      true,
    );
    this.#trackSentMessage(messageId, lineIndex);
  }

  // ── Panic / duress wipe ──────────────────────────────────────
  #doPanic() {
    panicWipe({
      historyStore: this.#historyStore,
      trustStore: this.#trustStore,
      auditLog: this.#auditLog,
    });
    this.#passphrase = null; // never re-save state on the way out
    try {
      this.#handshake.destroy();
    } catch {
      /* best effort */
    }
    try {
      this.#keyManager.destroy();
    } catch {
      /* best effort */
    }
    this.#ui.clearChat();
    this.#ui.addSystemMessage('PANIC: session, history, trust, and keys wiped. Exiting...');
    setTimeout(() => process.exit(0), 60);
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
    this.#stopCover();
    if (this.#autoAwayTimer) {
      clearTimeout(this.#autoAwayTimer);
    }
    for (const timer of this.#peerTypingTimers.values()) {
      clearTimeout(timer);
    }
    for (const timer of this.#ephemeralTimers) {
      clearTimeout(timer);
    }
    if (this.#historyStore) {
      this.#historyStore.destroy();
    }
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connection.close();
    this.#ui.destroy();
  }
}
