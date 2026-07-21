import sodium from 'sodium-native';
import notifier from 'node-notifier';
import qrcode from 'qrcode-terminal';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { exportBackup } from '../crypto/IdentityBackup.js';
import { keyArt } from '../shared/keyArt.js';
import {
  KEY_ROTATION_INTERVAL_MS,
  EMOJI_MAP,
  OFFLINE_QUEUE_MAX_PER_PEER,
  OFFLINE_QUEUE_MAX_AGE_MS,
  COVER_CONSTANT_MS,
} from '../shared/constants.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { Handshake } from '../crypto/Handshake.js';
import { NonceManager } from '../crypto/NonceManager.js';
import * as MessageCrypto from '../crypto/MessageCrypto.js';
import { TrustStore, TrustResult } from '../crypto/TrustStore.js';
import { FileTransfer } from '../client/FileTransfer.js';
import { isImageFile, renderImagePreview, loadImageBuffers } from '../client/ImagePreview.js';
import { detectImageProtocol, encodeInlineImage } from '../shared/terminalGraphics.js';
import { AuditLog, AuditEvent } from '../shared/AuditLog.js';
import { deriveSharedKey, encryptDeniable, decryptDeniable } from '../crypto/DeniableEncrypt.js';
import { GroupSession } from '../crypto/SenderKey.js';
import { suggestCommand } from '../shared/commandSuggest.js';
import { nextCoverDelay, coverPayload, isCover } from '../shared/coverTraffic.js';
import { recordVoiceNote, playVoiceNote, isAudioFile } from '../shared/voiceNote.js';
import { setTheme, getThemeName, themeNames } from '../shared/themes.js';
import { panicWipe } from '../shared/panic.js';
import { farewellBanner } from '../shared/banner.js';
import { parseDndWindow, shouldNotify, nowMinutes, mentionsMe } from '../shared/dnd.js';
import { trustBadge } from '../shared/trust.js';
import { tipAt, TIPS } from '../shared/tips.js';
import { COMMANDS } from '../client/UI.js';

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
  #pendingFileOffers = new Map(); // transferId -> { data, nickname }
  #verifyNudged = new Set(); // peers already nudged to /verify this session
  #tipIndex = -1; // rotates through TIPS for /tips
  #knownPeers = new Set(); // nicknames seen this session (for store-and-forward)
  #sfQueue = new Map(); // nickname -> [{ payload, queuedAt }] for offline peers
  #currentRoom = 'general';
  #peerRooms = new Map(); // nickname -> room (last announced)
  #groups = new Map(); // room -> GroupSession (sender keys)
  #groupBuffer = new Map(); // sender -> group msgs awaiting the sender's key
  #dndMode = 'off'; // 'off' | 'mentions' | 'on'
  #dndWindow = null; // quiet-hours { start, end } in minutes, or null
  #lastImagePath = null; // last received image (for /img full-res render)
  #lastAudioPath = null; // last received voice note (for /play)
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
  #coverMode; // 'off' | 'jitter' | 'constant'
  #coverTimer;
  #paceQueue;
  #pluginManager;

  constructor(
    nickname,
    peerServer,
    connManager,
    discovery,
    ui,
    keyManager,
    restoredState = null,
    pluginManager = null,
  ) {
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
    if (restoredState?.trust) {
      this.#trustStore.importData(restoredState.trust);
    }
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
    this.#coverMode = 'off';
    this.#coverTimer = null;
    this.#paceQueue = [];
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
    this.#ui.handshakeConnect(nickname);
    this.#nudgeVerify(nickname);
    this.#auditLog.log(AuditEvent.PEER_CONNECTED, { nickname });

    this.#knownPeers.add(nickname);
    // Tell the new peer which room we're in (and default them to general).
    this.#peerRooms.set(nickname, this.#peerRooms.get(nickname) || 'general');
    this.#broadcastPayload(
      JSON.stringify({ action: 'room_announce', room: this.#currentRoom, sentAt: Date.now() }),
      false,
      nickname,
    );
    this.#flushSFQueue(nickname);
  }

  // One-time-per-session nudge to verify an unverified peer's identity.
  #nudgeVerify(nickname) {
    const key = nickname.toLowerCase();
    if (this.#trustStore.isVerified(nickname) || this.#verifyNudged.has(key)) {
      return;
    }
    this.#verifyNudged.add(key);
    this.#ui.addSystemMessage(
      `🔑 ${nickname} is unverified — run /verify ${nickname} to confirm their identity`,
    );
  }

  // ── Store-and-forward (P2P) ──────────────────────────────────
  #enqueueSF(nickname, payload) {
    let queue = this.#sfQueue.get(nickname);
    if (!queue) {
      queue = [];
      this.#sfQueue.set(nickname, queue);
    }
    queue.push({ payload, queuedAt: Date.now() });
    if (queue.length > OFFLINE_QUEUE_MAX_PER_PEER) {
      queue.shift(); // drop the oldest
    }
  }

  #flushSFQueue(nickname) {
    const queue = this.#sfQueue.get(nickname);
    if (!queue || queue.length === 0) {
      return;
    }
    this.#sfQueue.delete(nickname);

    const now = Date.now();
    let delivered = 0;
    for (const item of queue) {
      if (now - item.queuedAt > OFFLINE_QUEUE_MAX_AGE_MS) {
        continue; // expired
      }
      // Re-encrypt with the peer's current ratchet and send only to them.
      this.#broadcastPayload(item.payload, false, nickname);
      delivered++;
    }
    if (delivered > 0) {
      this.#ui.addSystemMessage(`${delivered} pending message(s) delivered to ${nickname}.`);
    }
  }

  // ── Peer disconnected ──────────────────────────────────────────
  #onPeerDisconnected(nickname) {
    this.#hidePeerTyping(nickname);
    this.#nonceManager.removePeer(nickname);
    const wasInMyRoom = (this.#peerRooms.get(nickname) || 'general') === this.#currentRoom;
    this.#peers.delete(nickname);
    this.#groupBuffer.delete(nickname);
    for (const group of this.#groups.values()) {
      group.removeMember(nickname);
    }
    // Forward secrecy: someone left my room → rotate my sender key so they
    // can't read my future messages, and redistribute to who's left.
    if (wasInMyRoom && this.#groups.has(this.#currentRoom)) {
      this.#getGroup(this.#currentRoom).rotate();
      this.#distributeSenderKey(this.#currentRoom);
    }

    this.#ui.setOnlineCount(this.#peers.size + 1);
    this.#ui.setPeerNames([...this.#peers.keys()]);
    this.#ui.handshakeDisconnect(nickname);
    this.#auditLog.log(AuditEvent.PEER_DISCONNECTED, { nickname });
  }

  // ── Handle message from peer ───────────────────────────────────
  #onPeerMessage(fromNickname, msg) {
    if (msg.type === 'p2p_group') {
      this.#onGroupMessage(fromNickname, msg);
      return;
    }
    if (msg.type !== 'p2p_message') {
      return;
    }

    const peer = this.#peers.get(fromNickname);
    if (!peer) {
      return;
    }

    const senderPublicKey = this.#handshake.getPeerPublicKey(fromNickname);
    if (!senderPublicKey) {
      return;
    }

    const ciphertext = Buffer.from(msg.payload.ciphertext, 'base64');
    const nonce = Buffer.from(msg.payload.nonce, 'base64');

    let plaintext = null;
    const isDeniable = !!msg.payload.deniable;

    // Deniable message path (symmetric crypto_secretbox)
    if (isDeniable) {
      // Anti-replay: deniable sends already use a structured NonceManager nonce.
      if (!this.#nonceManager.validate(fromNickname, nonce)) {
        this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: fromNickname, deniable: true });
        this.#ui.addErrorMessage(`Invalid nonce from ${fromNickname} (possible replay)`);
        return;
      }
      const sharedKey = deriveSharedKey(this.#handshake.secretKey, senderPublicKey);
      plaintext = decryptDeniable(ciphertext, nonce, sharedKey);
      if (!plaintext) {
        this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: fromNickname, deniable: true });
        this.#ui.addErrorMessage(`Failed to decrypt deniable message from ${fromNickname}`);
        return;
      }
    }

    // Ratcheted path (has ephemeralPublicKey)
    if (!isDeniable && msg.payload.ephemeralPublicKey) {
      const ratchet = this.#handshake.getRatchet(fromNickname);
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
        if (!this.#nonceManager.validate(fromNickname, nonce)) {
          this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: fromNickname });
          this.#ui.addErrorMessage(`Failed to decrypt message from ${fromNickname}`);
          return;
        }
        plaintext = MessageCrypto.decryptWithFallback(
          ciphertext,
          nonce,
          senderPublicKey,
          this.#handshake.secretKey,
          this.#handshake.getPreviousPeerPublicKey(fromNickname),
          this.#handshake.previousSecretKey,
        );
      }
    } else if (!isDeniable) {
      // Static path (no ephemeralPublicKey)
      if (!this.#nonceManager.validate(fromNickname, nonce)) {
        this.#auditLog.log(AuditEvent.NONCE_REPLAY, { nickname: fromNickname });
        this.#ui.addErrorMessage(`Invalid nonce from ${fromNickname}`);
        return;
      }
      plaintext = MessageCrypto.decryptWithFallback(
        ciphertext,
        nonce,
        senderPublicKey,
        this.#handshake.secretKey,
        this.#handshake.getPreviousPeerPublicKey(fromNickname),
        this.#handshake.previousSecretKey,
      );
    }

    if (!plaintext) {
      this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: fromNickname });
      this.#ui.addErrorMessage(`Failed to decrypt message from ${fromNickname} (invalid MAC)`);
      return;
    }

    try {
      const data = JSON.parse(plaintext.toString('utf-8'));
      this.#handleDecryptedAction(fromNickname, data, isDeniable);
    } catch {
      this.#ui.addErrorMessage(`Invalid payload from ${fromNickname}`);
    } finally {
      if (plaintext && Buffer.isBuffer(plaintext)) {
        sodium.sodium_memzero(plaintext);
      }
    }
  }

  #handleDecryptedAction(fromNickname, data, isDeniable = false) {
    const peer = this.#peers.get(fromNickname);

    // Cover traffic: a decoy — drop it silently (no UI, no history, no receipt).
    if (isCover(data)) {
      return;
    }

    if (data.action === 'clear') {
      this.#ui.clearChat();
      return;
    }

    if (data.action === 'typing') {
      this.#showPeerTyping(fromNickname);
      return;
    }

    if (data.action === 'sk_dist') {
      this.#getGroup(data.room).addMember(fromNickname, data.dist);
      this.#flushGroupBuffer(fromNickname, data.room);
      return;
    }

    if (data.action === 'room_announce') {
      const prev = this.#peerRooms.get(fromNickname);
      const room = data.room || 'general';
      this.#peerRooms.set(fromNickname, room);
      // They're now in my room — give them my sender key (before any group msg).
      if (room === this.#currentRoom) {
        this.#distributeSenderKey(this.#currentRoom, fromNickname);
      }
      if (prev !== undefined && prev !== room) {
        if (room === this.#currentRoom) {
          this.#ui.addSystemMessage(`${fromNickname} joined room #${room}`);
        } else if (prev === this.#currentRoom) {
          // They left my room — rotate so they can't read my future messages.
          this.#ui.addSystemMessage(`${fromNickname} left for room #${room}`);
          this.#getGroup(this.#currentRoom).rotate();
          this.#distributeSenderKey(this.#currentRoom);
        }
      }
      return;
    }

    if (data.action === 'key_rotation') {
      this.#handshake.updatePeerKey(fromNickname, data.newPublicKey);
      if (peer) {
        peer.publicKey = data.newPublicKey;
      }
      this.#trustStore.autoUpdatePeer(fromNickname, data.newPublicKey);
      this.#auditLog.log(AuditEvent.KEY_ROTATION_PEER, { nickname: fromNickname });
      this.#ui.addSystemMessage(`${fromNickname} rotated keys`);
      return;
    }

    if (data.action === 'file_offer') {
      // Require explicit consent — do NOT start receiving automatically.
      this.#pendingFileOffers.set(data.transferId, { data, nickname: fromNickname });
      const kb = (data.fileSize / 1024).toFixed(0);
      this.#ui.addSystemMessage(
        `${fromNickname} wants to send "${data.fileName}" (${kb}KB). ` +
          `Use /accept ${data.transferId} or /reject ${data.transferId}.`,
      );
      this.#ui.playNotification();
      return;
    }

    if (data.action === 'file_accept') {
      this.#fileTransfer.handleFileAccept(fromNickname, data);
      return;
    }

    if (data.action === 'file_reject') {
      this.#fileTransfer.handleFileReject(fromNickname, data);
      this.#ui.finishProgress();
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
      this.#fileTransfer.handleFileComplete(fromNickname, data).then(async (result) => {
        this.#ui.finishProgress();
        if (!result.success) {
          this.#ui.addErrorMessage(result.message);
          return;
        }
        this.#ui.addSystemMessage(result.message);
        if (result.savePath && isImageFile(result.savePath)) {
          this.#lastImagePath = result.savePath;
          try {
            this.#ui.addImagePreview(await renderImagePreview(result.savePath));
          } catch {
            // preview is best-effort
          }
          if (detectImageProtocol()) {
            this.#ui.addInfoMessage('Tip: /img to view this image in full resolution');
          }
        } else if (result.savePath && isAudioFile(result.savePath)) {
          this.#lastAudioPath = result.savePath;
          this.#ui.addInfoMessage('🔊 Voice note received — /play to listen');
        }
      });
      return;
    }

    if (data.action === 'reaction') {
      this.#ui.addSystemMessage(`${data.emoji} ${fromNickname} reacted to a message`);
      this.#ui.playNotification();
      return;
    }

    if (data.action === 'edit_message') {
      const author = this.#messageAuthors.get(data.messageId);
      if (author && author === fromNickname) {
        this.#ui.addSystemMessage(`${fromNickname} edited: ${data.newText} (edited)`);
      }
      return;
    }

    if (data.action === 'delete_message') {
      const author = this.#messageAuthors.get(data.messageId);
      if (author && author === fromNickname) {
        this.#ui.addSystemMessage(`${fromNickname} deleted a message`);
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
      this.#ui.addSystemMessage(
        `\uD83D\uDCCC ${fromNickname} pinned: "${data.text}" \u2014 ${data.nickname}`,
      );
      return;
    }

    if (data.action === 'unpin_message') {
      this.#pinnedMessages = this.#pinnedMessages.filter((p) => p.messageId !== data.messageId);
      this.#ui.addSystemMessage(`${fromNickname} removed a pin`);
      return;
    }

    // Text message — ignore if it belongs to a different room (defense in depth;
    // room-scoped sends already avoid delivering it, but a room change could race).
    if (data.room && data.room !== this.#currentRoom && !data.isDM) {
      return;
    }
    this.#hidePeerTyping(fromNickname);
    if (data.messageId) {
      this.#lastReceivedMessageId = data.messageId;
      this.#lastReceivedNickname = fromNickname;
      this.#lastReceivedText = data.text;
      this.#messageAuthors.set(data.messageId, fromNickname);
    }
    const mentioned = mentionsMe(data.text, this.#nickname) && !data.isDM;
    const ephLabel = data.ephemeral ? this.#formatDuration(data.ephemeral) : null;
    const trust = trustBadge(
      this.#trustStore.getPeerRecord(fromNickname),
      this.#findPeer(fromNickname)?.publicKey,
    );
    const { lineIndex } = this.#ui.addMessage(
      fromNickname,
      data.text,
      !!data.isDM,
      ephLabel,
      isDeniable || !!data.deniable,
      mentioned,
      trust,
    );
    const notify = shouldNotify(this.#dndMode, this.#dndWindow, nowMinutes(), mentioned);
    if (notify) {
      this.#ui.playNotification();
    }

    if (data.ephemeral && data.ephemeral > 0) {
      this.#scheduleEphemeralRemoval(lineIndex, data.ephemeral, fromNickname);
    }

    if (notify && (this.#ui.notifyEnabled || mentioned)) {
      notifier.notify({
        title: mentioned
          ? `🔔 ${fromNickname} mentioned you`
          : data.isDM
            ? `DM from ${fromNickname}`
            : `${fromNickname} — CipherMesh`,
        message: data.text.slice(0, 100),
        sound: mentioned,
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
          `WARNING: ${nickname}'s key changed! Use /trust ${nickname} to accept or /verify ${nickname} to verify.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#auditLog.log(AuditEvent.TRUST_VERIFIED_MISMATCH, { nickname });
        this.#ui.addErrorMessage(
          `ALERT: ${nickname}'s VERIFIED key changed! Use /verify ${nickname} to re-verify.`,
        );
        break;
    }
  }

  // ── Typing indicator ──────────────────────────────────────────
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

  #showPeerTyping(nickname) {
    const existing = this.#peerTypingTimers.get(nickname);
    if (existing) {
      clearTimeout(existing);
    }

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
        this.#ui.addInfoMessage('Available commands (P2P mode):');
        this.#ui.addInfoMessage('  /help                - Show this help');
        this.#ui.addInfoMessage('  /tips                - Show a security/UX tip');
        this.#ui.addInfoMessage('  /users               - List connected peers');
        this.#ui.addInfoMessage('  /msg <nick> <text>   - Send a private message (DM)');
        this.#ui.addInfoMessage('  /fingerprint         - Show your fingerprint');
        this.#ui.addInfoMessage("  /fingerprint <nick>  - Another peer's fingerprint");
        this.#ui.addInfoMessage('  /verify <nick>       - SAS code for verification');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirm verification');
        this.#ui.addInfoMessage('  /trust <nick>        - Accept a new key');
        this.#ui.addInfoMessage('  /trustlist           - Trust status');
        this.#ui.addInfoMessage('  (✓ = verified peer · ✗ = key changed — shown next to a name)');
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
        this.#ui.addInfoMessage('  /audit [N]           - Show the last N audit events');
        this.#ui.addInfoMessage('  /ephemeral <time|off> - Ephemeral messages (e.g. 30s, 5m, 1h)');
        this.#ui.addInfoMessage('  /react <emoji>       - React to the last received message');
        this.#ui.addInfoMessage('  /edit <new text>     - Edit your last sent message');
        this.#ui.addInfoMessage('  /delete              - Delete your last sent message');
        this.#ui.addInfoMessage('  /pin                 - Pin the last received message');
        this.#ui.addInfoMessage('  /unpin               - Remove the last pin');
        this.#ui.addInfoMessage('  /pins                - List pinned messages');
        this.#ui.addInfoMessage('  /deniable [on|off]   - Deniable mode (symmetric crypto)');
        this.#ui.addInfoMessage('  /cover [on|constant|off] - Cover traffic (masks timing/volume)');
        this.#ui.addInfoMessage('  /kick, /mute, /ban   - (server mode only)');
        this.#ui.addInfoMessage('  /theme [name]        - Nick color theme');
        this.#ui.addInfoMessage(
          '  /panic [yes]         - Wipe EVERYTHING from disk and exit (duress)',
        );
        this.#ui.addInfoMessage('  /plugins             - List loaded plugins');
        this.#ui.addInfoMessage('  /quit                - Exit the chat');
        break;

      case '/users': {
        const names = [...this.#peers.keys()];
        this.#ui.addInfoMessage(
          `Online (${names.length + 1}): ${this.#nickname} (you), ${names.join(', ') || 'nobody else'}`,
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
          const found = this.#findPeer(targetNick);
          if (found) {
            const fp = KeyManager.computeFingerprint(Buffer.from(found.publicKey, 'base64'));
            this.#ui.addInfoMessage(`${found.nickname}'s fingerprint: ${fp}`);
            this.#ui.addPlainLines(
              keyArt(Buffer.from(found.publicKey, 'base64'), found.nickname).split('\n'),
            );
          } else {
            this.#ui.addErrorMessage(`Peer "${targetNick}" not found`);
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
        const verifyPeer = this.#findPeer(verifyNick);
        if (!verifyPeer) {
          this.#ui.addErrorMessage(`Peer "${verifyNick}" not found`);
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
          this.#ui.addErrorMessage(`Peer "${confirmNick}" not found in trust store.`);
        }
        break;
      }

      case '/trust': {
        const trustNick = parts[1];
        if (!trustNick) {
          this.#ui.addErrorMessage('Usage: /trust <nickname>');
          break;
        }
        const trustPeer = this.#findPeer(trustNick);
        if (!trustPeer) {
          this.#ui.addErrorMessage(`Peer "${trustNick}" is not online`);
          break;
        }
        this.#trustStore.updatePeer(trustPeer.nickname, trustPeer.publicKey);
        this.#ui.addSystemMessage(`${trustPeer.nickname}'s key accepted (verification reset)`);
        break;
      }

      case '/trustlist': {
        const peerNames = [...this.#peers.keys()];
        if (peerNames.length === 0) {
          this.#ui.addInfoMessage('No peers online');
          break;
        }
        this.#ui.addInfoMessage('Trust status:');
        for (const name of peerNames) {
          const record = this.#trustStore.getPeerRecord(name);
          let status;
          if (!record) {
            status = 'unknown';
          } else if (record.verified) {
            status = 'verified';
          } else {
            status = 'trusted (TOFU)';
          }
          this.#ui.addInfoMessage(`  ${name}: ${status}`);
        }
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
        const msgPeer = this.#findPeer(msgNick);
        if (!msgPeer) {
          this.#ui.addErrorMessage(`Peer "${msgNick}" not found`);
          break;
        }
        this.#sendMessageToPeer(msgPeer.nickname, msgText);
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

      case '/img': {
        const imgPath = parts.slice(1).join(' ').trim() || this.#lastImagePath;
        if (!imgPath) {
          this.#ui.addErrorMessage('No recent image. Usage: /img [path]');
          break;
        }
        const protocol = detectImageProtocol();
        if (!protocol) {
          this.#ui.addInfoMessage(
            `Your terminal does not support inline images (kitty/iTerm2). File saved to: ${imgPath}`,
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
          this.#ui.addSystemMessage(`Identity + trust backup saved to ${path} (encrypted).`);
        } catch (e) {
          this.#ui.addErrorMessage(`Failed to save backup: ${e.message}`);
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
          pending.nickname,
          pending.data,
          pending.nickname,
        );
        this.#ui.addSystemMessage(`Accepting: ${offer.message}`);
        this.#broadcastPayload(
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
        this.#broadcastPayload(
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
            'Cover traffic (constant rate) enabled — uniform encrypted stream; ' +
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
        this.#ui.addSystemMessage('You unpinned a message');
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

      case '/join': {
        const room = (parts[1] || '')
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, '');
        if (room.length < 1 || room.length > 30) {
          this.#ui.addErrorMessage('Usage: /join <room> (1-30 characters: a-z, 0-9, _, -)');
          break;
        }
        if (room === this.#currentRoom) {
          this.#ui.addInfoMessage(`You are already in room #${room}`);
          break;
        }
        this.#currentRoom = room;
        this.#ui.setRoom(room);
        this.#ui.setHeaderIndicator('room', `{cyan-fg}#${room}{/cyan-fg}`);
        this.#broadcastPayload(
          JSON.stringify({ action: 'room_announce', room, sentAt: Date.now() }),
        );
        // Give my sender key to peers already in this room.
        this.#distributeSenderKey(room);
        this.#ui.addSystemMessage(`You joined room #${room}`);
        break;
      }

      case '/rooms': {
        const rooms = new Set([this.#currentRoom]);
        for (const r of this.#peerRooms.values()) {
          rooms.add(r);
        }
        const list = [...rooms].map((r) => {
          const peers = [...this.#peers.keys()].filter(
            (n) => (this.#peerRooms.get(n) || 'general') === r,
          ).length;
          const count = peers + (r === this.#currentRoom ? 1 : 0);
          return `#${r} (${count})`;
        });
        this.#ui.addInfoMessage(`Known rooms: ${list.join(', ')}`);
        break;
      }

      case '/room':
        this.#ui.addInfoMessage(`Current room: #${this.#currentRoom}`);
        break;

      case '/tips': {
        this.#tipIndex = (this.#tipIndex + 1) % TIPS.length;
        this.#ui.addTip(tipAt(this.#tipIndex));
        break;
      }

      case '/kick':
      case '/mute':
      case '/ban':
      case '/owner':
        this.#ui.addErrorMessage('Moderation not available in P2P mode');
        break;

      case '/plugins': {
        if (!this.#pluginManager || this.#pluginManager.pluginCount === 0) {
          this.#ui.addInfoMessage('No plugins loaded. Put .js files in ~/.ciphermesh/plugins/');
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

      case '/panic': {
        const panicArg = parts[1]?.toLowerCase();
        if (panicArg === 'sim' || panicArg === 'yes' || panicArg === 'wipe') {
          this.#doPanic();
        } else {
          this.#ui.addErrorMessage(
            'PANIC wipes EVERYTHING from disk (session, trust, keys) and exits. Confirm with /panic yes',
          );
        }
        break;
      }

      case '/quit':
        this.destroy(); // tears down the TUI, freeing the terminal for the animation
        farewellBanner().finally(() => process.exit(0));
        break;

      default: {
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

  #findPeer(nickname) {
    const direct = this.#peers.get(nickname);
    if (direct) {
      return { ...direct, nickname };
    }

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

  #formatDuration(ms) {
    if (ms >= 3_600_000) {
      return `${Math.round(ms / 3_600_000)}h`;
    }
    if (ms >= 60_000) {
      return `${Math.round(ms / 60_000)}m`;
    }
    return `${Math.round(ms / 1000)}s`;
  }

  #scheduleEphemeralRemoval(lineIndex, durationMs, nickname) {
    const timer = setTimeout(() => {
      this.#ui.burnLine(lineIndex, () => {
        this.#ui.addSystemMessage(`Ephemeral message from ${nickname} burned`);
      });
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
    this.#ui.addSystemMessage(`Keys rotated (new fingerprint: ${this.#keyManager.fingerprint})`);
  }

  // ── Send encrypted payload ─────────────────────────────────────
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

  // One constant-rate slot: a queued real message if there is one, else a decoy.
  coverTick() {
    const item = this.#paceQueue.shift();
    if (item) {
      this.#broadcastPayload(item.payload, item.deniable, null, item.room);
    } else {
      this.sendCoverNow();
    }
  }

  // Route an outgoing room payload: paced in constant mode, immediate otherwise.
  #paceOrSend(payload, deniable, room) {
    if (this.#coverMode === 'constant') {
      this.#paceQueue.push({ payload, deniable, room });
    } else {
      this.#broadcastPayload(payload, deniable, null, room);
    }
  }

  #flushPace() {
    while (this.#paceQueue.length > 0) {
      const { payload, deniable, room } = this.#paceQueue.shift();
      this.#broadcastPayload(payload, deniable, null, room);
    }
  }

  // Sends a single decoy immediately (used by tests and by the timers).
  sendCoverNow() {
    if (this.#peers.size > 0) {
      this.#broadcastPayload(coverPayload(Date.now()));
    }
  }

  #broadcastPayload(payload, deniable = false, only = null, room = null) {
    for (const [peerNickname] of this.#peers) {
      if (only && peerNickname !== only) {
        continue;
      }
      // Room-scoped send: only deliver to peers known to be in `room`.
      if (room !== null && (this.#peerRooms.get(peerNickname) || 'general') !== room) {
        continue;
      }
      const peerPublicKey = this.#handshake.getPeerPublicKey(peerNickname);
      if (!peerPublicKey) {
        continue;
      }

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
        payload,
        nonce,
        peerPublicKey,
        this.#handshake.secretKey,
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

  // ── Group crypto (sender keys) ─────────────────────────────────
  #getGroup(room) {
    let group = this.#groups.get(room);
    if (!group) {
      group = new GroupSession();
      this.#groups.set(room, group);
    }
    return group;
  }

  // Hand my sender key for `room` to a peer (or all room peers) over the
  // pairwise channel — confidential, and ordered before any group message on
  // the same connection.
  #distributeSenderKey(room, toPeer = null) {
    const payload = JSON.stringify({
      action: 'sk_dist',
      room,
      dist: this.#getGroup(room).distribution(),
      sentAt: Date.now(),
    });
    this.#broadcastPayload(payload, false, toPeer, room);
  }

  // Encrypt a room message ONCE and send the same ciphertext to every online
  // room peer — real group cryptography (O(1) encryption instead of O(N)).
  #sendRoomGroup(room, payload) {
    const packet = this.#getGroup(room).encrypt(payload);
    for (const [peerNickname] of this.#peers) {
      if ((this.#peerRooms.get(peerNickname) || 'general') !== room) {
        continue;
      }
      this.#connManager.send(peerNickname, { type: 'p2p_group', room, ...packet });
    }
  }

  #onGroupMessage(fromNickname, msg) {
    if (!this.#peers.has(fromNickname)) {
      return;
    }
    const plaintext = this.#getGroup(msg.room).decrypt(fromNickname, {
      counter: msg.counter,
      ciphertext: msg.ciphertext,
      nonce: msg.nonce,
    });
    if (!plaintext) {
      // No sender key yet (rare race) — buffer until sk_dist arrives.
      this.#bufferGroupMessage(fromNickname, msg);
      return;
    }
    try {
      this.#handleDecryptedAction(fromNickname, JSON.parse(plaintext.toString('utf-8')));
    } catch {
      // ignore malformed
    }
  }

  #bufferGroupMessage(fromNickname, msg) {
    let buf = this.#groupBuffer.get(fromNickname);
    if (!buf) {
      buf = [];
      this.#groupBuffer.set(fromNickname, buf);
    }
    if (buf.length < 20) {
      buf.push(msg);
    }
  }

  #flushGroupBuffer(fromNickname, room) {
    const buf = this.#groupBuffer.get(fromNickname);
    if (!buf) {
      return;
    }
    this.#groupBuffer.delete(fromNickname);
    for (const msg of buf) {
      if (msg.room === room) {
        this.#onGroupMessage(fromNickname, msg);
      }
    }
  }

  #sendMessageToAll(text) {
    const inMyRoom = (n) => (this.#peerRooms.get(n) || 'general') === this.#currentRoom;
    const onlineInRoom = [...this.#peers.keys()].filter(inMyRoom);
    const offlineKnownInRoom = [...this.#knownPeers].filter(
      (n) => !this.#peers.has(n) && inMyRoom(n),
    );

    if (onlineInRoom.length === 0 && offlineKnownInRoom.length === 0) {
      this.#ui.addSystemMessage(`Nobody in room #${this.#currentRoom} to receive messages`);
      return;
    }

    const messageId = Math.random().toString(36).slice(2, 10);
    const msgObj = {
      text,
      sentAt: Date.now(),
      messageId,
      room: this.#currentRoom,
    };

    this.#lastSentMessageId = messageId;

    if (this.#ephemeralMode) {
      msgObj.ephemeral = this.#ephemeralDurationMs;
    }
    if (this.#deniableMode) {
      msgObj.deniable = true;
    }

    const payload = JSON.stringify(msgObj);
    // Online delivery: real group crypto (one encryption) for normal messages.
    // Deniable stays pairwise (plausible deniability); cover-constant keeps the
    // paced pairwise path so the timing guarantee holds.
    if (this.#deniableMode || this.#coverMode === 'constant') {
      this.#paceOrSend(payload, this.#deniableMode, this.#currentRoom);
    } else {
      this.#sendRoomGroup(this.#currentRoom, payload);
    }

    // Store-and-forward: queue for same-room known peers that are offline (not
    // for deniable/ephemeral messages, which are not meant to be persisted).
    if (!this.#deniableMode && !this.#ephemeralMode && offlineKnownInRoom.length > 0) {
      for (const nick of offlineKnownInRoom) {
        this.#enqueueSF(nick, payload);
      }
      if (onlineInRoom.length === 0) {
        this.#ui.addSystemMessage(
          `Queued for ${offlineKnownInRoom.length} offline peer(s) (delivery on reconnect).`,
        );
      }
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
    }
  }

  // ── Send encrypted DM to one peer ────────────────────────────
  #sendMessageToPeer(peerNickname, text) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerNickname);
    if (!peerPublicKey) {
      this.#ui.addErrorMessage(`Public key not found for ${peerNickname}`);
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
    const ciphertext = MessageCrypto.encrypt(
      payload,
      nonce,
      peerPublicKey,
      this.#handshake.secretKey,
    );
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

  // ── Panic / duress wipe ──────────────────────────────────────
  #doPanic() {
    panicWipe({ trustStore: this.#trustStore, auditLog: this.#auditLog });
    this.#passphrase = null; // never re-save state on the way out
    for (const group of this.#groups.values()) {
      try {
        group.destroy();
      } catch {
        /* best effort */
      }
    }
    this.#groups.clear();
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
    this.#ui.addSystemMessage('PANIC: session, trust, and keys wiped. Exiting...');
    setTimeout(() => process.exit(0), 60);
  }

  // ── Destroy ─────────────────────────────────────────────────
  destroy() {
    if (this.#keyRotationTimer) {
      clearInterval(this.#keyRotationTimer);
    }
    this.#stopCover();
    for (const group of this.#groups.values()) {
      group.destroy();
    }
    this.#groups.clear();
    for (const timer of this.#peerTypingTimers.values()) {
      clearTimeout(timer);
    }
    for (const timer of this.#ephemeralTimers) {
      clearTimeout(timer);
    }
    this.#fileTransfer.destroy();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connManager.destroy();
    this.#peerServer.stop();
    this.#discovery.stop();
    this.#ui.destroy();
  }
}
