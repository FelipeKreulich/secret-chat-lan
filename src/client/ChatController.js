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
  createSealedMessage,
  createKeyUpdate,
  createJoinRoom,
  createLeaveRoom,
  createRoomAuth,
  createListRooms,
  createKickPeer,
  createMutePeer,
  createBanPeer,
  createGroupMessage,
  ERR,
} from '../protocol/messages.js';
import { sealEnvelope, openEnvelope } from '../crypto/SealedSender.js';
import {
  deriveRoomSecrets,
  signRoomChallenge,
  encryptRoomPayload,
  decryptRoomPayload,
  isRoomWrapped,
  freeRoomSecrets,
} from '../crypto/RoomKey.js';
import {
  KEY_ROTATION_INTERVAL_MS,
  EMOJI_MAP,
  COVER_CONSTANT_MS,
  OWN_CAPABILITIES,
  CAP,
} from '../shared/constants.js';
import { normalizeCaps, peerSupports, roomSupports } from '../protocol/capabilities.js';
import {
  buildDeviceGrant,
  buildDeviceRequest,
  parseDeviceGrant,
  parseDeviceRequest,
} from '../shared/deviceProvisioning.js';
import {
  DEVICE_LIMITS,
  identityFingerprint,
  isNewerList,
  signDeviceList,
  verifyDeviceList,
} from '../crypto/DeviceIdentity.js';
import { GroupSession } from '../crypto/SenderKey.js';
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
import { trustBadge } from '../shared/trust.js';
import { tipAt, TIPS } from '../shared/tips.js';
import { setTheme, getThemeName, themeNames } from '../shared/themes.js';
import { panicWipe } from '../shared/panic.js';
import { farewellBanner } from '../shared/banner.js';
import {
  parseDndWindow,
  shouldNotify,
  nowMinutes,
  mentionsMe,
  matchesKeyword,
} from '../shared/dnd.js';
import { saveLastSession } from '../shared/lastSession.js';
import { diagnose, formatDiagnosis } from '../shared/doctor.js';
import { pluginsCommand } from '../shared/pluginCommand.js';
import { COMMANDS } from './UI.js';

const TYPING_SEND_INTERVAL = 2000; // debounce: max 1 typing event per 2s
const TYPING_EXPIRE_TIMEOUT = 3000; // hide indicator after 3s of silence
const MENTIONS_MAX = 50; // session mention log cap (memory only, never persisted)

export class ChatController {
  #nickname;
  #connection;
  #ui;
  #keyManager;
  #handshake;
  #nonceManager;
  #sessionId;
  #peers; // Map<sessionId, { nickname, publicKey, caps }>
  #groups = new Map(); // room -> GroupSession (sender keys; receive only for now)
  #groupBuffer = new Map(); // keyId -> group msgs waiting on their sender key
  #distributed = new Map(); // room -> Set<sessionId> holding our current chain
  #serverCaps = []; // what the relay advertised in join_ack
  #kickedSessions = new Set(); // sessionIds announced kicked, awaiting their peer_left
  #lastTypingSent;
  #peerTypingTimers; // Map<sessionId, timeoutId>
  #fileTransfer;
  #pendingFileOffers = new Map(); // transferId -> { from, data, nickname }
  #verifyNudged = new Set(); // peers already nudged to /verify this session
  #tipIndex = -1; // rotates through TIPS for /tips
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
  #mentions = []; // session mention log: { nickname, text, room, at }
  #watchWords = new Set(); // /watch — keywords that alert like a mention does
  #awayUnread = 0; // messages received while away
  #awayMentions = 0; // …of which mentioned me
  #messageLines = new Map(); // messageId → { lineIndex, nickname, text, opts, room }
  #reactions = new Map(); // messageId → Map<emoji, count>
  #reconnectAttempts = 0; // consecutive reconnects, for the /doctor nudge
  #autoLockMs = 0; // idle screen-lock timeout (0 = off)
  #autoLockTimer = null;
  // Multi-room buffers (IRC style): lines live in the UI; membership, unread
  // counters and private-room secrets live here, one entry per joined room.
  #buffers = new Map(); // room → { unread, mentions, private, owner, secrets, pins }
  #bufferOrder = []; // Alt+1..9 order
  #allPeers = new Map(); // sessionId → { nickname, publicKey, rooms: Set } (all my rooms)
  // Device lists, keyed by the identity that signed them. Multi-device step 3
  // (docs/design/multi-device.md): received, verified and kept — and consulted
  // by nothing. Every identity here has exactly one device today, because
  // nothing can yet add a second.
  #deviceLists = new Map(); // identityPk → verified list
  #deviceListSentTo = new Set(); // sessionIds holding our *current* list
  // `nickname:boxPk` pairs we have warned the user about. Kept so that a proof
  // arriving later can close the warning it answers, rather than leaving the
  // user with an unexplained alarm in their scrollback.
  #warnedKeys = new Set();
  #ownList = null; // cached signature; redrawn when the counter moves
  #pendingRoomSecrets = null; // derived while joining/creating, promoted on join

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

  // Runs when the socket opens. Extracted so it can also fire once at setup
  // time when the boot sequence already established the connection (otherwise
  // the initial JOIN would be lost — the 'connected' event fired before we
  // attached the listener).
  #onConnected() {
    this.#reconnectAttempts = 0;
    this.#ui.setConnectionState('online');
    this.#connection.send(
      createJoin(
        this.#nickname,
        this.#keyManager.publicKeyB64,
        this.#keyManager.pqPublicKeyB64,
        OWN_CAPABILITIES,
        this.#keyManager.identityPublicKeyB64,
        // Carried so the relay can let this session share a nickname another of
        // our own devices already holds. Sent whenever there is one: a client
        // cannot know in advance whether its other device is already online.
        this.#ownDeviceListForDisplay(),
      ),
    );
  }

  // ── Connection event handlers ─────────────────────────────────
  #setupConnectionHandlers() {
    this.#connection.on('connected', () => this.#onConnected());

    // The boot sequence may have already opened the socket before this
    // controller existed — replay the connect so the JOIN still goes out.
    if (this.#connection.connected) {
      this.#onConnected();
    }

    this.#connection.on('disconnected', () => {
      this.#ui.setConnectionState('offline');
      this.#ui.setOnlineCount(0);
      this.#ui.addErrorMessage('Connection lost to the server');
    });

    this.#connection.on('reconnecting', (delay) => {
      this.#ui.setConnectionState('reconnecting');
      this.#ui.addSystemMessage(`Reconnecting in ${delay / 1000}s...`);
      // After a few failures this is not a blip — point at the tool that can
      // actually explain it, once, instead of looping silently forever.
      this.#reconnectAttempts++;
      if (this.#reconnectAttempts === 3) {
        this.#ui.addInfoMessage('Still failing? Run /doctor to find out where it breaks.');
      }
    });

    this.#connection.on('cert-ca-valid', ({ issuer }) => {
      this.#ui.addSystemMessage(
        `TLS verified against a public CA (${issuer}) — no trust-on-first-use window`,
      );
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

    this.#ui.on('unlocked', () => {
      this.#auditLog.log(AuditEvent.SCREEN_UNLOCKED, {});
      this.#ui.addSystemMessage('Screen unlocked');
      this.#noteActive();
    });

    this.#ui.on('lock-failed', () => {
      this.#auditLog.log(AuditEvent.SCREEN_UNLOCK_FAILED, {});
    });

    this.#ui.on('buffer-switch', (idx) => {
      const room = this.#bufferOrder[idx];
      if (room) {
        this.#switchToBuffer(room);
      }
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
      this.#reportAwayUnread();
      this.#broadcastPresence();
    }
    this.#armAutoAway();
    this.#armAutoLock();
  }

  // ── Screen lock (privacy, not duress — that's /panic) ────────
  #lockNow() {
    if (!this.#passphrase) {
      this.#ui.addErrorMessage(
        'No session passphrase — /lock needs one (set it at startup to enable locking)',
      );
      return;
    }
    if (this.#ui.isLocked) {
      return;
    }
    this.#auditLog.log(AuditEvent.SCREEN_LOCKED, {});
    this.#ui.showLock((attempt) => attempt === this.#passphrase);
  }

  #armAutoLock() {
    if (this.#autoLockTimer) {
      clearTimeout(this.#autoLockTimer);
      this.#autoLockTimer = null;
    }
    if (this.#autoLockMs > 0) {
      this.#autoLockTimer = setTimeout(() => this.#lockNow(), this.#autoLockMs);
      if (this.#autoLockTimer.unref) {
        this.#autoLockTimer.unref();
      }
    }
  }

  // Summarize what arrived while away, then reset the counters.
  #reportAwayUnread() {
    if (this.#awayUnread > 0) {
      const mentions =
        this.#awayMentions > 0 ? ` — ${this.#awayMentions} mention(s), see /mentions` : '';
      this.#ui.addSystemMessage(
        `While you were away: ${this.#awayUnread} new message(s)${mentions}`,
      );
    }
    this.#awayUnread = 0;
    this.#awayMentions = 0;
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
    this.#awayUnread = 0;
    this.#awayMentions = 0;
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

      case MSG.GROUP_MESSAGE:
        this.#onGroupMessage(msg);
        break;

      case MSG.PEER_KEY_UPDATED:
        this.#onPeerKeyUpdated(msg);
        break;

      case MSG.ROOM_CHANGED:
        this.#onRoomChanged(msg);
        break;

      case MSG.ROOM_JOINED:
        this.#onRoomJoined(msg);
        break;

      case MSG.ROOM_LEFT:
        this.#onRoomLeft(msg);
        break;

      case MSG.ROOM_CHALLENGE:
        this.#onRoomChallenge(msg);
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
        } else if (typeof msg.message === 'string' && msg.message.startsWith('Protocol mismatch')) {
          // Reconnecting cannot fix a version gap — say so instead of letting
          // the user watch an endless retry loop.
          this.#ui.addErrorMessage(msg.message);
          this.#ui.addInfoMessage(
            'Reconnecting will not help until both sides run the same version.',
          );
        } else if (msg.code === ERR.ROOM_AUTH_FAILED || msg.code === ERR.ROOM_EXISTS) {
          // Join/create refused — drop the derived secrets for that attempt.
          freeRoomSecrets(this.#pendingRoomSecrets);
          this.#pendingRoomSecrets = null;
          this.#ui.addErrorMessage(`Error: ${msg.message} (${msg.code})`);
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

      // Another of this peer's devices, signed by the identity bound to their
      // record. Silent: the alarm below is for a key nobody vouched for, and
      // this one has been vouched for by exactly what the user verified.
      case TrustResult.KNOWN_DEVICE:
        break;

      case TrustResult.MISMATCH:
        this.#warnedKeys.add(`${nickname.toLowerCase()}:${publicKey}`);
        this.#auditLog.log(AuditEvent.TRUST_MISMATCH, { nickname });
        this.#ui.addErrorMessage(
          `WARNING: ${nickname}'s key changed! Possible MITM attack. Use /trust ${nickname} to accept or /verify ${nickname} to verify.`,
        );
        break;

      case TrustResult.VERIFIED_MISMATCH:
        this.#warnedKeys.add(`${nickname.toLowerCase()}:${publicKey}`);
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
    // What the relay itself can do. No client can advertise this on its behalf,
    // and the fan-out for a room-addressed message is the relay's job — so a
    // capable room on an older hub is still not a room that can switch paths.
    this.#serverCaps = normalizeCaps(msg.serverCaps);
    const room = msg.room || 'general';
    const hadPrivateBuffers = [...this.#buffers.values()].some((b) => b.secrets);

    // Build map of old sessionIds by nickname for ratchet migration
    const oldSessionByNick = new Map();
    for (const [sid, peer] of this.#allPeers) {
      oldSessionByNick.set(peer.nickname.toLowerCase(), sid);
    }

    // (Re)connecting always starts over in a single public room.
    this.#resetBuffersTo(room);
    this.#currentRoomOwner = msg.roomOwner || null;
    if (hadPrivateBuffers) {
      this.#ui.addInfoMessage('Reconnected outside your private room(s) — /join them again.');
    }

    for (const peer of msg.peers) {
      this.#allPeers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
        caps: normalizeCaps(peer.caps),
        identityKey: peer.identityKey ?? null,
        rooms: new Set([room]),
      });

      const oldSid = oldSessionByNick.get(peer.nickname.toLowerCase());
      if (oldSid && oldSid !== peer.sessionId) {
        // Migrate ratchet from old sessionId to new sessionId
        this.#handshake.migrateRatchet(oldSid, peer.sessionId);
      } else if (!oldSid) {
        this.#handshake.registerPeer(peer.sessionId, peer.publicKey, peer.pqPublicKey);
      }

      if (!this.#isOwnDevice(peer)) {
        this.#checkTrust(peer.nickname, peer.publicKey);
      }
    }

    // Initialize ratchets now that we have our session ID
    this.#handshake.setMySessionId(msg.sessionId);

    this.#rebuildActivePeers();
    const peerNames = [...this.#peers.values()].map((p) => p.nickname);
    this.#ui.addSystemMessage('Connected to server with E2E encryption active');

    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }

    // Server notice (MOTD): the operator's only channel to everyone, since
    // they cannot read or inject anything into the conversations themselves.
    if (typeof msg.motd === 'string' && msg.motd.trim()) {
      this.#ui.addInfoMessage('── Server notice ──');
      for (const line of msg.motd.split('\n').slice(0, 10)) {
        this.#ui.addInfoMessage(`  ${line}`);
      }
    }

    if (msg.queuedCount > 0) {
      this.#ui.addSystemMessage(`${msg.queuedCount} pending message(s) being delivered`);
    }

    // Invite included a room — join it once after the first connect
    if (this.#inviteRoom && this.#inviteRoom !== this.#currentRoom) {
      this.#connection.send(createJoinRoom(this.#inviteRoom));
      this.#inviteRoom = null;
    }

    this.#saveLastSession();
  }

  // Remember where we are for the next launch. Privacy: in a private room only
  // the server is written — the room name never touches disk.
  #saveLastSession(isPrivate = false) {
    saveLastSession({
      server: (this.#connection.url || '').replace(/^wss?:\/\//, ''),
      room: isPrivate || this.#activeSecrets ? undefined : this.#currentRoom,
    });
  }

  // ── Multi-room buffer plumbing ───────────────────────────────

  get #activeSecrets() {
    return this.#buffers.get(this.#currentRoom)?.secrets || null;
  }

  #ensureBuffer(room, { isPrivate = false, owner = null, secrets = null } = {}) {
    if (!this.#buffers.has(room)) {
      this.#buffers.set(room, {
        unread: 0,
        mentions: 0,
        private: isPrivate,
        owner,
        secrets,
        pins: [],
        topic: null, // { text, by, at } — E2EE among members, never on the relay
      });
      this.#bufferOrder.push(room);
    }
    return this.#buffers.get(room);
  }

  #dropBufferState(room) {
    const buf = this.#buffers.get(room);
    if (buf) {
      freeRoomSecrets(buf.secrets);
      this.#buffers.delete(room);
    }
    this.#bufferOrder = this.#bufferOrder.filter((r) => r !== room);
    this.#ui.dropBuffer(room);
  }

  // Forget every buffer and exist only in `room` (connect, reconnect, or a
  // legacy full switch — including being kicked).
  #resetBuffersTo(room, opts = {}) {
    for (const buf of this.#buffers.values()) {
      freeRoomSecrets(buf.secrets);
    }
    this.#buffers.clear();
    this.#bufferOrder = [];
    this.#allPeers.clear();
    this.#peers.clear();
    this.#currentRoom = room;
    const buf = this.#ensureBuffer(room, opts);
    this.#pinnedMessages = buf.pins;
    this.#currentRoomOwner = buf.owner;
    this.#ui.resetBuffers(room);
    this.#updateBufferBar();
    this.#updatePrivateIndicator();
  }

  #switchToBuffer(room) {
    if (room === this.#currentRoom || !this.#buffers.has(room)) {
      return;
    }
    // Sync the active-view aliases back before leaving the buffer.
    const cur = this.#buffers.get(this.#currentRoom);
    if (cur) {
      cur.pins = this.#pinnedMessages;
      cur.owner = this.#currentRoomOwner;
    }
    this.#currentRoom = room;
    const buf = this.#buffers.get(room);
    buf.unread = 0;
    buf.mentions = 0;
    this.#pinnedMessages = buf.pins;
    this.#currentRoomOwner = buf.owner;
    this.#ui.switchBuffer(room);
    this.#rebuildActivePeers();
    this.#applyTopicToUI();
    this.#updateBufferBar();
    this.#updatePrivateIndicator();
    this.#saveLastSession(buf.private);
  }

  // #peers is always "the active room's peers" so every send path stays
  // room-scoped without changes. Rebuilt from the global map on switches.
  #rebuildActivePeers() {
    this.#peers.clear();
    for (const [sid, p] of this.#allPeers) {
      if (p.rooms.has(this.#currentRoom)) {
        this.#peers.set(sid, {
          nickname: p.nickname,
          publicKey: p.publicKey,
          caps: p.caps || [],
          // Carried, not read. Step 3 is what gives it meaning; carrying it now
          // is what lets step 3 be a small change instead of a wide one, and
          // what makes "did the advertisement survive the trip" testable before
          // anything depends on the answer.
          identityKey: p.identityKey ?? null,
        });
      }
    }
    // People, not connections: your own other devices are you.
    const people = this.#otherPeople();
    this.#ui.setOnlineCount(people.length + 1);
    this.#ui.setPeerNames(people.map(([, p]) => p.nickname));
  }

  // Can every member of the active room speak `cap`? This is the switch the
  // group send path is gated on, together with the relay check below — see
  // #canSendToGroup. `own` stays overridable so a test can ask the question as
  // a build that advertises something else.
  roomSupportsCapability(cap, own = OWN_CAPABILITIES) {
    return roomSupports(this.#peers.values(), cap, own);
  }

  // Did the relay say it can do this? Separate from the room check on purpose:
  // both have to hold before a send path may switch, and they fail for
  // different reasons — an old peer versus an old hub.
  relaySupportsCapability(cap) {
    return this.#serverCaps.includes(cap);
  }

  #applyTopicToUI() {
    const topic = this.#buffers.get(this.#currentRoom)?.topic;
    this.#ui.setTopic(topic?.text || null);
  }

  #updateBufferBar() {
    this.#ui.setBufferBar(
      this.#bufferOrder.map((room) => {
        const b = this.#buffers.get(room);
        return {
          room,
          active: room === this.#currentRoom,
          unread: b?.unread || 0,
          private: !!b?.private,
        };
      }),
    );
  }

  #updatePrivateIndicator() {
    if (this.#activeSecrets) {
      this.#ui.setHeaderIndicator('private', '{green-fg}[🔒]{/green-fg}');
    } else {
      this.#ui.removeHeaderIndicator('private');
    }
  }

  // Which buffer an incoming payload belongs to: its own E2EE `room` tag when
  // it names a room we're in; otherwise a room shared with the sender.
  #roomForIncoming(data, fromSid) {
    if (typeof data.room === 'string' && this.#buffers.has(data.room)) {
      return data.room;
    }
    const peer = this.#allPeers.get(fromSid);
    if (peer?.rooms.has(this.#currentRoom)) {
      return this.#currentRoom;
    }
    return peer?.rooms.values().next().value || this.#currentRoom;
  }

  // Count a message that landed in an inactive buffer.
  #noteBufferUnread(room, mentioned) {
    if (room === this.#currentRoom) {
      return;
    }
    const buf = this.#buffers.get(room);
    if (buf) {
      buf.unread++;
      if (mentioned) {
        buf.mentions++;
      }
      this.#updateBufferBar();
    }
  }

  // Tag an outgoing payload with the room it belongs to. Travels INSIDE the
  // E2EE envelope — the relay never sees it.
  #tagRoom(payloadStr) {
    try {
      const obj = JSON.parse(payloadStr);
      if (obj && typeof obj === 'object' && !obj.room) {
        obj.room = this.#currentRoom;
        return JSON.stringify(obj);
      }
    } catch {
      /* not JSON — send as is */
    }
    return payloadStr;
  }

  // ── New peer arrived ──────────────────────────────────────────
  #onPeerJoined(msg) {
    const { peer } = msg;
    const room = msg.room && this.#buffers.has(msg.room) ? msg.room : this.#currentRoom;

    const existing = this.#allPeers.get(peer.sessionId);
    if (existing) {
      existing.rooms.add(room);
    } else {
      this.#allPeers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
        caps: normalizeCaps(peer.caps),
        identityKey: peer.identityKey ?? null,
        rooms: new Set([room]),
      });
      this.#handshake.registerPeer(peer.sessionId, peer.publicKey, peer.pqPublicKey);
    }
    // Your own other device is not a peer to be trusted on first sight: a
    // record for yourself would sit in the trust store forever, and the verify
    // nudge would be asking you to compare digits with your own phone.
    const ownDevice = this.#isOwnDevice(peer);
    if (!ownDevice) {
      this.#checkTrust(peer.nickname, peer.publicKey);
    }
    this.#auditLog.log(AuditEvent.PEER_CONNECTED, { nickname: peer.nickname, room });

    if (room === this.#currentRoom) {
      this.#rebuildActivePeers();
      this.#ui.handshakeConnect(peer.nickname);
      if (!ownDevice) {
        this.#nudgeVerify(peer.nickname);
      }
    } else {
      this.#ui.toBuffer(room, () => {
        this.#ui.addSystemMessage(`${peer.nickname} joined #${room}`);
      });
    }

    // A newcomer holds no chain of ours, so give them one before anything is
    // sent on it. Ordered ahead of the presence and topic sends below because
    // those may themselves go out on the group path.
    //
    // No rotation here. Someone arriving is not someone gaining access to the
    // past: a serialised chain carries its *current* counter, so what they are
    // handed opens what comes next and nothing before it.
    if (room === this.#currentRoom) {
      this.#distributeSenderKey(room, peer.sessionId);
    }
    if (this.#wantsDeviceList(peer.sessionId)) {
      this.#distributeDeviceList(peer.sessionId);
    }

    // A newcomer doesn't know my presence — send only to them
    if (this.#away || this.#statusText) {
      this.#sendPayloadToPeer(peer.sessionId, this.#presencePayload());
    }

    // …nor the room topic. Everyone who has it answers; the timestamp settles
    // any disagreement, and `silent` keeps the sync out of the chat log.
    const topic = this.#buffers.get(room)?.topic;
    if (topic) {
      this.#sendPayloadToPeer(
        peer.sessionId,
        JSON.stringify({
          action: 'set_topic',
          room,
          text: topic.text,
          at: topic.at,
          silent: true,
          sentAt: Date.now(),
        }),
      );
    }
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

  // ── Peer left (one room, or entirely when untagged) ──────────
  #onPeerLeft(msg) {
    const entry = this.#allPeers.get(msg.sessionId);
    const nickname = entry?.nickname || msg.nickname || 'Unknown';
    const room = msg.room && this.#buffers.has(msg.room) ? msg.room : null;

    if (entry && room) {
      entry.rooms.delete(room);
    }
    const goneEntirely = !entry || !room || entry.rooms.size === 0;

    // Two separate things, and only the second is forward secrecy.
    //
    // Dropping *their* chain stops us holding a key we can no longer be sent
    // anything on. Rotating *ours* is what stops them reading what the room says
    // next — a chain ratchets forward, so the copy they were handed opens every
    // message after it until we draw a new one.
    //
    // Which rooms rotate is decided by which ones actually lost a member, not by
    // which ones we happen to hold a session for: every rotation costs a
    // redistribution to everyone remaining.
    const lostFrom = new Set();
    if (room && this.#groups.get(room)?.removeMember(msg.sessionId)) {
      lostFrom.add(room);
    }

    if (goneEntirely) {
      this.#hidePeerTyping(msg.sessionId, nickname);
      this.#handshake.removePeer(msg.sessionId);
      this.#nonceManager.removePeer(msg.sessionId);
      this.#allPeers.delete(msg.sessionId);
      for (const [groupRoom, group] of this.#groups) {
        if (group.removeMember(msg.sessionId)) {
          lostFrom.add(groupRoom);
        }
      }
    }

    for (const lost of lostFrom) {
      this.#rotateGroupFor(lost);
    }

    // A kick already announced itself. Do every bit of the state work, and say
    // nothing — "was kicked" followed by "left" describes one event twice.
    const wasKicked = this.#kickedSessions.delete(msg.sessionId);

    if (!room || room === this.#currentRoom) {
      this.#rebuildActivePeers();
      if (!wasKicked) {
        this.#ui.handshakeDisconnect(nickname);
      }
    } else if (!wasKicked) {
      this.#ui.toBuffer(room, () => {
        this.#ui.addSystemMessage(`${nickname} left #${room}`);
      });
    }
    this.#auditLog.log(AuditEvent.PEER_DISCONNECTED, { nickname });
  }

  // ── Sender keys on the relay ──────────────────────────────────
  //
  // The receive half shipped a release ahead of this one, on purpose: a room
  // switches to group sending only once every member advertises that it can
  // read one, so the readers had to be in the field before the writers or the
  // switch would never have become true for anybody.
  //
  // Three things have to hold before a line goes out once instead of N times,
  // and they fail for different reasons:
  //
  //   1. every member of the room advertises `sk1`   — an old peer
  //   2. the relay advertises `sk1`                  — an old hub
  //   3. the message is not deniable                 — see #canSendToGroup
  //
  // Any one of them false and the per-peer loop runs, unchanged.

  #getGroup(room) {
    let group = this.#groups.get(room);
    if (!group) {
      group = new GroupSession();
      this.#groups.set(room, group);
    }
    return group;
  }

  // A member handed us their sender key. This arrives over the pairwise sealed
  // channel, so `fromSessionId` was authenticated by opening the envelope —
  // never asserted by the relay, which is the whole reason distribution does not
  // ride on the group path itself.
  #onSenderKeyDistribution(fromSessionId, data) {
    if (typeof data.room !== 'string' || !data.dist || typeof data.dist !== 'object') {
      return;
    }
    this.#getGroup(data.room).addMember(fromSessionId, data.dist);
    this.#flushGroupBuffer(data.dist.keyId);

    // Answer with ours if they do not have it. This is what makes distribution
    // reliable without anything having to know who joined in which order:
    // whoever knows the other first speaks, and the reply cannot race, because
    // receiving this proves they already hold our public key.
    if (!this.#hasDistributedTo(data.room, fromSessionId)) {
      this.#distributeSenderKey(data.room, fromSessionId);
    }
  }

  // A full room switch: every buffer is dropped and we exist only in `room`.
  // The chains follow. Carrying one across would mean a chain drawn for one
  // room's membership being used against another's, and a keyId that outlives
  // the set of people it was ever meant to label.
  #dropAllGroups() {
    for (const group of this.#groups.values()) {
      group.destroy();
    }
    this.#groups.clear();
    this.#groupBuffer.clear();
    this.#distributed.clear();
  }

  // Hand our sender key for `room` to one peer, or to everyone in it.
  //
  // Always pairwise. The envelope is what proves who the key belongs to; a
  // distribution arriving on the group path would be a chain vouching for
  // itself, and the relay would be the only thing asserting whose it was.
  //
  // Never sent to a peer that may not know us yet. A client drops a ciphertext
  // from a session it has no public key for, and it learns ours from the
  // `peer_joined` the relay sends *after* our `join_ack` — so a newcomer
  // announcing itself into the room on arrival is talking to people who cannot
  // hear it. That is why nothing distributes on join: the peers who already
  // know us distribute to us (#onPeerJoined), and we answer (#onSenderKeyDistribution).
  #distributeSenderKey(room, toPeer = null) {
    const recipients = (toPeer ? [toPeer] : [...this.#peers.keys()]).filter((id) =>
      this.#worthDistributingTo(id),
    );
    if (recipients.length === 0) {
      return;
    }

    // Only now: distribution() is what draws the chain, and a chain is guarded
    // memory. See #worthDistributingTo.
    const payload = JSON.stringify({
      action: 'sk_dist',
      room,
      dist: this.#getGroup(room).distribution(),
      sentAt: Date.now(),
    });
    let sent = this.#distributed.get(room);
    if (!sent) {
      sent = new Set();
      this.#distributed.set(room, sent);
    }
    // Record before sending, never after.
    //
    // Sending re-enters this object. The peer receives the distribution, finds
    // it holds none of ours, and answers — and its answer can arrive before
    // #sendPayloadToPeer has returned. Marking afterwards means both sides
    // consult a record neither has written yet, each answers the other's
    // answer, and the exchange never converges.
    //
    // On a real socket that is a burst of duplicate distributions rather than a
    // hang, which is why it is worth stating: the bug is re-entrancy, and the
    // synchronous case is only the one that makes it obvious.
    for (const peerId of recipients) {
      sent.add(peerId);
    }
    for (const peerId of recipients) {
      this.#sendPayloadToPeer(peerId, payload);
    }
  }

  // A sender key is only ever useful to a peer that can read a group message,
  // on a hub that can fan one out. Handing one to anybody else is a wasted
  // round trip — and, less obviously, a wasted allocation.
  //
  // Chains live in sodium_malloc'd memory, which is mlock'd. Linux caps how much
  // a process may lock (RLIMIT_MEMLOCK), and the cap is small; drawing a chain
  // per room per peer regardless of whether it could ever be used exhausted it,
  // and sodium_malloc then returns NULL. That surfaced as a SIGABRT in an
  // unrelated ratchet call — the first allocation to fail, not the one at fault.
  #worthDistributingTo(peerId) {
    if (!this.relaySupportsCapability(CAP.SENDER_KEYS)) {
      return false;
    }
    const peer = this.#peers.get(peerId);
    return peer ? peerSupports(peer, CAP.SENDER_KEYS) : false;
  }

  // Has this peer been given our *current* chain for this room? Reset by
  // rotate(), because after one the answer is no for everybody.
  #hasDistributedTo(room, peerId) {
    return this.#distributed.get(room)?.has(peerId) ?? false;
  }

  // Someone is no longer in `room`: draw a new chain and hand it to whoever is
  // left.
  //
  // This is the forward secrecy the design promises, and the reason the relay
  // now reports a kick as a departure (#482). Without it a removed member keeps
  // the chain they were given, and a chain ratchets *forward* — holding it at
  // counter N opens every counter after N. Being removed from a room would stop
  // the relay delivering to them and would not stop them reading.
  //
  // rotate() has no failure to check and no value to return. The distribution
  // that follows is the whole point, so the two must not drift apart: a rotation
  // whose redistribution never happens is a room that quietly stopped being able
  // to read this client, with nothing raised anywhere.
  #rotateGroupFor(room) {
    const group = this.#groups.get(room);
    if (!group) {
      return;
    }
    group.rotate();
    this.#distributed.delete(room); // a new chain: nobody has it
    if (room === this.#currentRoom) {
      this.#distributeSenderKey(room);
    }
  }

  // ── Device lists ────────────────────────────────────────────────
  //
  // Step 3 of multi-device. A device list says "these are the keys that are me",
  // signed by the identity key advertised in JOIN. Today every list has exactly
  // one device in it, because nothing can add a second yet — the point of
  // landing it now is that the distribution, the verification and the replay
  // rule are all exercised before they carry weight.
  //
  // Nothing reads a stored list. That is deliberate and it is the last step at
  // which it is true: step 4 moves verification onto these keys.

  // Our own list, signed once per counter. The counter moves when the
  // descriptor does — see KeyManager.rotate — so caching on it cannot serve a
  // signature for a device that has since changed its key.
  #ownDeviceList() {
    // A secondary holds no identity secret, so the only list it can publish is
    // the one it was granted. It is signed by the same identity and says the
    // same thing; it simply cannot be updated from here.
    if (!this.#keyManager.isPrimaryDevice) {
      return this.#keyManager.grantedList;
    }
    const counter = this.#keyManager.listCounter;
    if (!this.#ownList || this.#ownList.counter !== counter) {
      this.#ownList = signDeviceList(this.#keyManager.identity, counter, [
        this.#keyManager.deviceDescriptor(),
      ]);
      // A new list is a list nobody has.
      this.#deviceListSentTo.clear();
    }
    return this.#ownList;
  }

  // Worth handing one to this peer? Same reasoning as #worthDistributingTo for
  // sender keys: a peer that cannot read it gains nothing and costs a round
  // trip. The relay is not consulted — a device list travels on the pairwise
  // channel the relay already carries, so there is nothing for it to agree to.
  #wantsDeviceList(peerId) {
    const peer = this.#peers.get(peerId);
    return peer ? peerSupports(peer, CAP.DEVICE_LIST) : false;
  }

  // Hand our list to one peer, or to everyone who can take one.
  //
  // Never on join, for the reason sender keys are not: a newcomer learns the
  // room from its join_ack before the room learns of the newcomer, so a client
  // announcing itself on arrival is talking to peers who hold no key for it and
  // will drop the ciphertext. The peers who already know us speak first, and we
  // answer.
  #distributeDeviceList(toPeer = null) {
    const recipients = (toPeer ? [toPeer] : [...this.#peers.keys()]).filter((id) =>
      this.#wantsDeviceList(id),
    );
    if (recipients.length === 0) {
      return;
    }
    const list = this.#ownDeviceList();
    if (!list) {
      return;
    }
    const payload = JSON.stringify({ action: 'device_list', list, sentAt: Date.now() });
    // Record before sending, never after — the same re-entrancy that bit sender
    // key distribution. Sending re-enters this object: the peer receives our
    // list, finds it holds none of ours, and answers, and its answer can arrive
    // before #sendPayloadToPeer has returned. Marked afterwards, both sides
    // consult a record neither has written yet and each answers the other's
    // answer.
    for (const peerId of recipients) {
      this.#deviceListSentTo.add(peerId);
      this.#sendPayloadToPeer(peerId, payload);
    }
  }

  // A peer handed us theirs.
  //
  // What authenticates it is not the seal — crypto_box_seal is anonymous, and
  // anyone can seal a blob to us claiming any sender. It is the layer under it:
  // this payload only decrypted because it was encrypted to us *by the holder
  // of this peer's box secret key*. So the pairwise channel is the authority on
  // whose list this is, and the identityKey the relay repeated in JOIN is only
  // ever a hint about whether distributing is worth the round trip. A relay that
  // tampers with that hint can stop us bothering; it cannot put words in a
  // peer's mouth, because it cannot produce this payload.
  #onDeviceList(fromSessionId, data) {
    const list = verifyDeviceList(data?.list);
    if (!list) {
      return;
    }

    // Highest counter wins, enforced here rather than trusted from the sender:
    // a relay that kept a copy of an older list could otherwise replay it, and
    // once revocation exists that would put a removed device back.
    const held = this.#deviceLists.get(list.identityPk);
    if (isNewerList(list, held)) {
      this.#deviceLists.set(list.identityPk, list);
      this.#bindPeerIdentity(fromSessionId, list);
    }

    // Answer with ours if they do not have it. Whoever knows the other first
    // speaks; the reply cannot race, because receiving this proves they already
    // hold our public key.
    if (!this.#deviceListSentTo.has(fromSessionId)) {
      this.#distributeDeviceList(fromSessionId);
    }
  }

  /** The list held for an identity, or null. */
  deviceListFor(identityPk) {
    return this.#deviceLists.get(identityPk) ?? null;
  }

  // Attach an identity to the trust record the user already has — step 4.
  //
  // Only when the binding is provable, which is a narrower condition than it
  // looks: the list has to *name the box key this peer is using*, and the list
  // only reached us because the holder of that box key encrypted it to us. So
  // the identity is vouched for by exactly the key the user compared digits
  // over. Anything else and we leave the record alone.
  //
  // This is the migration the design doc worried about, and it is silent on
  // purpose. Every already-verified record was verified against a box key; the
  // one thing that must not happen is thousands of clients simultaneously
  // telling their users that everyone they trust has been replaced.
  #bindPeerIdentity(fromSessionId, list) {
    const peer = this.#allPeers.get(fromSessionId);
    if (!peer) {
      return;
    }
    if (!list.devices.some((device) => device.boxPk === peer.publicKey)) {
      // A valid list that does not mention the key it arrived under. Not
      // necessarily an attack — a rotation can race a distribution — but it
      // proves nothing, so it binds nothing.
      return;
    }

    const result = this.#trustStore.bindIdentity(peer.nickname, list.identityPk);

    if (result === 'bound' || result === 'unchanged') {
      this.#recordPeerDevices(peer, list);
      return;
    }

    // A second identity for a record that already had one. On an unverified
    // record this is worth a line; on a verified one it is the same class of
    // event as VERIFIED_MISMATCH and is said in the same voice.
    this.#auditLog.log(AuditEvent.TRUST_MISMATCH, { nickname: peer.nickname });
    if (this.#trustStore.isVerified(peer.nickname)) {
      this.#ui.addErrorMessage(
        `${peer.nickname} is presenting a different identity key than the one you verified. ` +
          'Nothing has been changed. Verify again out of band before trusting this session.',
      );
    } else {
      this.#ui.addSystemMessage(
        `${peer.nickname} is presenting a different identity key than before.`,
      );
    }
  }

  // Write the devices an identity has signed for onto the peer's trust record,
  // so the next time one of them shows up it is recognised instead of reported.
  //
  // A second device is otherwise indistinguishable from an attack: it arrives
  // under the same nickname with a box key the record has never seen, which is
  // precisely what checkPeer is built to shout about. It *should* shout — until
  // something proves otherwise, a new key under a known name is the shape of a
  // MITM. So the alarm is never suppressed in advance. It is answered, once the
  // proof exists, and the answer is said out loud rather than swallowed: the
  // user saw a warning and is owed the resolution.
  #recordPeerDevices(peer, list) {
    const added = this.#trustStore.addDevices(
      peer.nickname,
      list.identityPk,
      list.devices.map((device) => device.boxPk),
    );

    // Only speak about the keys the user was actually warned about. A list that
    // simply happens to mention devices nobody has met is not news.
    const nick = peer.nickname.toLowerCase();
    const answered = added.filter((key) => this.#warnedKeys.has(`${nick}:${key}`));
    if (answered.length === 0) {
      return;
    }
    for (const key of answered) {
      this.#warnedKeys.delete(`${nick}:${key}`);
    }
    this.#ui.addSystemMessage(
      `The key you were warned about for ${peer.nickname} is another of their devices — ` +
        `signed by the identity you already ${
          this.#trustStore.isVerified(peer.nickname) ? 'verified' : 'know'
        }, so it is not a key that changed.`,
    );
  }

  /** Whatever list this device would publish, primary or secondary. */
  #ownDeviceListForDisplay() {
    return this.#keyManager.isPrimaryDevice ? this.#ownDeviceList() : this.#keyManager.grantedList;
  }

  // Sign a new list that includes the asking device, and hand back a grant.
  //
  // The counter moves because the list changed — that is what makes every peer
  // take the new one instead of keeping a list the new device is missing from.
  #grantDevice(request) {
    const current = this.#ownDeviceList();
    const devices = current ? [...current.devices] : [this.#keyManager.deviceDescriptor()];

    if (devices.some((device) => device.deviceId === request.deviceId)) {
      this.#ui.addErrorMessage('That device is already on the list.');
      return null;
    }
    if (devices.some((device) => device.boxPk === request.boxPk)) {
      // One key under two device ids makes "which device is this" unanswerable
      // for every reader, and verifyDeviceList refuses such a list outright.
      this.#ui.addErrorMessage('That key is already on the list under another device.');
      return null;
    }
    if (devices.length >= DEVICE_LIMITS.MAX_DEVICES) {
      this.#ui.addErrorMessage(`A list holds at most ${DEVICE_LIMITS.MAX_DEVICES} devices.`);
      return null;
    }

    devices.push({
      deviceId: request.deviceId,
      boxPk: request.boxPk,
      label: request.label,
      createdAt: Date.now(),
    });

    this.#keyManager.bumpListCounter();
    const list = signDeviceList(this.#keyManager.identity, this.#keyManager.listCounter, devices);
    // A new list is a list nobody has; #ownDeviceList caches on the counter, so
    // resetting here is what makes the next distribution carry this one.
    this.#ownList = list;
    this.#deviceListSentTo.clear();
    this.#distributeDeviceList();

    this.#auditLog.log(AuditEvent.KEY_ROTATION_OWN, { fingerprint: request.deviceId.slice(0, 8) });
    return buildDeviceGrant({ identityPk: list.identityPk, list });
  }

  // Adopt an identity this device does not hold the secret for.
  //
  // Three checks, and all three matter. The list has to verify under the
  // identity it claims, or a grant is just a JSON blob. It has to name *this*
  // device by both id and key, or a grant intended for somebody else — or
  // tampered with in transit — would be accepted. And this device must not
  // already be a secondary of something else, because there is no sensible
  // meaning for two.
  #acceptDeviceGrant(text) {
    const grant = parseDeviceGrant(text);
    if (!grant) {
      this.#ui.addErrorMessage('Usage: /device accept ciphermesh-device://grant/…');
      return;
    }
    if (!this.#keyManager.isPrimaryDevice) {
      this.#ui.addErrorMessage('This device already belongs to an identity.');
      return;
    }

    const list = verifyDeviceList(grant.list);
    if (!list || list.identityPk !== grant.identityPk) {
      this.#ui.addErrorMessage('That grant is not signed by the identity it names.');
      return;
    }

    const me = list.devices.find(
      (device) =>
        device.deviceId === this.#keyManager.deviceId &&
        device.boxPk === this.#keyManager.publicKeyB64,
    );
    if (!me) {
      this.#ui.addErrorMessage(
        'That grant is for a different device. Run /device request here and use that.',
      );
      return;
    }

    this.#keyManager.adoptIdentity(grant.identityPk, list);
    this.#ownList = null;
    this.#deviceListSentTo.clear();
    this.#ui.addSystemMessage(
      `This device now belongs to identity ${this.#keyManager.identityFingerprint}. ` +
        'It cannot add or remove devices — only the device holding the identity key can. ' +
        'Reconnect for peers to see it.',
    );
  }

  /**
   * Is this peer one of *our* devices?
   *
   * Proven, never asserted. The obvious test — does the peer's `identityKey`
   * match ours — would be worse than useless: the relay forwards that field
   * unchecked, so a hostile one could label a stranger as your own device and
   * every protection below would be turned off for them. Their messages would
   * be attributed to you.
   *
   * So the answer comes from a list we hold the signature of: our own. A device
   * is ours if our list names its box key, which only the holder of the
   * identity secret could have arranged.
   */
  #isOwnDevice(peer) {
    const own = this.#ownDeviceListForDisplay();
    if (!own || !peer?.publicKey) {
      return false;
    }
    return own.devices.some(
      (device) => device.boxPk === peer.publicKey && device.boxPk !== this.#keyManager.publicKeyB64,
    );
  }

  /** The peers in this room that are other people, rather than other devices. */
  #otherPeople() {
    return [...this.#peers.entries()].filter(([, peer]) => !this.#isOwnDevice(peer));
  }

  // Can this pair compare identity keys instead of box keys?
  //
  // Both sides have to answer the same way or two people doing everything right
  // are shown two different codes and conclude they are under attack. So the
  // condition is symmetric by construction: each of us holds the other's list,
  // which is exactly the state the exchange leaves both in.
  #identitySasReady(peerId) {
    const peer = this.#peers.get(peerId);
    if (!peer?.identityKey || !peerSupports(peer, CAP.DEVICE_LIST)) {
      return false;
    }
    const bound = this.#trustStore.identityFor(peer.nickname);
    return Boolean(bound) && this.#deviceListSentTo.has(peerId);
  }

  /**
   * The code to compare for a peer, and which keys it is over.
   *
   * Exposed rather than inlined into the command so a test can ask the question
   * without going through the UI.
   */
  sasFor(peerId) {
    const peer = this.#peers.get(peerId);
    if (!peer) {
      return null;
    }
    if (this.#identitySasReady(peerId)) {
      return {
        over: 'identity',
        code: TrustStore.computeIdentitySAS(
          this.#keyManager.identityPublicKeyB64,
          this.#trustStore.identityFor(peer.nickname),
        ),
      };
    }
    return {
      over: 'device',
      code: TrustStore.computeSAS(this.#keyManager.publicKeyB64, peer.publicKey),
    };
  }

  // Can this payload go out once, addressed to the room, instead of N times?
  #canSendToGroup(deniable) {
    // Deniability is a property of the pairwise construction — a symmetric key
    // both sides could have derived, so neither can prove the other wrote it. A
    // group packet is signed by exactly one sender for exactly that reason, so
    // sending a deniable message on it would publish the opposite of what was
    // asked for.
    if (deniable) {
      return false;
    }
    if (this.#peers.size === 0) {
      return false;
    }
    return (
      this.roomSupportsCapability(CAP.SENDER_KEYS) && this.relaySupportsCapability(CAP.SENDER_KEYS)
    );
  }

  // Which path the next line you type will take out of this room, and — when it
  // is the expensive one — what is holding it there.
  //
  // The fallback is invisible today. A room quietly sends N envelopes per line
  // instead of one and nobody can tell whether that is one peer on an older
  // build, an older hub, or deniable mode left on an hour ago. That is the same
  // shape as the three bugs this feature already shipped with: nothing errors,
  // nothing is logged, the room is just paying fifty times over and no one
  // knows.
  //
  // #481 asks whether the per-peer loop can be retired. It cannot — see the
  // decision recorded in docs/design/sender-keys-on-relay.md — so the useful
  // thing is being able to see when it runs and why, which is also what turns
  // "consider retiring it" into a question answerable with data.
  //
  // The order matches #canSendToGroup so the two cannot disagree, with one
  // deliberate exception: an older hub is reported before older peers. Both can
  // be true at once, and naming peers who are perfectly current would send the
  // reader after the wrong problem.
  groupSendStatus() {
    if (this.#deniableMode) {
      return { group: false, reason: 'deniable', blockers: [] };
    }
    if (this.#peers.size === 0) {
      return { group: false, reason: 'alone', blockers: [] };
    }
    if (!this.relaySupportsCapability(CAP.SENDER_KEYS)) {
      return { group: false, reason: 'relay', blockers: [] };
    }
    const blockers = [...this.#peers.values()]
      .filter((peer) => !peerSupports(peer, CAP.SENDER_KEYS))
      .map((peer) => peer.nickname);
    if (blockers.length > 0) {
      return { group: false, reason: 'peers', blockers };
    }
    // roomSupports() also requires *this* build to advertise the capability,
    // which is the one remaining way to land here with nobody to name.
    if (!this.roomSupportsCapability(CAP.SENDER_KEYS)) {
      return { group: false, reason: 'self', blockers: [] };
    }
    return { group: true, reason: null, blockers: [] };
  }

  // Plain language, because the number is the whole point: a line costs one
  // encryption and one frame, or it costs one of each per person in the room.
  #describeSendPath() {
    const status = this.groupSendStatus();
    const size = this.#peers.size;

    if (status.group) {
      return `one ciphertext to the room (sender keys), read by ${size}`;
    }

    const cost = `${size} envelope${size === 1 ? '' : 's'} per message`;
    switch (status.reason) {
      case 'alone':
        return 'nothing yet — no one else is here';
      case 'deniable':
        return `${cost} — deniable mode is on, and deniability is pairwise`;
      case 'relay':
        return `${cost} — this relay cannot fan out a room-addressed message`;
      case 'peers':
        return `${cost} — ${status.blockers.join(', ')} ${
          status.blockers.length === 1 ? 'is' : 'are'
        } on a build without sender keys`;
      default:
        return `${cost} — this build is not advertising sender keys`;
    }
  }

  // One encryption, one frame, the whole room. The payload arrives already
  // room-tagged and already through the private-room layer when there is one —
  // both happen before the path splits, so a group message and a pairwise one
  // carry exactly the same bytes inside.
  #sendRoomGroup(room, payload) {
    // Nobody can read a packet on a chain they were never given. The exchange
    // above covers every ordinary path; this covers the rest, and costs one
    // Set lookup per member when there is nothing to do.
    for (const [peerId] of this.#peers) {
      if (!this.#hasDistributedTo(room, peerId)) {
        this.#distributeSenderKey(room, peerId);
      }
    }
    const packet = this.#getGroup(room).encrypt(payload);
    this.#connection.send(createGroupMessage(room, packet));
  }

  #onGroupMessage(msg) {
    const group = this.#groups.get(msg.room);
    const from = group ? group.memberForKeyId(msg.keyId) : null;

    // A label we hold no distribution for. Usually a race — the fan-out beat the
    // sender key through a different path — so hold it rather than drop it.
    if (!from || !this.#allPeers.has(from)) {
      this.#bufferGroupMessage(msg);
      return;
    }

    const plaintext = group.decrypt(from, {
      keyId: msg.keyId,
      counter: msg.counter,
      ciphertext: msg.ciphertext,
      nonce: msg.nonce,
      signature: msg.signature,
    });
    if (!plaintext) {
      // A replayed counter, a chain that rotated without us being told yet, or a
      // signature that does not check out. The first two resolve on the next
      // distribution; the third never will, and buffering it costs one slot in a
      // bounded map rather than a decision made on too little information here.
      this.#bufferGroupMessage(msg);
      return;
    }

    // Hand it to the one path that knows what a payload means. `payload` is
    // empty because there was no pairwise envelope: the group chain replaced it.
    this.#onEncryptedMessage({ from, payload: {} }, plaintext);
  }

  #bufferGroupMessage(msg) {
    // Bounded twice over: a hostile relay can invent keyIds all day, and each
    // one must not become a place to park memory.
    if (!this.#groupBuffer.has(msg.keyId) && this.#groupBuffer.size >= 32) {
      return;
    }
    let buf = this.#groupBuffer.get(msg.keyId);
    if (!buf) {
      buf = [];
      this.#groupBuffer.set(msg.keyId, buf);
    }
    if (buf.length < 20) {
      buf.push(msg);
    }
  }

  #flushGroupBuffer(keyId) {
    const buf = this.#groupBuffer.get(keyId);
    if (!buf) {
      return;
    }
    this.#groupBuffer.delete(keyId);
    for (const msg of buf) {
      this.#onGroupMessage(msg);
    }
  }

  // ── Received encrypted message ────────────────────────────────
  // `preDecrypted` is the group path handing over plaintext it already opened
  // with a sender chain (see #onGroupMessage). Everything after the decryption
  // step is shared on purpose: a group message must land in history, buffers,
  // receipts and the action dispatch exactly like a pairwise one, and the way to
  // guarantee that is for there to be only one copy of it.
  #onEncryptedMessage(msg, preDecrypted = null) {
    // Sealed sender: the relay handed us only `to` + an opaque blob. Open it
    // with our identity key to recover the real sender + payload; from here the
    // rest of the handler is unchanged. A blob that isn't for us (or is tampered)
    // simply fails to open and is dropped.
    if (typeof msg.sealed === 'string') {
      const opened = this.#openSealed(msg.sealed);
      if (!opened || typeof opened.from !== 'string' || !opened.payload) {
        return;
      }
      // Rebind to a fresh object — never mutate the received message.
      msg = { ...msg, from: opened.from, payload: opened.payload };
    }

    // Multi-room: the sender may live in any of my rooms, not just the active one.
    const peer = this.#allPeers.get(msg.from);
    if (!peer) {
      this.#ui.addErrorMessage('Message from unknown peer');
      return;
    }

    const senderPublicKey = this.#handshake.getPeerPublicKey(msg.from);
    if (!senderPublicKey) {
      this.#ui.addErrorMessage(`Public key not found for ${peer.nickname}`);
      return;
    }

    // Blocked: drop it here, before spending the decryption. Nothing goes back,
    // so the sender cannot tell — refusing to listen is not a message. This is
    // also the only protection that works in `general`, which has no owner.
    if (this.#trustStore.isBlocked(senderPublicKey)) {
      return;
    }

    let plaintext = preDecrypted;
    // A group message is never deniable — deniable sends stay pairwise, as they
    // do in P2P — and carries no pairwise envelope to inspect.
    const isDeniable = !preDecrypted && !!msg.payload.deniable;

    if (!plaintext) {
      const ciphertext = Buffer.from(msg.payload.ciphertext, 'base64');
      const nonce = Buffer.from(msg.payload.nonce, 'base64');

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
          this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, {
            nickname: peer.nickname,
            deniable: true,
          });
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
            msg.payload.pqCiphertext ? Buffer.from(msg.payload.pqCiphertext, 'base64') : null,
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
    }

    if (!plaintext) {
      this.#auditLog.log(AuditEvent.DECRYPT_FAILURE, { nickname: peer.nickname });
      this.#ui.addErrorMessage(`Failed to decrypt message from ${peer.nickname} (invalid MAC)`);
      return;
    }

    try {
      let data = JSON.parse(plaintext.toString('utf-8'));

      // Private-room layer: try each private buffer's key (active room first).
      // Content we can't read (no key, or stale key) is dropped silently.
      if (isRoomWrapped(data)) {
        let inner = this.#activeSecrets
          ? decryptRoomPayload(data, this.#activeSecrets.roomKey)
          : null;
        if (!inner) {
          for (const buf of this.#buffers.values()) {
            if (buf.secrets) {
              inner = decryptRoomPayload(data, buf.secrets.roomKey);
              if (inner) {
                break;
              }
            }
          }
        }
        if (!inner) {
          return;
        }
        data = JSON.parse(inner);
      }

      // Cover traffic: a decoy — drop it silently (no UI, no history, no receipt).
      if (isCover(data)) {
        return;
      }

      // A sender key. Never surfaced to the user and never carried on the group
      // path itself — it has to arrive pairwise, where the envelope proves who
      // sent it.
      if (data.action === 'sk_dist') {
        this.#onSenderKeyDistribution(msg.from, data);
        return;
      }

      // A device list. Pairwise for the same reason a sender key is: the
      // channel is what says whose it is.
      if (data.action === 'device_list') {
        this.#onDeviceList(msg.from, data);
        return;
      }

      // Which buffer this belongs to (the tag rides inside the E2EE envelope).
      const msgRoom = this.#roomForIncoming(data, msg.from);
      const roomActive = msgRoom === this.#currentRoom;

      if (data.action === 'clear') {
        this.#ui.clearBuffer(msgRoom);
        return;
      }

      if (data.action === 'typing') {
        if (roomActive) {
          this.#showPeerTyping(msg.from, peer.nickname);
        }
        return;
      }

      if (data.action === 'key_rotation') {
        this.#handshake.updatePeerKey(msg.from, data.newPublicKey);
        peer.publicKey = data.newPublicKey;
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
        // Presence lives on the global peer entry so it survives buffer
        // switches; the active view (#peers) mirrors it.
        const p = peer;
        {
          const wasAway = !!p.away;
          const oldStatus = p.status || null;
          p.away = !!data.away;
          p.awayReason = typeof data.reason === 'string' ? data.reason.slice(0, 60) : null;
          p.status = typeof data.status === 'string' ? data.status.slice(0, 60) : null;
          const view = this.#peers.get(msg.from);
          if (view) {
            view.away = p.away;
            view.awayReason = p.awayReason;
            view.status = p.status;
          }

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
        // Hang the reaction off the message itself; only fall back to a log
        // line when the target is not on screen (older or another room).
        const applied =
          roomActive && data.targetMessageId
            ? this.#applyReaction(data.targetMessageId, data.emoji)
            : false;
        if (!applied) {
          this.#ui.toBuffer(msgRoom, () => {
            this.#ui.addSystemMessage(`${data.emoji} ${peer.nickname} reacted to a message`);
          });
        }
        if (roomActive) {
          this.#ui.playNotification();
        }
        return;
      }

      if (data.action === 'edit_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (!author || author !== peer.nickname) {
          return; // only the author may rewrite their own message
        }
        const entry = this.#editableMessage(data.messageId);
        if (entry) {
          entry.text = data.newText;
          this.#ui.replaceMessageText(entry.lineIndex, entry.nickname, data.newText, entry.opts);
        } else {
          this.#ui.toBuffer(msgRoom, () => {
            this.#ui.addSystemMessage(`${peer.nickname} edited: ${data.newText} (edited)`);
          });
        }
        return;
      }

      if (data.action === 'delete_message') {
        const author = this.#messageAuthors.get(data.messageId);
        if (!author || author !== peer.nickname) {
          return;
        }
        const entry = this.#editableMessage(data.messageId);
        if (entry) {
          this.#ui.tombstoneMessage(entry.lineIndex, peer.nickname);
          this.#messageLines.delete(data.messageId);
        } else {
          this.#ui.toBuffer(msgRoom, () => {
            this.#ui.addSystemMessage(`${peer.nickname} deleted a message`);
          });
        }
        return;
      }

      if (data.action === 'set_topic') {
        const buf = this.#buffers.get(msgRoom);
        if (buf && typeof data.text === 'string') {
          const at = Number(data.at) || 0;
          // Last write wins. On join everyone who knows the topic answers, so
          // the timestamp is what keeps those replies from fighting.
          if (!buf.topic || at >= buf.topic.at) {
            const text = data.text.slice(0, 200);
            const changed = buf.topic?.text !== text;
            buf.topic = { text, by: peer.nickname, at };
            if (msgRoom === this.#currentRoom) {
              this.#applyTopicToUI();
            }
            if (changed && !data.silent) {
              this.#ui.toBuffer(msgRoom, () => {
                this.#ui.addSystemMessage(
                  text
                    ? `📋 ${peer.nickname} set the topic of #${msgRoom}: ${text}`
                    : `📋 ${peer.nickname} cleared the topic of #${msgRoom}`,
                );
              });
            }
          }
        }
        return;
      }

      if (data.action === 'pin_message') {
        const pins = roomActive ? this.#pinnedMessages : this.#buffers.get(msgRoom)?.pins;
        pins?.push({
          messageId: data.messageId,
          nickname: data.nickname,
          text: data.text,
          pinnedBy: peer.nickname,
          pinnedAt: Date.now(),
        });
        this.#ui.toBuffer(msgRoom, () => {
          this.#ui.addSystemMessage(
            `\uD83D\uDCCC ${peer.nickname} pinned: "${data.text}" \u2014 ${data.nickname}`,
          );
        });
        return;
      }

      if (data.action === 'unpin_message') {
        if (roomActive) {
          this.#pinnedMessages = this.#pinnedMessages.filter((p) => p.messageId !== data.messageId);
        } else {
          const buf = this.#buffers.get(msgRoom);
          if (buf) {
            buf.pins = buf.pins.filter((p) => p.messageId !== data.messageId);
          }
        }
        this.#ui.toBuffer(msgRoom, () => {
          this.#ui.addSystemMessage(`${peer.nickname} removed a pin`);
        });
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
          room: msgRoom,
          nickname: peer.nickname,
          text: data.text,
          isDM: !!data.isDM,
        });
      }

      // A line you sent from another device is yours. Attributing it to the
      // nickname would be technically true and would read as somebody else
      // talking; marking the device is what makes the transcript match what
      // happened.
      const fromOwnDevice = this.#isOwnDevice(peer);

      const watchHit = fromOwnDevice ? null : this.#matchedWatch(data.text);
      // A watched keyword deserves the same attention a mention gets — but not
      // when you are the one who typed it. Your own nickname in your own line
      // is not somebody calling you, and a notification for it would train you
      // to ignore the ones that matter.
      const mentioned = (this.#mentionsMe(data.text) || !!watchHit) && !data.isDM && !fromOwnDevice;
      if (watchHit) {
        this.#ui.toBuffer(msgRoom, () => {
          this.#ui.addSystemMessage(`👁 "${watchHit}" mentioned by ${peer.nickname} in #${msgRoom}`);
        });
      }
      if (mentioned) {
        this.#mentions.push({
          nickname: peer.nickname,
          text: data.text,
          room: msgRoom,
          at: Date.now(),
        });
        if (this.#mentions.length > MENTIONS_MAX) {
          this.#mentions.shift();
        }
      }
      // Away: count what's arriving and keep the header badge live.
      if (this.#away) {
        this.#awayUnread++;
        if (mentioned) {
          this.#awayMentions++;
        }
        this.#ui.setHeaderIndicator(
          'away',
          `{yellow-fg}[away · ${this.#awayUnread} new]{/yellow-fg}`,
        );
      }
      const ephLabel = data.ephemeral ? this.#formatDuration(data.ephemeral) : null;
      const displayName = fromOwnDevice ? `${peer.nickname} (your other device)` : peer.nickname;
      const trust = fromOwnDevice
        ? null
        : trustBadge(this.#trustStore.getPeerRecord(peer.nickname), peer.publicKey);
      // File the message into its buffer (live log when active, stored otherwise).
      let lineIndex = -1;
      let renderInfo = null;
      this.#ui.toBuffer(msgRoom, () => {
        if (data.replyTo?.nickname && typeof data.replyTo.excerpt === 'string') {
          this.#ui.addQuoteLine(String(data.replyTo.nickname), data.replyTo.excerpt.slice(0, 80));
        }
        ({ lineIndex, render: renderInfo } = data.isAction
          ? this.#ui.addActionMessage(displayName, data.text)
          : this.#ui.addMessage(
              displayName,
              data.text,
              !!data.isDM,
              ephLabel,
              isDeniable || !!data.deniable,
              mentioned,
              trust,
            ));
      });
      if (roomActive && data.messageId) {
        this.#rememberMessage(data.messageId, lineIndex, peer.nickname, data.text, renderInfo);
      }
      this.#noteBufferUnread(msgRoom, mentioned);
      const notify = shouldNotify(this.#dndMode, this.#dndWindow, nowMinutes(), mentioned);
      if (notify) {
        this.#ui.playNotification();
      }

      // Ephemeral burn animation only makes sense on the live log; in an
      // inactive buffer the message simply expires in place.
      if (data.ephemeral && data.ephemeral > 0 && roomActive) {
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

  // The first /watch keyword present in the text, or null.
  #matchedWatch(text) {
    for (const word of this.#watchWords) {
      if (matchesKeyword(text, word)) {
        return word;
      }
    }
    return null;
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
        this.#ui.addInfoMessage('  /tips                - Show a security/UX tip');
        this.#ui.addInfoMessage('  /users               - List online users');
        this.#ui.addInfoMessage('  /msg <nick> <text>   - Send a private message (DM)');
        this.#ui.addInfoMessage('  /reply <text>        - Reply to the last received message');
        this.#ui.addInfoMessage('  /me <action>         - Third-person action message');
        this.#ui.addInfoMessage('  /mentions [n]        - Recent mentions of you (this session)');
        this.#ui.addInfoMessage('  /watch [add|remove|clear] - Alert on a keyword in any room');
        this.#ui.addInfoMessage('  /contacts [add|remove|all] - Contact book (aliases for peers)');
        this.#ui.addInfoMessage(
          '  /away [reason]       - Mark yourself as away (unreads are counted)',
        );
        this.#ui.addInfoMessage('  /back                - Clear the away status');
        this.#ui.addInfoMessage('  /autoaway <min|off>  - Auto-away on inactivity');
        this.#ui.addInfoMessage('  /lock                - Lock the screen (session passphrase)');
        this.#ui.addInfoMessage('  /autolock <min|off>  - Auto-lock on inactivity');
        this.#ui.addInfoMessage('  /status <text|off>   - Set a status (accepts :emoji:)');
        this.#ui.addInfoMessage('  /join <room> [pass]  - Join a room as a new buffer (Alt+1..9)');
        this.#ui.addInfoMessage('  /leave [room]        - Leave a room (its buffer closes)');
        this.#ui.addInfoMessage('  /topic [text|clear]  - Show or set the room topic');
        this.#ui.addInfoMessage('  /create <room> <pass> - Create a private room 🔒');
        this.#ui.addInfoMessage('  /invite [host:port]  - Generate an invite with QR code');
        this.#ui.addInfoMessage('  /rooms               - List available rooms');
        this.#ui.addInfoMessage(
          '  /room                - Current room, how it is sending, and your buffers',
        );
        this.#ui.addInfoMessage('  /fingerprint         - Show your fingerprint');
        this.#ui.addInfoMessage('  /device [sub]        - Your devices under one identity');
        this.#ui.addInfoMessage("  /fingerprint <nick>  - Another user's fingerprint");
        this.#ui.addInfoMessage('  /verify <nick>       - Show SAS code for verification');
        this.#ui.addInfoMessage('  /verify-confirm <nick> - Confirm peer verification');
        this.#ui.addInfoMessage("  /trust <nick>        - Accept a peer's new key");
        this.#ui.addInfoMessage("  /trustlist           - Peers' trust status");
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
        this.#ui.addInfoMessage('  /search <term>       - Search the encrypted local history');
        this.#ui.addInfoMessage('  /find [term]         - Find in this room and jump (Ctrl+F)');
        this.#ui.addInfoMessage('  /doctor [host:port]  - Diagnose why a connection fails');
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
        this.#ui.addInfoMessage('  /block <nick>        - Stop seeing someone, just for you');
        this.#ui.addInfoMessage('  /unblock <nick>      - Undo a block');
        this.#ui.addInfoMessage('  /blocklist           - Who you have blocked');
        this.#ui.addInfoMessage('  /ban <nick> [reason] - Ban a user from the room (owner)');
        this.#ui.addInfoMessage('  /owner               - Show the current room owner');
        this.#ui.addInfoMessage('  /theme [name]        - Nick color theme');
        this.#ui.addInfoMessage(
          '  /panic [yes]         - Wipe EVERYTHING from disk and exit (duress)',
        );
        this.#ui.addInfoMessage(
          '  /plugins [allow <file>] - List plugins; approve one before it runs',
        );
        this.#ui.addInfoMessage('  /quit                - Leave the chat');
        this.#ui.addInfoMessage('Tip: PageUp/PageDown scroll the chat history');
        this.#ui.addInfoMessage('Tip: shortcodes like :fire: become emoji — Tab autocompletes');
        break;

      case '/users': {
        const ownDevices = [...this.#peers.values()].filter((p) => this.#isOwnDevice(p)).length;
        const names = this.#otherPeople().map(([, p]) => {
          let label = p.nickname;
          const alias = this.#trustStore.getAlias(p.nickname);
          if (alias) {
            label += ` (${alias})`;
          }
          if (p.away) {
            label += ` [away${p.awayReason ? `: ${p.awayReason}` : ''}]`;
          }
          if (p.status) {
            label += ` — ${p.status}`;
          }
          return label;
        });
        let me = `${this.#nickname} (you${ownDevices > 0 ? `, on ${ownDevices + 1} devices` : ''})`;
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
          // Shown alongside, not instead. The device fingerprint is what every
          // existing verification was made against, and it stays the thing on
          // screen until there is nothing left comparing it.
          this.#ui.addInfoMessage(`Your identity:    ${this.#keyManager.identityFingerprint}`);
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
            const boundIdentity = this.#trustStore.identityFor(found.nickname);
            if (boundIdentity) {
              this.#ui.addInfoMessage(
                `${found.nickname}'s identity:    ${identityFingerprint(boundIdentity)}`,
              );
            }
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
        const verifySid = [...this.#peers.entries()].find(
          ([, p]) => p.nickname === verifyPeer.nickname,
        )?.[0];
        const { over, code: sas } = this.sasFor(verifySid);
        this.#auditLog.log(AuditEvent.SAS_VERIFY, { nickname: verifyPeer.nickname });
        this.#ui.addInfoMessage(`SAS code for ${verifyPeer.nickname}: ${sas}`);
        // Say which keys the code is over. Both of you compute it the same way —
        // the switch is symmetric — but a code that silently changed meaning
        // between two releases is the one thing that would make comparing them
        // worthless.
        this.#ui.addInfoMessage(
          over === 'identity'
            ? '  over both identity keys — survives a device key rotation'
            : '  over both device keys — this peer has no identity key yet',
        );
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
        for (const [sid, p] of this.#peers) {
          const record = this.#trustStore.getPeerRecord(p.nickname);
          let status;
          if (!record) {
            status = 'unknown';
          } else if (record.verified) {
            status = 'verified';
          } else {
            status = 'trusted (TOFU)';
          }
          // [PQ] = this session's ratchet root also includes an ML-KEM secret.
          const pq = this.#handshake.isHybrid(sid) ? ' {green-fg}[PQ]{/green-fg}' : '';
          this.#ui.addInfoMessage(`  ${p.nickname}: ${status}${pq}`);
        }
        this.#ui.addInfoMessage('  [PQ] = hybrid post-quantum session (X25519 + ML-KEM-768)');
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
        const roomName = parts[1]?.toLowerCase();
        if (!roomName) {
          this.#ui.addErrorMessage('Usage: /join <room> [password]');
          break;
        }
        // Already have that buffer? Just focus it.
        if (this.#buffers.has(roomName)) {
          this.#switchToBuffer(roomName);
          break;
        }
        const joinPassword = parts.slice(2).join(' ');
        if (joinPassword) {
          // Derive now so we can answer the server's challenge immediately.
          this.#prepareRoomSecrets(roomName, joinPassword, () => {
            this.#connection.send(createJoinRoom(roomName));
          });
        } else {
          this.#connection.send(createJoinRoom(roomName));
        }
        break;
      }

      case '/create': {
        const roomName = parts[1]?.toLowerCase();
        if (!roomName) {
          this.#ui.addErrorMessage('Usage: /create <room> <password>');
          break;
        }
        if (this.#buffers.has(roomName)) {
          this.#ui.addErrorMessage(`You are already in #${roomName}`);
          break;
        }
        const createPassword = parts.slice(2).join(' ');
        if (!createPassword) {
          // No password — same as joining/creating a public room.
          this.#connection.send(createJoinRoom(roomName));
          break;
        }
        this.#prepareRoomSecrets(roomName, createPassword, (secrets) => {
          this.#connection.send(createJoinRoom(roomName, secrets.authPublicKey.toString('base64')));
        });
        break;
      }

      case '/leave': {
        const target = (parts[1] || this.#currentRoom).toLowerCase();
        if (!this.#buffers.has(target)) {
          this.#ui.addErrorMessage(`You are not in #${target}`);
          break;
        }
        if (this.#bufferOrder.length === 1) {
          this.#ui.addErrorMessage('Cannot leave your last room');
          break;
        }
        this.#connection.send(createLeaveRoom(target));
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

      case '/room': {
        this.#ui.addInfoMessage(
          `Current room: #${this.#currentRoom}${this.#activeSecrets ? ' 🔒 (private)' : ''}`,
        );
        this.#ui.addInfoMessage(`Sending: ${this.#describeSendPath()}`);
        if (this.#bufferOrder.length > 1) {
          const list = this.#bufferOrder
            .map((r, i) => {
              const b = this.#buffers.get(r);
              const mark = r === this.#currentRoom ? '*' : ' ';
              const unread = b?.unread ? ` (${b.unread} unread)` : '';
              return `  ${mark}${i + 1}. #${r}${b?.private ? ' 🔒' : ''}${unread}`;
            })
            .join('\n');
          this.#ui.addInfoMessage(`Buffers (Alt+1..9):\n${list}`);
        }
        break;
      }

      // ── Devices ──────────────────────────────────────────────
      //
      // Three hops, and it cannot be fewer: a new device has to say what its
      // key is before the identity can sign for it, and has to be told what
      // identity it belongs to afterwards. The identity secret never moves,
      // which is the whole point — see shared/deviceProvisioning.js.
      case '/device': {
        const sub = (parts[1] || '').toLowerCase();

        if (!sub || sub === 'list') {
          const own = this.#ownDeviceListForDisplay();
          this.#ui.addInfoMessage(
            `This device: ${this.#keyManager.deviceId.slice(0, 8)} — ` +
              (this.#keyManager.isPrimaryDevice
                ? 'holds the identity key, so it can add and remove devices'
                : 'a secondary; only the device holding the identity key can change this list'),
          );
          this.#ui.addInfoMessage(`Identity: ${this.#keyManager.identityFingerprint}`);
          if (!own) {
            this.#ui.addInfoMessage('No device list yet.');
            break;
          }
          this.#ui.addInfoMessage(`Devices (list v${own.counter}):`);
          for (const device of own.devices) {
            const mine = device.deviceId === this.#keyManager.deviceId ? ' (this one)' : '';
            const label = device.label ? ` ${device.label}` : '';
            this.#ui.addInfoMessage(`  ${device.deviceId.slice(0, 8)}${label}${mine}`);
          }
          break;
        }

        if (sub === 'request') {
          const request = buildDeviceRequest({
            deviceId: this.#keyManager.deviceId,
            boxPk: this.#keyManager.publicKeyB64,
            label: parts.slice(2).join(' ').trim(),
          });
          this.#ui.addInfoMessage(
            'Give this to the device that holds your identity key, with /device add:',
          );
          this.#ui.addPlainLines([request]);
          this.#ui.addInfoMessage(
            'It is not a secret — it is a public key. Nothing happens until the grant comes back.',
          );
          break;
        }

        if (sub === 'add') {
          if (!this.#keyManager.isPrimaryDevice) {
            this.#ui.addErrorMessage(
              'Only the device holding the identity key can add another. Run this there.',
            );
            break;
          }
          const request = parseDeviceRequest(parts.slice(2).join(' ').trim());
          if (!request) {
            this.#ui.addErrorMessage('Usage: /device add ciphermesh-device://request/…');
            break;
          }
          const grant = this.#grantDevice(request);
          if (!grant) {
            break;
          }
          this.#ui.addInfoMessage(
            `Added ${request.deviceId.slice(0, 8)}. Give this back to it with /device accept:`,
          );
          this.#ui.addPlainLines([grant]);
          break;
        }

        if (sub === 'accept') {
          this.#acceptDeviceGrant(parts.slice(2).join(' ').trim());
          break;
        }

        this.#ui.addErrorMessage('Usage: /device [list|request|add <req>|accept <grant>]');
        break;
      }

      case '/tips': {
        this.#tipIndex = (this.#tipIndex + 1) % TIPS.length;
        this.#ui.addTip(tipAt(this.#tipIndex));
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

      case '/away': {
        this.#away = true;
        this.#autoAwaySet = false; // an explicit /away is not auto
        this.#awayUnread = 0;
        this.#awayMentions = 0;
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
        this.#reportAwayUnread();
        this.#broadcastPresence();
        break;
      }

      case '/contacts': {
        const sub = (parts[1] || 'list').toLowerCase();

        if (sub === 'add') {
          const nick = parts[2];
          const alias = parts.slice(3).join(' ').trim();
          if (!nick || !alias) {
            this.#ui.addErrorMessage('Usage: /contacts add <nick> <alias>');
            break;
          }
          if (this.#trustStore.setAlias(nick, alias)) {
            this.#ui.addInfoMessage(`Contact saved: ${nick} → "${alias.slice(0, 30)}"`);
          } else {
            this.#ui.addErrorMessage(
              `"${nick}" was never seen on this identity — no trust record to alias`,
            );
          }
          break;
        }

        if (sub === 'remove') {
          const nick = parts[2];
          if (!nick) {
            this.#ui.addErrorMessage('Usage: /contacts remove <nick>');
            break;
          }
          if (this.#trustStore.clearAlias(nick)) {
            this.#ui.addInfoMessage(`Alias removed from ${nick}`);
          } else {
            this.#ui.addErrorMessage(`${nick} has no alias`);
          }
          break;
        }

        if (sub !== 'list' && sub !== 'all') {
          this.#ui.addErrorMessage('Usage: /contacts [add <nick> <alias> | remove <nick> | all]');
          break;
        }

        const contacts = this.#trustStore.listContacts(sub === 'all');
        if (contacts.length === 0) {
          this.#ui.addInfoMessage(
            sub === 'all'
              ? 'No peers known yet.'
              : 'No contacts yet. Use /contacts add <nick> <alias>',
          );
          break;
        }
        this.#ui.addInfoMessage(sub === 'all' ? 'Known peers:' : 'Contacts:');
        for (const c of contacts) {
          const badge = c.verified ? ' ✓' : '';
          const alias = c.alias ? ` (${c.alias})` : '';
          const seen = c.lastSeen
            ? ` — last seen ${new Date(c.lastSeen).toLocaleString('en-US', {
                day: '2-digit',
                month: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
              })}`
            : '';
          this.#ui.addInfoMessage(`  ${c.nickname}${alias}${badge}${seen}`);
        }
        break;
      }

      case '/topic': {
        const buf = this.#buffers.get(this.#currentRoom);
        const newTopic = parts.slice(1).join(' ').trim();

        if (!newTopic) {
          const t = buf?.topic;
          this.#ui.addInfoMessage(
            t?.text
              ? `Topic of #${this.#currentRoom}: ${t.text}  (set by ${t.by})`
              : `#${this.#currentRoom} has no topic. Set one with /topic <text>`,
          );
          break;
        }

        const text = newTopic === 'clear' ? '' : applyShortcodes(newTopic).slice(0, 200);
        const at = Date.now();
        if (buf) {
          buf.topic = { text, by: this.#nickname, at };
        }
        this.#applyTopicToUI();
        this.#paceOrSend(
          JSON.stringify({ action: 'set_topic', room: this.#currentRoom, text, at, sentAt: at }),
        );
        this.#ui.addSystemMessage(
          text ? `📋 You set the topic: ${text}` : '📋 You cleared the topic',
        );
        break;
      }

      case '/me': {
        const actionText = parts.slice(1).join(' ').trim();
        if (!actionText) {
          this.#ui.addErrorMessage('Usage: /me <action>  — e.g. /me is compiling');
          break;
        }
        this.#sendMessageToAll(actionText, null, true);
        break;
      }

      case '/watch': {
        const sub = (parts[1] || 'list').toLowerCase();
        if (sub === 'add') {
          const word = parts.slice(2).join(' ').trim();
          if (!word) {
            this.#ui.addErrorMessage('Usage: /watch add <keyword>');
            break;
          }
          this.#watchWords.add(word.toLowerCase());
          this.#ui.addInfoMessage(`Watching for "${word.toLowerCase()}" in every room`);
          break;
        }
        if (sub === 'remove' || sub === 'rm') {
          const word = parts.slice(2).join(' ').trim().toLowerCase();
          if (this.#watchWords.delete(word)) {
            this.#ui.addInfoMessage(`No longer watching "${word}"`);
          } else {
            this.#ui.addErrorMessage(`"${word}" is not being watched`);
          }
          break;
        }
        if (sub === 'clear') {
          this.#watchWords.clear();
          this.#ui.addInfoMessage('Watch list cleared');
          break;
        }
        if (sub !== 'list') {
          this.#ui.addErrorMessage('Usage: /watch [add <word> | remove <word> | clear]');
          break;
        }
        if (this.#watchWords.size === 0) {
          this.#ui.addInfoMessage('Not watching any keyword. Use /watch add <word>');
          break;
        }
        this.#ui.addInfoMessage(`Watching: ${[...this.#watchWords].join(', ')}`);
        break;
      }

      case '/mentions': {
        if (this.#mentions.length === 0) {
          this.#ui.addInfoMessage('No mentions in this session yet.');
          break;
        }
        const count = Math.min(parseInt(parts[1], 10) || 10, this.#mentions.length);
        this.#ui.addInfoMessage(`Last ${count} mention(s) of you:`);
        for (const m of this.#mentions.slice(-count)) {
          const when = new Date(m.at).toLocaleString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
          });
          this.#ui.addInfoMessage(`  [${when}] [#${m.room}] ${m.nickname}: ${m.text.slice(0, 80)}`);
        }
        break;
      }

      case '/lock':
        this.#lockNow();
        break;

      case '/autolock': {
        const alArg = parts[1]?.toLowerCase();
        if (alArg === 'off' || alArg === '0') {
          this.#autoLockMs = 0;
          this.#armAutoLock();
          this.#ui.addInfoMessage('Auto-lock disabled');
          break;
        }
        const alMin = parseInt(alArg, 10);
        if (!Number.isInteger(alMin) || alMin < 1 || alMin > 240) {
          this.#ui.addInfoMessage(
            `Auto-lock: ${this.#autoLockMs ? `${this.#autoLockMs / 60000}min` : 'off'}. Usage: /autolock <minutes|off>`,
          );
          break;
        }
        if (!this.#passphrase) {
          this.#ui.addErrorMessage(
            'No session passphrase — auto-lock needs one (set it at startup)',
          );
          break;
        }
        this.#autoLockMs = alMin * 60_000;
        this.#armAutoLock();
        this.#ui.addInfoMessage(`Auto-lock after ${alMin}min of inactivity`);
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

      case '/doctor': {
        const target = parts.slice(1).join(' ').trim() || this.#connection.url || '';
        this.#ui.addInfoMessage(`Diagnosing ${target} …`);
        diagnose(target)
          .then((steps) => {
            for (const line of formatDiagnosis(steps)) {
              this.#ui.addInfoMessage(line);
            }
          })
          .catch((err) => {
            this.#ui.addErrorMessage(`Diagnostics failed to run: ${err.message}`);
          });
        break;
      }

      case '/find': {
        const term = parts.slice(1).join(' ').trim();
        // Opens the same overlay as Ctrl+F, pre-filled when a term is given.
        this.#ui.openFinder(term);
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
        // /search reads the on-disk history (possibly from other sessions);
        // point at the navigable finder for what is actually on screen.
        this.#ui.addInfoMessage(
          `Tip: /find ${term} (or Ctrl+F) searches this room's scrollback and jumps to the message.`,
        );
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
        // Show it on the message right away instead of announcing it.
        if (!this.#applyReaction(this.#lastReceivedMessageId, emoji)) {
          this.#ui.addSystemMessage(
            `${emoji} You reacted to ${this.#lastReceivedNickname}'s message`,
          );
        }
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
        // Rewrite our own line in place, like the peers will.
        const editEntry = this.#editableMessage(this.#lastSentMessageId);
        if (editEntry) {
          editEntry.text = editText;
          this.#ui.replaceMessageText(
            editEntry.lineIndex,
            editEntry.nickname,
            editText,
            editEntry.opts,
          );
        } else {
          this.#ui.addSystemMessage(`You edited: ${editText} (edited)`);
        }
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
        const delEntry = this.#editableMessage(this.#lastSentMessageId);
        if (delEntry) {
          this.#ui.tombstoneMessage(delEntry.lineIndex, this.#nickname);
          this.#messageLines.delete(this.#lastSentMessageId);
        } else {
          this.#ui.addSystemMessage('You deleted a message');
        }
        this.#lastSentMessageId = null;
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

      // /block is nothing like /kick, /ban or /mute: those need to be the room
      // owner because they act on everyone, and this acts only on me. Nothing
      // is sent, the relay never learns, and the other person cannot tell.
      // That is why everybody gets it — and why it is the only protection that
      // works in `general`, which has no owner at all.
      case '/block': {
        const blockNick = parts[1];
        if (!blockNick) {
          this.#ui.addErrorMessage('Usage: /block <nick>');
          break;
        }
        if (this.#trustStore.blockPeer(blockNick)) {
          this.#ui.addInfoMessage(
            `Blocked ${blockNick}. You will not see their messages; they are not told.`,
          );
        } else {
          this.#ui.addErrorMessage(`No record of "${blockNick}" — you can only block someone seen`);
        }
        break;
      }

      case '/unblock': {
        const unblockNick = parts[1];
        if (!unblockNick) {
          this.#ui.addErrorMessage('Usage: /unblock <nick>');
          break;
        }
        if (this.#trustStore.unblockPeer(unblockNick)) {
          this.#ui.addInfoMessage(`Unblocked ${unblockNick}`);
        } else {
          this.#ui.addErrorMessage(`"${unblockNick}" was not blocked`);
        }
        break;
      }

      case '/blocklist': {
        const blocked = this.#trustStore.listBlocked();
        if (blocked.length === 0) {
          this.#ui.addInfoMessage('Nobody blocked');
          break;
        }
        this.#ui.addInfoMessage(`Blocked (${blocked.length}):`);
        for (const entry of blocked) {
          const label = entry.alias ? `${entry.nickname} (${entry.alias})` : entry.nickname;
          this.#ui.addInfoMessage(`  ${label}  ${entry.fingerprint}`);
        }
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
        pluginsCommand(this.#pluginManager, parts.slice(1)).then((lines) => {
          for (const { kind, text } of lines) {
            if (kind === 'error') {
              this.#ui.addErrorMessage(text);
            } else if (kind === 'system') {
              this.#ui.addSystemMessage(text);
            } else {
              this.#ui.addInfoMessage(text);
            }
          }
        });
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
        this.#connection.send(
          createJoin(
            newNick,
            this.#keyManager.publicKeyB64,
            this.#keyManager.pqPublicKeyB64,
            OWN_CAPABILITIES,
            this.#keyManager.identityPublicKeyB64,
            this.#ownDeviceListForDisplay(),
          ),
        );
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
        this.destroy(); // tears down the TUI, freeing the terminal for the animation
        farewellBanner().finally(() => process.exit(0));
        break;

      default: {
        // Try plugin commands before reporting unknown
        if (this.#pluginManager) {
          const result = this.#pluginManager.handleCommand(cmd, parts.slice(1));
          if (result) {
            // Plugin API: `{ send }` goes to the room as a normal E2EE
            // message; `{ info }` or a plain string stays local.
            if (typeof result === 'object' && typeof result.send === 'string' && result.send) {
              this.#sendMessageToAll(result.send);
            } else if (typeof result === 'object' && typeof result.info === 'string') {
              this.#ui.addInfoMessage(result.info);
            } else if (typeof result === 'string') {
              this.#ui.addInfoMessage(result);
            }
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

  // ── Private rooms: derive secrets off the input handler ─────
  // Argon2id (MODERATE) blocks for ~1s — let the UI paint the notice first.
  #prepareRoomSecrets(roomName, password, onReady) {
    const room = roomName.toLowerCase();
    this.#ui.addInfoMessage('Deriving room key (Argon2id)…');
    setImmediate(() => {
      freeRoomSecrets(this.#pendingRoomSecrets);
      const secrets = deriveRoomSecrets(room, password);
      this.#pendingRoomSecrets = { room, ...secrets };
      onReady(secrets);
    });
  }

  // ── Handle ROOM_CHALLENGE (target room is private) ──────────
  #onRoomChallenge(msg) {
    const pending = this.#pendingRoomSecrets;
    if (!pending || pending.room !== msg.room) {
      this.#ui.addErrorMessage(`Room #${msg.room} is private. Usage: /join ${msg.room} <password>`);
      return;
    }
    const signature = signRoomChallenge(
      pending.authSecretKey,
      msg.room,
      msg.nonce,
      this.#sessionId,
    );
    this.#connection.send(createRoomAuth(msg.room, msg.nonce, signature.toString('base64')));
  }

  // Promote pending password-derived secrets once the server confirms the
  // room really is private; warn when it isn't (old server or needless password).
  #promotePendingSecrets(room, isPrivate) {
    let secrets = null;
    if (this.#pendingRoomSecrets?.room === room) {
      if (isPrivate) {
        secrets = this.#pendingRoomSecrets;
      } else {
        freeRoomSecrets(this.#pendingRoomSecrets);
        this.#ui.addErrorMessage(
          'WARNING: the server treated this room as PUBLIC — anyone can join.',
        );
      }
      this.#pendingRoomSecrets = null;
    } else if (this.#pendingRoomSecrets) {
      freeRoomSecrets(this.#pendingRoomSecrets);
      this.#pendingRoomSecrets = null;
    }
    return secrets;
  }

  #announceJoinedRoom(room, isPrivate, peerNames) {
    if (isPrivate) {
      this.#ui.addSystemMessage(`You joined private room #${room} 🔒`);
      this.#ui.addInfoMessage('Messages here get an extra layer encrypted with the room key.');
    } else {
      this.#ui.addSystemMessage(`You joined room #${room}`);
    }
    if (peerNames.length > 0) {
      this.#ui.addSystemMessage(`Online: ${peerNames.join(', ')}`);
    }
    if (this.#away || this.#statusText) {
      this.#broadcastPresence();
    }
  }

  // ── Handle ROOM_CHANGED (legacy full switch — also how a kick lands) ──
  // change_room semantics: every buffer is dropped, we exist only in msg.room.
  #onRoomChanged(msg) {
    const secrets = this.#promotePendingSecrets(msg.room, !!msg.private);

    this.#resetBuffersTo(msg.room, {
      isPrivate: !!msg.private,
      owner: msg.roomOwner || null,
      secrets,
    });
    this.#currentRoomOwner = msg.roomOwner || null;

    for (const peer of msg.peers) {
      this.#allPeers.set(peer.sessionId, {
        nickname: peer.nickname,
        publicKey: peer.publicKey,
        // The relay sends these here exactly as it does in join_ack. Dropping
        // them made every peer look incapable after a room switch, which is not
        // an error anywhere — it is a room that silently never turns the group
        // path on, because one absent capability is enough to hold all of it.
        caps: normalizeCaps(peer.caps),
        rooms: new Set([msg.room]),
      });
      if (!this.#handshake.getRatchet(peer.sessionId)) {
        this.#handshake.registerPeer(peer.sessionId, peer.publicKey, peer.pqPublicKey);
      }
      if (!this.#isOwnDevice(peer)) {
        this.#checkTrust(peer.nickname, peer.publicKey);
      }
    }

    this.#rebuildActivePeers();
    // A switch drops every buffer, so it drops every chain with them. Carrying
    // one across would mean a chain drawn for one room's membership being used
    // against another's, and a keyId outliving the set of people it labelled.
    // The new room's chain is drawn on first use and distributed by the same
    // exchange as any other.
    this.#dropAllGroups();
    this.#auditLog.log(AuditEvent.ROOM_CHANGED, { room: msg.room });
    this.#announceJoinedRoom(
      msg.room,
      !!secrets,
      [...this.#peers.values()].map((p) => p.nickname),
    );
    this.#saveLastSession(!!msg.private);
  }

  // ── Handle ROOM_JOINED (additive join — new buffer, focused) ──
  #onRoomJoined(msg) {
    const secrets = this.#promotePendingSecrets(msg.room, !!msg.private);
    this.#ensureBuffer(msg.room, {
      isPrivate: !!msg.private,
      owner: msg.roomOwner || null,
      secrets,
    });

    for (const peer of msg.peers || []) {
      const existing = this.#allPeers.get(peer.sessionId);
      if (existing) {
        existing.rooms.add(msg.room);
      } else {
        this.#allPeers.set(peer.sessionId, {
          nickname: peer.nickname,
          publicKey: peer.publicKey,
          caps: normalizeCaps(peer.caps),
          rooms: new Set([msg.room]),
        });
        if (!this.#handshake.getRatchet(peer.sessionId)) {
          this.#handshake.registerPeer(peer.sessionId, peer.publicKey, peer.pqPublicKey);
        }
      }
      if (!this.#isOwnDevice(peer)) {
        this.#checkTrust(peer.nickname, peer.publicKey);
      }
    }

    this.#auditLog.log(AuditEvent.ROOM_CHANGED, { room: msg.room, additive: true });
    this.#switchToBuffer(msg.room);
    this.#announceJoinedRoom(
      msg.room,
      !!secrets,
      [...this.#peers.values()].map((p) => p.nickname),
    );
    this.#updateBufferBar();
  }

  // ── Handle ROOM_LEFT (we left one room; buffer dies) ─────────
  #onRoomLeft(msg) {
    const room = msg.room;
    const wasActive = room === this.#currentRoom;
    this.#dropBufferState(room);

    // Peers we only shared that room with are gone for us now.
    for (const [sid, p] of [...this.#allPeers]) {
      p.rooms.delete(room);
      if (p.rooms.size === 0) {
        this.#hidePeerTyping(sid, p.nickname);
        this.#handshake.removePeer(sid);
        this.#nonceManager.removePeer(sid);
        this.#allPeers.delete(sid);
      }
    }

    if (wasActive && this.#bufferOrder.length > 0) {
      this.#switchToBuffer(this.#bufferOrder[0]);
    } else {
      this.#rebuildActivePeers();
      this.#updateBufferBar();
    }
    this.#ui.addSystemMessage(`You left #${room}`);
    this.#auditLog.log(AuditEvent.ROOM_CHANGED, { room, left: true });
  }

  // ── Handle ROOM_LIST ───────────────────────────────────────
  #onRoomList(msg) {
    this.#ui.addInfoMessage('Available rooms:');
    for (const room of msg.rooms) {
      const current = room.name === this.#currentRoom ? ' (current)' : '';
      const lock = room.private ? ' 🔒' : '';
      this.#ui.addInfoMessage(`  #${room.name}${lock} — ${room.memberCount} member(s)${current}`);
    }
  }

  // ── Handle PEER_KICKED ────────────────────────────────────
  #onPeerKicked(msg) {
    // The relay sends this immediately before the peer_left for the same
    // session. Remember it so the departure is reported as a kick and not
    // announced twice; the state work still happens in #onPeerLeft, which is
    // the one place that knows how to unwind a member.
    if (typeof msg.sessionId === 'string') {
      // A kick whose peer_left never arrives (an older relay) must not park an
      // entry here forever.
      if (this.#kickedSessions.size >= 64) {
        this.#kickedSessions.clear();
      }
      this.#kickedSessions.add(msg.sessionId);
    }
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
    // Line indexes are only valid on the live log — skip the ✓✓ update when
    // the message's buffer isn't on screen (multi-room v1 limitation).
    if (tracked.room && tracked.room !== this.#currentRoom) {
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

  // Remember where a message was drawn so reactions/edits/deletes can change
  // it in place. Bounded like the receipt tracker.
  #rememberMessage(messageId, lineIndex, nickname, text, render) {
    if (!messageId || lineIndex === undefined || lineIndex < 0) {
      return;
    }
    this.#messageLines.set(messageId, {
      lineIndex,
      nickname,
      text,
      opts: render?.opts || {},
      room: this.#currentRoom,
    });
    if (this.#messageLines.size > 200) {
      const oldest = this.#messageLines.keys().next().value;
      this.#messageLines.delete(oldest);
      this.#reactions.delete(oldest);
    }
  }

  // A message can only be redrawn while its room is the one on screen.
  #editableMessage(messageId) {
    const entry = this.#messageLines.get(messageId);
    if (!entry || entry.room !== this.#currentRoom) {
      return null;
    }
    return entry;
  }

  #applyReaction(messageId, emoji) {
    const entry = this.#editableMessage(messageId);
    if (!entry) {
      return false;
    }
    const counts = this.#reactions.get(messageId) || new Map();
    counts.set(emoji, (counts.get(emoji) || 0) + 1);
    this.#reactions.set(messageId, counts);

    // Re-render the line, then hang the reactions off the end of it.
    const badge = [...counts.entries()].map(([e, n]) => (n > 1 ? `${e}${n}` : e)).join(' ');
    this.#ui.replaceMessageText(entry.lineIndex, entry.nickname, entry.text, {
      ...entry.opts,
      edited: entry.opts?.edited,
    });
    const rebuilt = this.#ui.getLine(entry.lineIndex);
    this.#ui.appendBadge(entry.lineIndex, rebuilt, badge);
    return true;
  }

  #trackSentMessage(messageId, lineIndex) {
    const baseLine = this.#ui.getLine(lineIndex);
    if (baseLine === null || baseLine === undefined) {
      return;
    }
    this.#sentMessageLines.set(messageId, { lineIndex, baseLine, room: this.#currentRoom });

    // Bound memory: keep only the most recent 200 tracked messages
    if (this.#sentMessageLines.size > 200) {
      const oldest = this.#sentMessageLines.keys().next().value;
      this.#sentMessageLines.delete(oldest);
      this.#messageReaders.delete(oldest);
    }
  }

  // Sealed sender: wrap an outgoing wire message so the relay sees only `to` and
  // an opaque blob. The sender identity (`from`) + the payload are sealed to the
  // recipient's key — only they can open it.
  #sealAndSend(recipientPublicKey, wireMsg) {
    const sealed = sealEnvelope(wireMsg.from, wireMsg.payload, recipientPublicKey);
    this.#connection.send(createSealedMessage(wireMsg.to, sealed));
  }

  // Open a sealed envelope with our identity key, falling back to the previous
  // key during the post-rotation grace window. Returns { from, payload } or null.
  #openSealed(sealedB64) {
    let opened = openEnvelope(sealedB64, this.#keyManager.publicKey, this.#keyManager.secretKey);
    if (!opened && this.#keyManager.previousPublicKey) {
      opened = openEnvelope(
        sealedB64,
        this.#keyManager.previousPublicKey,
        this.#keyManager.previousSecretKey,
      );
    }
    return opened;
  }

  // ── Send encrypted payload to a single peer ────────────────────
  #sendPayloadToPeer(peerId, payload) {
    const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
    if (!peerPublicKey) {
      return;
    }

    // Tag with the active room (inside the E2EE envelope), then the private
    // room's extra symmetric layer when there is one.
    payload = this.#tagRoom(payload);
    if (this.#activeSecrets) {
      payload = encryptRoomPayload(payload, this.#activeSecrets.roomKey);
    }

    const ratchet = this.#handshake.getRatchet(peerId);
    if (ratchet && ratchet.isInitialized) {
      try {
        const result = ratchet.encrypt(payload);
        this.#sealAndSend(peerPublicKey, createRatchetedMessage(this.#sessionId, peerId, result));
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
    this.#sealAndSend(
      peerPublicKey,
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
    // Tag with the active room (inside the E2EE envelope), then the private
    // room's extra symmetric layer, so even a relay-injected member can't
    // read the room without the password.
    payload = this.#tagRoom(payload);
    if (this.#activeSecrets) {
      payload = encryptRoomPayload(payload, this.#activeSecrets.roomKey);
    }

    // One ciphertext for the room, when the room and the relay can both take
    // one. Everything above this line has already run, so the bytes inside are
    // identical either way — including cover traffic, which has to travel the
    // path real messages travel or it stops resembling them.
    if (this.#canSendToGroup(deniable)) {
      this.#sendRoomGroup(this.#currentRoom, payload);
      return;
    }

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
        this.#sealAndSend(peerPublicKey, msg);
        continue;
      }

      // Try ratchet path (PFS) first
      const ratchet = this.#handshake.getRatchet(peerId);
      if (ratchet && ratchet.isInitialized) {
        try {
          const result = ratchet.encrypt(payload);
          this.#sealAndSend(peerPublicKey, createRatchetedMessage(this.#sessionId, peerId, result));
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

      this.#sealAndSend(
        peerPublicKey,
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
  #sendMessageToAll(text, replyTo = null, isAction = false) {
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
    if (isAction) {
      msgObj.isAction = true;
    }
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
    const { lineIndex, render } = isAction
      ? this.#ui.addActionMessage(this.#nickname, text)
      : this.#ui.addMessage(this.#nickname, text, false, ephLabel, this.#deniableMode);
    this.#rememberMessage(messageId, lineIndex, this.#nickname, text, render);

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
    this.#dropAllGroups();
    this.#handshake.destroy();
    this.#keyManager.destroy();
    this.#connection.close();
    this.#ui.destroy();
  }
}
