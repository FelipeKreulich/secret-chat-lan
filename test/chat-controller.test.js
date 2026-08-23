import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { ChatController } from '../src/client/ChatController.js';
import { CAP, PROTOCOL_VERSION, SERVER_CAPABILITIES } from '../src/shared/constants.js';
import {
  MSG,
  ERR,
  createJoinAck,
  createPeerJoined,
  createRoomChanged,
  createError,
  createGroupMessage,
  createSealedMessage,
} from '../src/protocol/messages.js';
import { GroupSession } from '../src/crypto/SenderKey.js';
import { NonceManager } from '../src/crypto/NonceManager.js';
import * as MessageCrypto from '../src/crypto/MessageCrypto.js';
import { sealEnvelope } from '../src/crypto/SealedSender.js';

// ── Mocks ────────────────────────────────────────────────────────
// The relay client talks to a single server socket. MockConn stands in for it
// and, when attached to a Hub, routes JOIN/ENCRYPTED/CHANGE_ROOM like the real
// server would — enough to drive two controllers end-to-end.
class MockConn extends EventEmitter {
  connected = false;
  url = 'wss://test:3600';
  sent = [];
  hub = null;
  client = null;
  // Mirror the real Connection: not connected until the socket opens. Flip the
  // flag as the lifecycle events fire so `connection.connected` stays truthful.
  emit(event, ...args) {
    if (event === 'connected') {
      this.connected = true;
    } else if (event === 'disconnected') {
      this.connected = false;
    }
    return super.emit(event, ...args);
  }
  send(msg) {
    this.sent.push(msg);
    if (this.hub) {
      this.hub.route(this, msg);
    }
    return true;
  }
  connect() {}
  destroy() {}
  sentOfType(type) {
    return this.sent.filter((m) => m.type === type);
  }
}

function mockUI() {
  const rec = {
    system: [],
    errors: [],
    info: [],
    messages: [],
    plain: [],
    connState: [],
    handshakes: [],
    disconnects: [],
    room: null,
    cleared: 0,
    locks: [],
  };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: (nick, text, isDM, ephLabel, deniable, mentioned, trust) => {
      rec.messages.push({ nick, text, isDM, mentioned, trust });
      return { lineIndex: rec.messages.length - 1, render: { nickname: nick, opts: {} } };
    },
    replaceMessageText: (lineIndex, nick, newText) => {
      rec.messages[lineIndex] = { ...rec.messages[lineIndex], text: newText, edited: true };
    },
    tombstoneMessage: (lineIndex, nick) => {
      rec.messages[lineIndex] = { nick, text: null, deleted: true };
    },
    getLine: (i) => rec.messages[i]?.text ?? null,
    appendBadge: (lineIndex, baseLine, badge) => {
      rec.messages[lineIndex] = { ...rec.messages[lineIndex], badge };
    },
    addActionMessage: (nick, text) => {
      rec.messages.push({ nick, text, isAction: true });
      return { lineIndex: rec.messages.length - 1 };
    },
    addPlainLines: (lines) => rec.plain.push(...lines),
    setConnectionState: (s) => rec.connState.push(s),
    handshakeConnect: (n) => rec.handshakes.push(n),
    handshakeDisconnect: (n) => rec.disconnects.push(n),
    setRoom: (r) => {
      rec.room = r;
    },
    clearChat: () => {
      rec.cleared++;
    },
    showLock: (verify) => {
      rec.locks.push(verify);
    },
    isLocked: false,
    // Buffer plumbing: tests record everything into the same rec, so content
    // "filed to an inactive buffer" is still assertable.
    resetBuffers: (room) => {
      rec.room = room;
    },
    switchBuffer: (room) => {
      rec.room = room;
    },
    toBuffer: (room, fn) => fn(),
    dropBuffer: () => {},
    clearBuffer: () => {
      rec.cleared++;
    },
    setBufferBar: (items) => {
      rec.bufferBar = items;
    },
    setTopic: (t) => {
      rec.topic = t;
    },
    openFinder: (q) => {
      rec.finderOpened = q;
    },
    soundEnabled: true,
    notifyEnabled: false,
    on: emitter.on.bind(emitter),
    emit: emitter.emit.bind(emitter),
    _rec: rec,
  };
  // Auto-stub any other UI method the controller happens to call.
  return new Proxy(target, {
    get(t, prop) {
      if (prop in t) return t[prop];
      return () => {};
    },
  });
}

// Minimal in-memory relay with multi-room membership (mirrors the real server:
// join_room is additive, leave_room scoped, change_room the legacy full switch).
class Hub {
  constructor() {
    this.clients = [];
    this._n = 0;
    // What this hub advertises about itself. Set to [] to stand in for a relay
    // too old to fan a room-addressed message out.
    this.serverCaps = SERVER_CAPABILITIES;
  }
  attach(client) {
    client.conn.hub = this;
    client.conn.client = client;
    this.clients.push(client);
  }
  #peersFor(me, room) {
    return this.clients
      .filter((c) => c !== me && c.joined && c.rooms.has(room))
      .map((c) => ({
        sessionId: c.sid,
        nickname: c.nick,
        publicKey: c.pk,
        // Mirrors the real relay: relayed verbatim, omitted when empty.
        ...(c.caps?.length ? { caps: [...c.caps] } : {}),
        ...(c.identityKey ? { identityKey: c.identityKey } : {}),
      }));
  }
  #peerRecord(c) {
    return {
      sessionId: c.sid,
      nickname: c.nick,
      publicKey: c.pk,
      ...(c.caps?.length ? { caps: [...c.caps] } : {}),
      ...(c.identityKey ? { identityKey: c.identityKey } : {}),
    };
  }
  #toRoom(room, exclude, msg) {
    for (const c of this.clients) {
      if (c !== exclude && c.joined && c.rooms.has(room)) {
        c.conn.emit('message', msg);
      }
    }
  }
  route(conn, msg) {
    const me = conn.client;
    if (!me) return;
    switch (msg.type) {
      case MSG.JOIN: {
        me.sid = `s${++this._n}`;
        me.rooms = new Set(['general']);
        me.pk = msg.publicKey;
        me.nick = msg.nickname;
        // `advertise` lets a test stand this peer up as a newer build than the
        // one under test, which is the only way to exercise negotiation while
        // OWN_CAPABILITIES is still empty.
        me.caps = me.advertise || msg.caps || [];
        // `advertiseIdentity: null` stands a client up as a build from before
        // identity keys existed.
        me.identityKey =
          me.advertiseIdentity === undefined ? msg.identityKey : me.advertiseIdentity;
        me.joined = true;
        conn.emit(
          'message',
          createJoinAck(me.sid, this.#peersFor(me, 'general'), 0, 'general', this.serverCaps),
        );
        this.#toRoom('general', me, createPeerJoined(this.#peerRecord(me), 'general'));
        break;
      }
      case MSG.ENCRYPTED_MESSAGE: {
        const target = this.clients.find((c) => c.sid === msg.to && c.joined);
        if (target && [...me.rooms].some((r) => target.rooms.has(r))) {
          target.conn.emit('message', msg);
        }
        break;
      }
      case MSG.GROUP_MESSAGE: {
        // Mirrors the real relay: fan one ciphertext out to the room, sender
        // excluded, only for a room the sender is actually in, nothing stamped.
        if (!me.rooms.has(msg.room)) break;
        this.#toRoom(msg.room, me, msg);
        break;
      }
      case MSG.JOIN_ROOM: {
        if (me.rooms.has(msg.room)) break;
        me.rooms.add(msg.room);
        this.#toRoom(msg.room, me, createPeerJoined(this.#peerRecord(me), msg.room));
        conn.emit('message', {
          ...createRoomChanged(msg.room, this.#peersFor(me, msg.room)),
          type: MSG.ROOM_JOINED,
        });
        break;
      }
      case MSG.LEAVE_ROOM: {
        if (!me.rooms.has(msg.room) || me.rooms.size === 1) break;
        me.rooms.delete(msg.room);
        this.#toRoom(msg.room, me, {
          type: MSG.PEER_LEFT,
          version: 2,
          timestamp: Date.now(),
          sessionId: me.sid,
          nickname: me.nick,
          room: msg.room,
        });
        conn.emit('message', {
          type: MSG.ROOM_LEFT,
          version: 2,
          timestamp: Date.now(),
          room: msg.room,
        });
        break;
      }
      case MSG.CHANGE_ROOM: {
        me.rooms = new Set([msg.room]);
        conn.emit('message', createRoomChanged(msg.room, this.#peersFor(me, msg.room)));
        break;
      }
    }
  }
}

// ── Tests ────────────────────────────────────────────────────────
describe('ChatController (relay client)', () => {
  let cwd;
  let home;
  let tempDir;
  const spawned = [];

  beforeEach(() => {
    // Contain file I/O (TrustStore/FileTransfer use cwd, AuditLog uses HOME).
    tempDir = mkdtempSync(join(tmpdir(), 'ciphermesh-relay-'));
    cwd = process.cwd();
    home = process.env.HOME;
    process.chdir(tempDir);
    process.env.HOME = tempDir;
    spawned.length = 0;
  });

  afterEach(() => {
    for (const c of spawned) {
      try {
        c.controller.destroy();
      } catch {
        /* ignore */
      }
    }
    process.chdir(cwd);
    process.env.HOME = home;
    rmSync(tempDir, { recursive: true, force: true });
  });

  const spawn = (nick = 'alice', opts = {}) => {
    const conn = new MockConn();
    const ui = mockUI();
    const controller = new ChatController(
      nick,
      conn,
      ui,
      opts.restoredState || null,
      opts.pluginManager || null,
    );
    const client = { conn, ui, controller, nick, joined: false };
    spawned.push(client);
    return client;
  };

  // Bring a client online through a hub (JOIN → JOIN_ACK handshake).
  const online = (hub, client) => {
    hub.attach(client);
    client.conn.emit('connected');
  };

  const input = (client, text) => client.ui.emit('input', text);
  const rec = (client) => client.ui._rec;

  // ── Command handling ───────────────────────────────────────────
  it('/help lists the available commands', () => {
    const a = spawn();
    input(a, '/help');
    assert.ok(rec(a).info.some((m) => m.includes('/quit')));
    assert.ok(rec(a).info.some((m) => m.includes('/verify')));
  });

  it('suggests the nearest command for a typo', () => {
    const a = spawn();
    input(a, '/qut');
    assert.ok(rec(a).errors.some((m) => m.includes('/quit')));
  });

  it('reports an unknown command with no close match', () => {
    const a = spawn();
    input(a, '/zxcvbnm');
    assert.ok(rec(a).errors.some((m) => m.includes('Unknown command') && m.includes('/help')));
  });

  it('/deniable toggles the mode on and off', () => {
    const a = spawn();
    input(a, '/deniable on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('enabled')));
    rec(a).info.length = 0;
    input(a, '/deniable off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('disabled')));
  });

  it('/receipts toggles read receipts', () => {
    const a = spawn();
    input(a, '/receipts off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('disabled')));
    input(a, '/receipts on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('enabled')));
  });

  it('/away then /back toggles presence; /back alone is a no-op notice', () => {
    const a = spawn();
    input(a, '/back');
    assert.ok(rec(a).info.some((m) => m.includes('not away')));
    input(a, '/away lunch');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('away')));
    input(a, '/back');
    assert.ok(rec(a).info.some((m) => m.includes('back')));
  });

  it('counts messages received while away and summarizes on /back', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/away lunch');
    input(b, 'primeira mensagem');
    input(b, 'oi @alice tudo bem?');
    assert.equal(rec(a).messages.length, 2, 'away still receives and shows messages');

    input(a, '/back');
    const summary = rec(a).system.find((m) => m.includes('While you were away'));
    assert.ok(summary, 'back shows an unread summary');
    assert.ok(summary.includes('2 new message(s)'), summary);
    assert.ok(summary.includes('1 mention(s)'), summary);

    // Counters reset: going away and coming back with no traffic → no summary.
    input(a, '/away');
    input(a, '/back');
    const summaries = rec(a).system.filter((m) => m.includes('While you were away'));
    assert.equal(summaries.length, 1, 'no summary when nothing arrived');
  });

  it('/lock requires a session passphrase and hands the UI a working verifier', () => {
    const noPass = spawn('alice');
    input(noPass, '/lock');
    assert.ok(rec(noPass).errors.some((m) => m.includes('passphrase')));
    assert.equal(rec(noPass).locks.length, 0);

    const a = spawn('ana', { restoredState: { passphrase: 'segredo' } });
    input(a, '/lock');
    assert.equal(rec(a).locks.length, 1, 'UI lock engaged');
    const verify = rec(a).locks[0];
    assert.equal(verify('errada'), false);
    assert.equal(verify('segredo'), true);
  });

  it('/autolock validates minutes and needs a passphrase', () => {
    const a = spawn('ana', { restoredState: { passphrase: 'segredo' } });
    input(a, '/autolock 5');
    assert.ok(rec(a).info.some((m) => m.includes('Auto-lock after 5min')));
    input(a, '/autolock off');
    assert.ok(rec(a).info.some((m) => m.includes('Auto-lock disabled')));
    input(a, '/autolock 999');
    assert.ok(rec(a).info.some((m) => m.includes('Usage: /autolock')));

    const noPass = spawn('bob');
    input(noPass, '/autolock 5');
    assert.ok(rec(noPass).errors.some((m) => m.includes('passphrase')));
  });

  it('plugin { send } result reaches the room E2EE; { info } stays local', () => {
    const pluginManager = {
      handleCommand: (cmd) =>
        cmd === '/eco'
          ? { send: 'eco do plugin!' }
          : cmd === '/local'
            ? { info: 'só local' }
            : null,
    };
    const hub = new Hub();
    const a = spawn('alice', { pluginManager });
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/eco');
    assert.ok(
      rec(b).messages.some((m) => m.text === 'eco do plugin!'),
      'peer received the plugin message',
    );

    input(a, '/local');
    assert.ok(rec(a).info.includes('só local'));
    assert.ok(
      !rec(b).messages.some((m) => m.text === 'só local'),
      'info result never leaves the client',
    );

    input(a, '/inexistente');
    assert.ok(rec(a).errors.some((m) => m.includes('Unknown command')));
  });

  it('/contacts adds, lists and removes aliases; /users shows them', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b); // alice records bob's key via TOFU on PEER_JOINED

    input(a, '/contacts');
    assert.ok(rec(a).info.some((m) => m.includes('No contacts yet')));

    input(a, '/contacts add bob Bob da Firma');
    assert.ok(rec(a).info.some((m) => m.includes('Contact saved')));

    input(a, '/contacts add ghost Fulano');
    assert.ok(rec(a).errors.some((m) => m.includes('never seen')));

    rec(a).info.length = 0;
    input(a, '/contacts');
    assert.ok(rec(a).info.some((m) => m.includes('bob') && m.includes('Bob da Firma')));

    rec(a).info.length = 0;
    input(a, '/users');
    assert.ok(
      rec(a).info.some((m) => m.includes('bob (Bob da Firma)')),
      '/users shows the alias',
    );

    input(a, '/contacts remove bob');
    rec(a).info.length = 0;
    input(a, '/contacts');
    assert.ok(rec(a).info.some((m) => m.includes('No contacts yet')));
  });

  it('multi-room: /join opens a buffer, messages are tagged and filed with unread', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    // Alice opens #dev (additive) — auto-focused.
    input(a, '/join dev');
    assert.equal(rec(a).room, 'dev', 'new buffer focused');
    assert.ok(rec(a).system.some((m) => m.includes('You joined room #dev')));

    // Bob follows; both are still in general too.
    input(b, '/join dev');
    assert.equal(rec(b).room, 'dev');

    // Bob talks in #dev; Alice (also in #dev, active) sees it live.
    input(b, 'papo de dev');
    assert.ok(rec(a).messages.some((m) => m.text === 'papo de dev'));

    // Alice goes back to #general (Alt+1); Bob keeps talking in #dev →
    // unread badge on Alice's dev buffer, message still filed.
    a.ui.emit('buffer-switch', 0);
    assert.equal(rec(a).room, 'general');
    input(b, 'mensagem no dev enquanto alice esta no general');
    const devBadge = rec(a).bufferBar?.find((x) => x.room === 'dev');
    assert.equal(devBadge?.unread, 1, 'inactive buffer counts unread');
    assert.ok(
      rec(a).messages.some((m) => m.text.includes('enquanto alice')),
      'message filed into the dev buffer',
    );

    // Switching back clears the badge.
    a.ui.emit('buffer-switch', 1);
    assert.equal(rec(a).room, 'dev');
    assert.equal(
      rec(a).bufferBar?.find((x) => x.room === 'dev')?.unread,
      0,
      'unread cleared on focus',
    );
  });

  it('multi-room: /leave closes the buffer and refuses the last room', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);

    input(a, '/leave');
    assert.ok(rec(a).errors.some((m) => m.includes('last room')));

    input(a, '/join dev');
    input(a, '/leave dev');
    assert.equal(rec(a).room, 'general', 'active buffer falls back after leaving');
    assert.ok(rec(a).system.some((m) => m.includes('You left #dev')));

    input(a, '/leave fantasma');
    assert.ok(rec(a).errors.some((m) => m.includes('not in #fantasma')));
  });

  it('multi-room: legacy room_changed collapses every buffer (kick semantics)', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);
    input(a, '/join dev');
    input(a, '/join ops');
    assert.equal(rec(a).bufferBar.length, 3);

    // Server-side full switch (how a kick lands you in #general).
    a.conn.emit('message', createRoomChanged('general', []));
    assert.equal(rec(a).room, 'general');
    assert.equal(rec(a).bufferBar.length, 1, 'only one buffer survives');
  });

  it('persists the last session (server + room) on join and room change', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);

    const path = join(tempDir, '.ciphermesh', 'last-session.json');
    let saved = JSON.parse(readFileSync(path, 'utf-8'));
    assert.equal(saved.server, 'test:3600', 'server saved without the wss:// prefix');
    assert.equal(saved.room, 'general');

    input(a, '/join sala2');
    saved = JSON.parse(readFileSync(path, 'utf-8'));
    assert.equal(saved.room, 'sala2');

    // A private room must never write its name to disk — only the server.
    a.conn.emit('message', { ...createRoomChanged('cofre', []), private: true });
    saved = JSON.parse(readFileSync(path, 'utf-8'));
    assert.equal(saved.server, 'test:3600');
    assert.equal(saved.room, undefined, 'private room name stays off disk');
  });

  it('/topic sets, shows and clears the room topic across peers', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/topic');
    assert.ok(rec(a).info.some((m) => m.includes('has no topic')));

    input(a, '/topic planejamento da sprint');
    assert.equal(rec(a).topic, 'planejamento da sprint', 'status bar updated locally');
    assert.ok(rec(a).system.some((m) => m.includes('You set the topic')));

    // The peer learns it over the E2EE channel.
    assert.equal(rec(b).topic, 'planejamento da sprint', "peer's status bar updated");
    assert.ok(rec(b).system.some((m) => m.includes('alice') && m.includes('planejamento')));

    rec(b).info.length = 0;
    input(b, '/topic');
    assert.ok(rec(b).info.some((m) => m.includes('planejamento da sprint')));

    input(a, '/topic clear');
    assert.equal(rec(a).topic, null);
    assert.equal(rec(b).topic, null, 'clearing propagates too');
  });

  it('a newcomer is told the topic without spamming the log', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);
    input(a, '/topic sala de deploys');

    // Bob arrives after the topic was set.
    const b = spawn('bob');
    online(hub, b);

    assert.equal(rec(b).topic, 'sala de deploys', 'newcomer synced');
    assert.equal(
      rec(b).system.filter((m) => m.includes('📋')).length,
      0,
      'the sync is silent — no chat noise',
    );
  });

  it('a reaction lands ON the message, not as a loose log line', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, 'mensagem que vai receber reacao');
    input(b, '/react :fire:');

    // Alice (the author) sees the reaction attached to her own line.
    const authored = rec(a).messages.find((m) => m.text === 'mensagem que vai receber reacao');
    assert.ok(authored.badge?.includes('🔥'), 'reaction badge on the message');
    assert.ok(
      !rec(a).system.some((m) => m.includes('reacted to a message')),
      'no loose system line when the message is on screen',
    );

    // And bob, who reacted, sees it on the message too.
    const seen = rec(b).messages.find((m) => m.text === 'mensagem que vai receber reacao');
    assert.ok(seen.badge?.includes('🔥'));
  });

  it('/edit rewrites the original line and /delete leaves a tombstone', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, 'texto com errro');
    input(a, '/edit texto corrigido');

    const mine = rec(a).messages.find((m) => m.edited);
    assert.equal(mine.text, 'texto corrigido', 'own line rewritten in place');
    assert.ok(
      !rec(a).messages.some((m) => m.text === 'texto com errro'),
      'the old text is gone, not stacked below',
    );

    const theirs = rec(b).messages.find((m) => m.edited);
    assert.equal(theirs.text, 'texto corrigido', 'peer sees the same rewrite');

    input(a, '/delete');
    assert.ok(
      rec(a).messages.some((m) => m.deleted),
      'own message becomes a tombstone',
    );
    assert.ok(
      rec(b).messages.some((m) => m.deleted),
      'peer sees the tombstone too',
    );
  });

  it('edits from either side rewrite the right line', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    // Bob writes and edits; alice must see HIS line change, not hers.
    input(a, 'linha da alice');
    input(b, 'linha do bob');
    input(b, '/edit linha do bob corrigida');

    const edited = rec(a).messages.find((m) => m.edited);
    assert.equal(edited.text, 'linha do bob corrigida');
    assert.equal(edited.nick, 'bob', 'the edit landed on bob line');
    assert.ok(
      rec(a).messages.some((m) => m.text === 'linha da alice' && !m.edited),
      'alice own message is untouched',
    );
  });

  it('/find opens the navigable finder, pre-filled when given a term', () => {
    const a = spawn('alice');

    input(a, '/find');
    assert.equal(rec(a).finderOpened, '', 'opens empty for interactive typing');

    input(a, '/find deploy da sexta');
    assert.equal(rec(a).finderOpened, 'deploy da sexta', 'pre-filled with the term');
  });

  it('/me sends a third-person action that peers render as an action', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/me');
    assert.ok(rec(a).errors.some((m) => m.includes('Usage: /me')));

    input(a, '/me está compilando');
    const mine = rec(a).messages.find((m) => m.text === 'está compilando');
    assert.ok(mine?.isAction, 'own echo is an action line');

    const theirs = rec(b).messages.find((m) => m.text === 'está compilando');
    assert.ok(theirs?.isAction, 'peer renders it as an action too');
    assert.equal(theirs.nick, 'alice');
  });

  it('/watch alerts on a keyword like a mention would', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/watch');
    assert.ok(rec(a).info.some((m) => m.includes('Not watching any keyword')));

    input(a, '/watch add deploy');
    assert.ok(rec(a).info.some((m) => m.includes('deploy')));

    input(b, 'vamos falar de deploy amanha');
    assert.ok(
      rec(a).system.some((m) => m.includes('👁') && m.includes('deploy')),
      'watch hit is announced',
    );
    const msg = rec(a).messages.find((m) => m.text.includes('deploy'));
    assert.equal(msg.mentioned, true, 'highlighted like a mention');

    // Substring must not fire.
    rec(a).system.length = 0;
    input(b, 'redeploying agora');
    assert.equal(
      rec(a).system.filter((m) => m.includes('👁')).length,
      0,
      'substring does not trigger',
    );

    input(a, '/watch remove deploy');
    assert.ok(rec(a).info.some((m) => m.includes('No longer watching')));
    input(a, '/watch remove inexistente');
    assert.ok(rec(a).errors.some((m) => m.includes('not being watched')));
  });

  it('/mentions lists session mentions and is empty by default', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    input(a, '/mentions');
    assert.ok(rec(a).info.some((m) => m.includes('No mentions')));

    input(b, 'oi @alice, olha isso');
    input(b, 'mensagem sem mencao');
    input(a, '/mentions');

    const lines = rec(a).info.filter((m) => m.includes('#general') && m.includes('bob'));
    assert.equal(lines.length, 1, 'only the mentioning message is listed');
    assert.ok(lines[0].includes('@alice'));

    // DMs never count as mentions (they are already targeted at you).
    input(b, '/msg alice oi @alice em privado');
    input(a, '/mentions');
    const dmLines = rec(a).info.filter((m) => m.includes('em privado'));
    assert.equal(dmLines.length, 0, 'DM mention is not logged');
  });

  it('/status sets and clears the status text', () => {
    const a = spawn();
    input(a, '/status coding');
    assert.ok(rec(a).info.some((m) => m.includes('coding')));
    input(a, '/status off');
    assert.ok(rec(a).info.some((m) => m.includes('cleared')));
  });

  it('/room reports the current room', () => {
    const a = spawn();
    input(a, '/room');
    assert.ok(rec(a).info.some((m) => m.includes('#general')));
  });

  it('/join with no argument errors; with one it sends an additive join_room', () => {
    const a = spawn();
    input(a, '/join');
    assert.ok(rec(a).errors.some((m) => m.includes('Usage: /join')));
    input(a, '/join project');
    assert.equal(a.conn.sentOfType(MSG.JOIN_ROOM).length, 1);
    assert.equal(a.conn.sentOfType(MSG.JOIN_ROOM)[0].room, 'project');
  });

  it('/rooms asks the server for the room list', () => {
    const a = spawn();
    input(a, '/rooms');
    assert.equal(a.conn.sentOfType(MSG.LIST_ROOMS).length, 1);
  });

  it('/owner says #general has no owner', () => {
    const a = spawn();
    input(a, '/owner');
    assert.ok(rec(a).info.some((m) => m.includes('#general') && m.includes('no owner')));
  });

  it('/reject with no pending offer reports nothing pending', () => {
    const a = spawn();
    input(a, '/reject');
    assert.ok(rec(a).errors.some((m) => m.includes('No pending file offer')));
  });

  it('/react with nothing to react to errors', () => {
    const a = spawn();
    input(a, '/react :fire:');
    assert.ok(rec(a).errors.some((m) => m.includes('No message to react to')));
  });

  it('/reply with nothing to reply to errors', () => {
    const a = spawn();
    input(a, '/reply hi');
    assert.ok(rec(a).errors.some((m) => m.includes('No message to reply to')));
  });

  it('/pins is empty by default', () => {
    const a = spawn();
    input(a, '/pins');
    assert.ok(rec(a).info.some((m) => m.includes('No pinned messages')));
  });

  it('/dnd toggles do-not-disturb modes', () => {
    const a = spawn();
    input(a, '/dnd on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('total silence')));
    input(a, '/dnd mentions');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('mentions')));
    input(a, '/dnd 22:00-08:00');
    assert.ok(rec(a).info.some((m) => m.includes('22:00-08:00')));
    input(a, '/dnd 99:99-00:00');
    assert.ok(rec(a).errors.some((m) => m.toLowerCase().includes('invalid format')));
    input(a, '/dnd off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('disabled')));
  });

  it('auto-away marks away after idle and returns on activity', (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/autoaway 1'); // 1 minute idle timeout
    rec(alice).system.length = 0;
    t.mock.timers.tick(60_000); // no activity for a minute
    assert.ok(rec(alice).system.some((m) => m.toLowerCase().includes('auto-away')));

    // Any activity brings us back automatically.
    input(alice, 'back now');
    assert.ok(rec(alice).system.some((m) => m.includes('back')));
  });

  it('/plugins reports none loaded', async () => {
    const a = spawn();
    input(a, '/plugins');
    // The handler is async now: approving a plugin imports it, and an import
    // cannot be awaited synchronously. One turn of the microtask queue is
    // enough for the status path, which touches no I/O.
    await Promise.resolve();
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('no plugins')));
  });

  it('/search without an open history store is rejected', () => {
    const a = spawn();
    input(a, '/search secret');
    assert.ok(rec(a).errors.some((m) => m.toLowerCase().includes('history disabled')));
  });

  it('/backup without a session passphrase is rejected', () => {
    const a = spawn();
    input(a, '/backup ./x.json');
    assert.ok(
      rec(a).errors.some(
        (m) => m.toLowerCase().includes('passphrase') || m.toLowerCase().includes('reinicie'),
      ),
    );
  });

  // ── Moderation (relay forwards to the server, which enforces) ───
  it('/kick with no target errors; with one it forwards a kick_peer', () => {
    const a = spawn();
    input(a, '/kick');
    assert.ok(rec(a).errors.some((m) => m.includes('Usage: /kick')));
    input(a, '/kick bob reason');
    const kicks = a.conn.sentOfType(MSG.KICK_PEER);
    assert.equal(kicks.length, 1);
    assert.equal(kicks[0].targetNickname, 'bob');
  });

  it('/mute with an invalid duration errors', () => {
    const a = spawn();
    input(a, '/mute bob zzz');
    assert.ok(rec(a).errors.some((m) => m.toLowerCase().includes('invalid time format')));
  });

  // ── /nick ──────────────────────────────────────────────────────
  it('/nick with an invalid nickname errors', () => {
    const a = spawn();
    input(a, '/nick');
    assert.ok(rec(a).errors.some((m) => m.includes('Usage: /nick')));
  });

  it('/nick before joining re-sends a JOIN under the new name', () => {
    const a = spawn();
    input(a, '/nick renamed');
    assert.equal(a.conn.sentOfType(MSG.JOIN).length, 1);
    assert.equal(a.conn.sentOfType(MSG.JOIN)[0].nickname, 'renamed');
    assert.ok(rec(a).system.some((m) => m.includes('Trying to join as renamed')));
  });

  it('/nick after joining is refused', () => {
    const hub = new Hub();
    const a = spawn();
    online(hub, a); // now has a sessionId
    a.conn.sent.length = 0;
    input(a, '/nick renamed');
    assert.ok(rec(a).errors.some((m) => m.includes("Can't change")));
    assert.equal(a.conn.sentOfType(MSG.JOIN).length, 0);
  });

  // ── Send guards ────────────────────────────────────────────────
  it('sending with no connection warns and does not transmit', () => {
    const a = spawn();
    a.conn.connected = false;
    input(a, 'hello world');
    assert.ok(rec(a).errors.some((m) => m.includes('No connection')));
    assert.equal(a.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 0);
  });

  it('sending with no peers online is a no-op notice', () => {
    const a = spawn();
    a.conn.emit('connected'); // connected to the relay, just no peers yet
    input(a, 'anyone here?');
    assert.ok(rec(a).system.some((m) => m.includes('No peers online')));
    assert.equal(a.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 0);
  });

  // ── Connection lifecycle ───────────────────────────────────────
  it('on connect it goes online and sends a JOIN', () => {
    const a = spawn();
    a.conn.emit('connected');
    assert.ok(rec(a).connState.includes('online'));
    assert.equal(a.conn.sentOfType(MSG.JOIN).length, 1);
  });

  it('on disconnect it goes offline and warns', () => {
    const a = spawn();
    a.conn.emit('disconnected');
    assert.ok(rec(a).connState.includes('offline'));
    assert.ok(rec(a).errors.some((m) => m.includes('Connection lost')));
  });

  it('on reconnecting it shows the countdown', () => {
    const a = spawn();
    a.conn.emit('reconnecting', 3000);
    assert.ok(rec(a).connState.includes('reconnecting'));
    assert.ok(rec(a).system.some((m) => m.includes('Reconnecting in 3s')));
  });

  // ── Server message handling ────────────────────────────────────
  it('JOIN_ACK registers peers and confirms E2E', () => {
    const hub = new Hub();
    const a = spawn();
    online(hub, a);
    assert.ok(rec(a).system.some((m) => m.includes('Connected to server')));
    assert.equal(rec(a).room, 'general');
  });

  // ── Capability negotiation (#463, steps 2-3) ───────────────────
  // These prove the advertisement survives the trip through JOIN_ACK /
  // PEER_JOINED into the active-room peer map, which is the switch the send
  // path reads. Both halves are in the field now — receive in 2.11.0, send in
  // 2.12.0 — so what these guard is the negotiation itself: a peer that says
  // nothing is an older peer, and one of those holds the whole room.
  it('a room of current builds is capable', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b); // alice learns bob's caps via PEER_JOINED

    assert.equal(a.controller.roomSupportsCapability(CAP.SENDER_KEYS), true);
    assert.equal(b.controller.roomSupportsCapability(CAP.SENDER_KEYS), true);
  });

  it('one peer on an older build holds the whole room back', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    const c = spawn('carol');
    c.advertise = []; // a pre-capability client: sends no caps at all
    online(hub, a);
    online(hub, b);
    assert.equal(a.controller.roomSupportsCapability(CAP.SENDER_KEYS), true);

    online(hub, c);
    assert.equal(
      a.controller.roomSupportsCapability(CAP.SENDER_KEYS),
      false,
      'the room drops back the moment an older client walks in',
    );
  });

  it('capabilities arriving in JOIN_ACK count the same as in PEER_JOINED', () => {
    const hub = new Hub();
    const old = spawn('carol');
    old.advertise = [];
    online(hub, old);

    const a = spawn('alice'); // joins second, so learns carol from the peer list
    online(hub, a);
    assert.equal(
      a.controller.roomSupportsCapability(CAP.SENDER_KEYS),
      false,
      'an older peer already in the room counts the same as one that walks in',
    );
  });

  it('a room is not capable while this build says it is not', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);
    assert.equal(a.controller.roomSupportsCapability(CAP.SENDER_KEYS, []), false);
  });

  it('a capable room on an older hub is still not switchable', () => {
    const hub = new Hub();
    hub.serverCaps = []; // a relay that cannot fan a room-addressed message out
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    assert.equal(a.controller.roomSupportsCapability(CAP.SENDER_KEYS), true, 'the peers can');
    assert.equal(
      a.controller.relaySupportsCapability(CAP.SENDER_KEYS),
      false,
      'but the hub cannot, and no client can advertise that on its behalf',
    );
  });

  it('reads the relay capabilities out of join_ack', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);
    assert.equal(a.controller.relaySupportsCapability(CAP.SENDER_KEYS), true);
    assert.equal(a.controller.relaySupportsCapability('nonesuch'), false);
  });

  // ── The identity key on the wire (#481, item 4, step 2) ─────────
  //
  // Nothing reads this key yet, which is exactly why it needs a test: an
  // advertisement nobody consumes can stop arriving with no symptom at all, and
  // the first person to find out would be whoever builds step 3 on the
  // assumption that it is there.
  //
  // The capability list had this bug for real — it was dropped on a room
  // switch, and every peer silently looked incapable — so the room switch is
  // tested here rather than trusted.
  // Read through serializeState() rather than a test-only accessor: it is the
  // active-room peer map, and going through it also proves the key survives
  // into a persisted session.
  const peerIn = (client, nick) =>
    Object.values(client.controller.serializeState().peers).find((p) => p.nickname === nick);

  it('sends its identity key in JOIN', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);

    const join = a.conn.sentOfType(MSG.JOIN)[0];
    assert.match(join.identityKey, /^[A-Za-z0-9+/]{43}=$/, 'a 32-byte key, base64');
    assert.notEqual(join.identityKey, join.publicKey, 'not the box key under another name');
  });

  it('keeps a peer identity key that arrived in the peer list', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b); // bob joins second, so learns alice from JOIN_ACK

    const aliceKey = a.conn.sentOfType(MSG.JOIN)[0].identityKey;
    assert.equal(peerIn(b, 'alice')?.identityKey, aliceKey);
  });

  it('keeps one that arrived in PEER_JOINED', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b); // alice learns bob by announcement

    const bobKey = b.conn.sentOfType(MSG.JOIN)[0].identityKey;
    assert.equal(peerIn(a, 'bob')?.identityKey, bobKey);
  });

  it('carries it across a room switch', () => {
    // Peer capabilities were dropped exactly here (#481): room_changed and
    // room_joined carry them and the client did not copy them across, so after
    // a switch every peer looked incapable and nothing said so.
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    const bobKey = b.conn.sentOfType(MSG.JOIN)[0].identityKey;
    input(b, '/join projeto');
    input(a, '/join projeto');

    assert.equal(peerIn(a, 'bob')?.identityKey, bobKey, 'still there after the switch');
  });

  it('treats a peer without one as an older build, not an error', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const old = spawn('carol');
    old.advertiseIdentity = null; // a client from before identity keys
    online(hub, a);
    online(hub, old);

    assert.equal(peerIn(a, 'carol')?.identityKey, null, 'null, and nothing complains');
    assert.equal(rec(a).errors.length, 0);
  });

  it('changes nothing about how a message is sent', () => {
    // "Used by nobody" is the property that makes step 2 safe to ship on its
    // own, and it is worth asserting rather than assuming.
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    a.conn.sent.length = 0;
    input(a, 'hello');

    assert.equal(a.controller.groupSendStatus().group, true);
    assert.equal(a.conn.sentOfType(MSG.GROUP_MESSAGE).length, 1);
    assert.ok(
      rec(b).messages.some((m) => m.nick === 'alice' && m.text === 'hello'),
      'and bob still reads it',
    );
  });

  // ── Which path a room is on, and why (#481, item 3) ─────────────
  //
  // The per-peer loop is not going away — deniability and sender-key
  // distribution both need it permanently — so the thing worth having is being
  // able to see when it runs. A room silently paying N envelopes per line is
  // the failure mode these guard against: not an error, just a cost nobody can
  // attribute.
  //
  // The reasons are asserted through `/room`'s own output rather than only
  // through groupSendStatus(), because a status object nothing prints is a
  // status nobody reads.
  const sendLine = (client) => rec(client).info.find((m) => m.startsWith('Sending:'));

  it('reports one ciphertext when the room and the hub can both take one', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    assert.deepEqual(a.controller.groupSendStatus(), {
      group: true,
      reason: null,
      blockers: [],
    });
    input(a, '/room');
    assert.match(sendLine(a), /one ciphertext to the room/);
    assert.match(sendLine(a), /read by 1/);
  });

  it('names the peer holding the room on the per-peer path', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    const c = spawn('carol');
    c.advertise = []; // a pre-capability client
    online(hub, a);
    online(hub, b);
    online(hub, c);

    const status = a.controller.groupSendStatus();
    assert.equal(status.group, false);
    assert.equal(status.reason, 'peers');
    assert.deepEqual(status.blockers, ['carol']);

    input(a, '/room');
    assert.match(sendLine(a), /2 envelopes per message/);
    assert.match(sendLine(a), /carol is on a build without sender keys/);
  });

  it('blames the hub rather than the peers when the hub is the older one', () => {
    // Both can be true at once. Naming peers who are perfectly current would
    // send the reader after the wrong problem.
    const hub = new Hub();
    hub.serverCaps = [];
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);

    assert.equal(a.controller.groupSendStatus().reason, 'relay');
    input(a, '/room');
    assert.match(sendLine(a), /this relay cannot fan out a room-addressed message/);
    assert.doesNotMatch(sendLine(a), /bob/);
  });

  it('reports deniable mode as the reason, ahead of everything else', () => {
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    online(hub, a);
    online(hub, b);
    input(a, '/deniable on');

    assert.equal(a.controller.groupSendStatus().reason, 'deniable');
    input(a, '/room');
    assert.match(sendLine(a), /deniable mode is on/);
  });

  it('says nothing is going anywhere when the room is empty', () => {
    const hub = new Hub();
    const a = spawn('alice');
    online(hub, a);

    assert.equal(a.controller.groupSendStatus().reason, 'alone');
    input(a, '/room');
    assert.match(sendLine(a), /no one else is here/);
  });

  it('agrees with the path #broadcastPayload actually takes', () => {
    // The status object is a second implementation of the same decision, so it
    // can drift from the one that encrypts. This pins them together by looking
    // at what went on the wire: a group message, or an envelope each.
    const hub = new Hub();
    const a = spawn('alice');
    const b = spawn('bob');
    const c = spawn('carol');
    online(hub, a);
    online(hub, b);
    online(hub, c);

    assert.equal(a.controller.groupSendStatus().group, true);

    // Warm the room first: a group send also hands out the sender key to
    // anyone who lacks it, and that distribution is pairwise by necessity. It
    // is paid once, so measuring after it leaves only the message itself.
    input(a, 'warm up');
    a.conn.sent.length = 0;
    input(a, 'hello');
    assert.equal(a.conn.sentOfType(MSG.GROUP_MESSAGE).length, 1, 'one frame for the room');
    assert.equal(
      a.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length,
      0,
      'and nothing pairwise — sealed envelopes ride as ENCRYPTED_MESSAGE',
    );

    input(a, '/deniable on');
    assert.equal(a.controller.groupSendStatus().group, false);
    a.conn.sent.length = 0;
    input(a, 'hello again');
    assert.equal(a.conn.sentOfType(MSG.GROUP_MESSAGE).length, 0);
    assert.equal(
      a.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length,
      2,
      'one sealed envelope per peer, which is the cost the status reported',
    );
  });

  // ── Sender keys: the receive half (#463, step 3) ────────────────
  //
  // The test plays the part of the sending peer rather than driving a second
  // controller: what is under test here is the reader, and a hand-rolled sender
  // is the only way to hold a packet still — malformed, out of order, or ahead
  // of its distribution — while the reader is asked what it does with it.
  class GroupSender {
    constructor(hub, nick = 'zoe') {
      this.conn = new MockConn();
      this.keys = new KeyManager();
      this.nonces = new NonceManager();
      this.group = new GroupSession();
      this.record = { conn: this.conn, nick, joined: false };
      hub.attach(this.record);
      this.conn.send({
        type: MSG.JOIN,
        version: PROTOCOL_VERSION,
        timestamp: Date.now(),
        nickname: nick,
        publicKey: this.keys.publicKeyB64,
        caps: [CAP.SENDER_KEYS],
      });
    }

    get sid() {
      return this.record.sid;
    }

    // The sender key on the pairwise sealed channel — identity comes from the
    // envelope, never from the relay. Built separately from being sent so a test
    // can hold it back and reproduce the reordering the receive buffer exists
    // for: the distribution leaves first and arrives second.
    distributionFor(peer, room = 'general') {
      const peerPub = Buffer.from(peer.pk, 'base64');
      const payload = JSON.stringify({
        action: 'sk_dist',
        room,
        dist: this.group.distribution(),
        sentAt: Date.now(),
      });
      const nonce = this.nonces.generate();
      const ct = MessageCrypto.encrypt(payload, nonce, peerPub, this.keys.secretKey);
      const sealed = sealEnvelope(
        this.sid,
        { ciphertext: ct.toString('base64'), nonce: nonce.toString('base64') },
        peerPub,
      );
      return createSealedMessage(peer.sid, sealed);
    }

    distributeTo(peer, room = 'general') {
      this.conn.send(this.distributionFor(peer, room));
    }

    say(text, room = 'general') {
      const packet = this.group.encrypt(
        JSON.stringify({ room, text, sentAt: Date.now(), messageId: `g-${text}` }),
      );
      this.conn.send(createGroupMessage(room, packet));
      return packet;
    }

    destroy() {
      this.group.destroy();
      this.keys.destroy();
    }
  }

  it('reads a group message once it holds the sender key', () => {
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);

    zoe.distributeTo(bob);
    zoe.say('one ciphertext, every member');

    assert.ok(
      rec(bob).messages.some((m) => m.text === 'one ciphertext, every member'),
      'a group message lands in the buffer like any other',
    );
    assert.equal(rec(bob).errors.length, 0);
    zoe.destroy();
  });

  it('buffers a group message that overtakes its sender key', () => {
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);

    // Sent first, delivered second — the two travel different paths (pairwise
    // unicast versus room fan-out), so nothing orders them.
    const inFlight = zoe.distributionFor(bob);
    zoe.say('early');
    assert.equal(rec(bob).messages.length, 0, 'nothing rendered yet');
    assert.equal(rec(bob).errors.length, 0, 'and nothing reported — it is a race, not a fault');

    zoe.conn.send(inFlight);
    assert.ok(
      rec(bob).messages.some((m) => m.text === 'early'),
      'the key arriving releases what was waiting on it',
    );
    zoe.destroy();
  });

  it('a sender key handed over late does not unlock what came before it', () => {
    // Not a bug to fix — it is the forward secrecy the ratcheting chain buys.
    // A member who joins mid-conversation reads from their arrival onward, and
    // the backlog stays shut even though they now hold the sender's chain.
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);

    zoe.say('said before bob had the key');
    zoe.distributeTo(bob); // serialised at the *current* counter, not zero
    assert.equal(rec(bob).messages.length, 0, 'the earlier line stays unreadable');

    zoe.say('said after');
    assert.ok(rec(bob).messages.some((m) => m.text === 'said after'));
    zoe.destroy();
  });

  it('stays silent on a group message it holds no key for', () => {
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);

    zoe.say('unreadable'); // never distributed

    assert.equal(rec(bob).messages.length, 0);
    assert.equal(
      rec(bob).errors.length,
      0,
      'an unknown key id may just be a rotation nobody told us about yet',
    );
    zoe.destroy();
  });

  it('drops a departed peer’s sender chain', () => {
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);
    zoe.distributeTo(bob);
    zoe.say('before');
    assert.equal(rec(bob).messages.length, 1);

    bob.conn.emit('message', {
      type: MSG.PEER_LEFT,
      sessionId: zoe.sid,
      nickname: 'zoe',
      room: 'general',
    });

    zoe.say('after');
    assert.equal(
      rec(bob).messages.length,
      1,
      'the chain went with the peer — nothing left to read them with',
    );
    zoe.destroy();
  });

  it('follows a rotation once the new key is redistributed', () => {
    const hub = new Hub();
    const bob = spawn('bob');
    online(hub, bob);
    const zoe = new GroupSender(hub);
    zoe.distributeTo(bob);
    zoe.say('before rotation');

    zoe.group.rotate(); // e.g. somebody was kicked
    zoe.say('after rotation'); // silently unreadable until redistribution
    assert.equal(rec(bob).messages.length, 1, 'a rotated chain is not readable on the old key');

    zoe.distributeTo(bob);
    zoe.say('after redistribution');
    assert.ok(rec(bob).messages.some((m) => m.text === 'after redistribution'));
    zoe.destroy();
  });

  it('PEER_JOINED plays the handshake flourish for the new peer', () => {
    const a = spawn();
    const bobKeys = new KeyManager();
    a.conn.emit(
      'message',
      createPeerJoined({ sessionId: 's9', nickname: 'bob', publicKey: bobKeys.publicKeyB64 }),
    );
    assert.ok(rec(a).handshakes.includes('bob'));
    bobKeys.destroy();
  });

  it('PEER_LEFT announces the departure', () => {
    const a = spawn();
    const bobKeys = new KeyManager();
    a.conn.emit(
      'message',
      createPeerJoined({ sessionId: 's9', nickname: 'bob', publicKey: bobKeys.publicKeyB64 }),
    );
    a.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: 's9', nickname: 'bob' });
    assert.ok(rec(a).disconnects.includes('bob'), 'plays the peer-leave animation');
    bobKeys.destroy();
  });

  it('a NICKNAME_TAKEN error nudges toward /nick', () => {
    const a = spawn();
    a.conn.emit('message', createError(ERR.NICKNAME_TAKEN, 'Nickname taken'));
    assert.ok(rec(a).errors.some((m) => m.includes('/nick')));
  });

  it('a ciphertext from an unknown session is flagged', () => {
    const a = spawn();
    a.conn.emit('message', {
      type: MSG.ENCRYPTED_MESSAGE,
      from: 'ghost',
      to: 's1',
      payload: { ciphertext: 'AA==', nonce: 'AA==' },
    });
    assert.ok(rec(a).errors.some((m) => m.includes('unknown peer')));
  });

  it('being kicked surfaces as an error to the user', () => {
    const a = spawn('alice');
    a.conn.emit('message', {
      type: MSG.PEER_KICKED,
      nickname: 'alice',
      reason: 'spam',
      self: true,
    });
    assert.ok(rec(a).errors.some((m) => m.includes('kicked')));
  });

  it('a kicked peer is unwound once, not announced twice', () => {
    // The relay now sends PEER_KICKED and then PEER_LEFT for the same session,
    // so that a kick is a membership change like any other and every consumer
    // of "someone left this room" — the roster, and the sender chain that has
    // to rotate away from them — hooks one event instead of two.
    //
    // The cost of that is a single event with two announcements. The kick line
    // is the one worth keeping: it says why.
    const a = spawn();
    const bobKeys = new KeyManager();
    a.conn.emit(
      'message',
      createPeerJoined({ sessionId: 's9', nickname: 'bob', publicKey: bobKeys.publicKeyB64 }),
    );

    a.conn.emit('message', {
      type: MSG.PEER_KICKED,
      nickname: 'bob',
      reason: 'spam',
      sessionId: 's9',
    });
    a.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: 's9', nickname: 'bob' });

    assert.ok(
      rec(a).system.some((m) => m.includes('kicked')),
      'the kick, with its reason, is what the user is told',
    );
    assert.ok(
      !rec(a).disconnects.includes('bob'),
      'and not also the generic departure for the same event',
    );
    bobKeys.destroy();
  });

  it('an ordinary departure is still announced after an unrelated kick', () => {
    // The suppression is per session. A kick must not silence the next person
    // who simply leaves — which is what a boolean flag instead of a set would
    // have done.
    const a = spawn();
    const bobKeys = new KeyManager();
    const evaKeys = new KeyManager();
    a.conn.emit(
      'message',
      createPeerJoined({ sessionId: 's9', nickname: 'bob', publicKey: bobKeys.publicKeyB64 }),
    );
    a.conn.emit(
      'message',
      createPeerJoined({ sessionId: 's10', nickname: 'eva', publicKey: evaKeys.publicKeyB64 }),
    );

    a.conn.emit('message', { type: MSG.PEER_KICKED, nickname: 'bob', reason: '', sessionId: 's9' });
    a.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: 's9', nickname: 'bob' });
    a.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: 's10', nickname: 'eva' });

    assert.ok(!rec(a).disconnects.includes('bob'), 'the kicked one stays quiet');
    assert.ok(rec(a).disconnects.includes('eva'), 'the one who left does not');
    bobKeys.destroy();
    evaKeys.destroy();
  });

  it('an older relay that sends no sessionId still announces the kick', () => {
    // PEER_KICKED without a sessionId is what every relay before this change
    // sent. There is then no PEER_LEFT to match, and nothing to suppress.
    const a = spawn();
    a.conn.emit('message', { type: MSG.PEER_KICKED, nickname: 'bob', reason: 'spam' });
    assert.ok(rec(a).system.some((m) => m.includes('kicked')));
  });

  it('ROOM_CHANGED updates the current room', () => {
    const a = spawn();
    a.conn.emit('message', createRoomChanged('project', []));
    input(a, '/room');
    assert.ok(rec(a).info.some((m) => m.includes('#project')));
  });

  // ── End-to-end through the hub ─────────────────────────────────
  it('delivers and decrypts a message between two clients', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob); // bob's JOIN_ACK includes alice; alice gets PEER_JOINED

    input(alice, 'hey bob, all good?');

    assert.ok(
      rec(bob).messages.some((m) => m.nick === 'alice' && m.text === 'hey bob, all good?'),
      "bob should receive and decrypt alice's message",
    );
  });

  // ── Sealed sender ──────────────────────────────────────────────
  it('sends messages sealed — no cleartext sender on the wire', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, 'hey bob, all good?');

    const enc = alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE);
    const wire = enc.at(-1);
    assert.equal(wire.from, undefined, 'the relay never sees who sent it');
    assert.equal(wire.payload, undefined, 'the payload is inside the seal, not on the wire');
    assert.equal(typeof wire.sealed, 'string', 'sender + payload are sealed to the recipient');
    // The recipient recovers the sender from the seal and attributes it correctly.
    assert.ok(rec(bob).messages.some((m) => m.nick === 'alice' && m.text === 'hey bob, all good?'));
  });

  // ── Trust visibility ───────────────────────────────────────────
  it('nudges you to verify a newly-arrived unverified peer, exactly once', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob); // alice sees bob arrive

    const nudges = rec(alice).system.filter(
      (m) => m.includes('unverified') && m.includes('/verify bob'),
    );
    assert.equal(nudges.length, 1, 'exactly one verify nudge for bob');
  });

  it('an unverified peer carries no trust badge', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, 'hey bob');
    const msg = rec(bob).messages.find((m) => m.text === 'hey bob');
    assert.equal(msg.trust, 'none', 'no badge until verified');
  });

  it('a SAS-verified peer renders with a verified trust badge', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(bob, '/verify-confirm alice'); // bob confirms alice's identity

    input(alice, 'hey bob');
    const msg = rec(bob).messages.find((m) => m.nick === 'alice' && m.text === 'hey bob');
    assert.ok(msg, 'bob received the message');
    assert.equal(msg.trust, 'verified', 'alice shows a verified badge for bob');
  });

  it('delivers and decrypts a deniable message', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/deniable on');
    input(alice, 'this is deniable');

    // Sealed sender: no cleartext payload/from on the wire — the deniable flag
    // now travels inside the sealed envelope, invisible to the relay.
    const enc = alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE);
    assert.ok(enc.length >= 1, 'a message was transmitted');
    assert.equal(enc.at(-1).from, undefined, 'no cleartext sender on the wire');
    assert.equal(enc.at(-1).payload, undefined, 'no cleartext payload on the wire');
    assert.equal(typeof enc.at(-1).sealed, 'string', 'message is sealed');
    // ...and bob still decrypts and shows it.
    assert.ok(rec(bob).messages.some((m) => m.nick === 'alice' && m.text === 'this is deniable'));
  });

  // ── Cover traffic ──────────────────────────────────────────────
  it('/cover toggles on and off', () => {
    const a = spawn();
    input(a, '/cover on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('enabled')));
    input(a, '/cover off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('disabled')));
  });

  it('a decoy sent by one client is silently dropped by the other', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    rec(bob).messages.length = 0;
    rec(bob).system.length = 0;
    rec(bob).errors.length = 0;
    alice.controller.sendCoverNow(); // emit one decoy

    // A ciphertext WAS transmitted to bob...
    assert.ok(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length >= 1, 'decoy is sent encrypted');
    // ...but it produces no message, system line, or error on bob's side.
    assert.equal(rec(bob).messages.length, 0);
    assert.equal(rec(bob).errors.length, 0);
    assert.ok(!rec(bob).system.some((m) => m.toLowerCase().includes('cover')));
  });

  it('constant cover paces real messages through slots (and fills with decoys)', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/cover constant');
    alice.conn.sent.length = 0;
    rec(bob).messages.length = 0;

    input(alice, 'paced message');
    // Shown locally at once, but held off the wire until the next slot.
    assert.ok(rec(alice).messages.some((m) => m.text === 'paced message'));
    assert.equal(alice.conn.sentOfType(MSG.GROUP_MESSAGE).length, 0, 'queued, not sent yet');

    alice.controller.coverTick(); // slot 1: drains the real message
    assert.equal(alice.conn.sentOfType(MSG.GROUP_MESSAGE).length, 1);
    assert.ok(
      rec(bob).messages.some((m) => m.text === 'paced message'),
      'bob decrypts',
    );

    rec(bob).messages.length = 0;
    alice.controller.coverTick(); // slot 2: queue empty → decoy on the wire
    assert.equal(alice.conn.sentOfType(MSG.GROUP_MESSAGE).length, 2);
    assert.equal(rec(bob).messages.length, 0, 'decoy is dropped');

    // The property cover traffic actually needs, now that there are two paths a
    // message could take: a decoy leaves as the same kind of frame a real
    // message does. A decoy on the pairwise path in a room that sends on the
    // group path would be a decoy that announces itself.
    assert.equal(
      alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length,
      0,
      'nothing took the per-peer path while the room was on the group path',
    );
  });

  it('leaving constant mode flushes any queued messages', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/cover constant');
    alice.conn.sent.length = 0;
    input(alice, "don't lose me");
    assert.equal(alice.conn.sentOfType(MSG.GROUP_MESSAGE).length, 0);

    input(alice, '/cover off'); // must flush the queue, not strand it
    assert.equal(alice.conn.sentOfType(MSG.GROUP_MESSAGE).length, 1, 'queued message was sent');
  });

  it('does not deliver across rooms', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/join secret-room'); // alice leaves #general
    rec(bob).messages.length = 0;
    input(alice, 'only for those in secret-room');

    assert.ok(
      rec(bob).messages.length === 0 || rec(alice).system.some((m) => m.includes('No peers')),
      'bob (in another room) should not receive it',
    );
  });

  // ── Group send ─────────────────────────────────────────────────
  // The half the whole capability exercise was for. A line in a room of N cost
  // N encryptions and N envelopes; it now costs one of each, when — and only
  // when — every member and the relay can read the result.

  describe('sending on the group path', () => {
    const groupFrames = (c) => c.conn.sentOfType(MSG.GROUP_MESSAGE);
    const pairFrames = (c) => c.conn.sentOfType(MSG.ENCRYPTED_MESSAGE);

    it('one line costs one frame, whatever the size of the room', () => {
      const hub = new Hub();
      const alice = spawn('alice');
      const peers = ['bob', 'carol', 'dave'].map((n) => spawn(n));
      online(hub, alice);
      for (const p of peers) {
        online(hub, p);
      }

      alice.conn.sent.length = 0;
      input(alice, 'one line to three people');

      assert.equal(groupFrames(alice).length, 1, 'one ciphertext for the room');
      assert.equal(pairFrames(alice).length, 0, 'and not one envelope each');

      for (const p of peers) {
        assert.ok(
          rec(p).messages.some((m) => m.text === 'one line to three people'),
          `${p.nick} read it`,
        );
      }
    });

    it('one peer on an older build holds the whole room on the per-peer path', () => {
      // The strict-consensus rule. A room is only as new as its oldest member,
      // because the alternative is encrypting in a form somebody cannot read.
      const hub = new Hub();
      const alice = spawn('alice');
      const bob = spawn('bob');
      const old = spawn('mallory');
      old.advertise = []; // a build from before sender keys
      online(hub, alice);
      online(hub, bob);
      online(hub, old);

      alice.conn.sent.length = 0;
      input(alice, 'has to reach everyone');

      assert.equal(groupFrames(alice).length, 0, 'no group frame');
      assert.equal(pairFrames(alice).length, 2, 'one envelope per peer, as before');
      assert.ok(rec(old).messages.some((m) => m.text === 'has to reach everyone'));
      assert.ok(rec(bob).messages.some((m) => m.text === 'has to reach everyone'));
    });

    it('an older relay holds the room back even when every peer is ready', () => {
      // Peers cannot promise the fan-out on the relay's behalf. Without this
      // check a current room on an old hub would encrypt once and send it
      // into a void.
      const hub = new Hub();
      hub.serverCaps = [];
      const alice = spawn('alice');
      const bob = spawn('bob');
      online(hub, alice);
      online(hub, bob);

      alice.conn.sent.length = 0;
      input(alice, 'the hub cannot fan this out');

      assert.equal(groupFrames(alice).length, 0);
      assert.equal(pairFrames(alice).length, 1);
      assert.ok(rec(bob).messages.some((m) => m.text === 'the hub cannot fan this out'));
    });

    it('a deniable message never takes the group path', () => {
      // Deniability is a property of the pairwise construction: a key both
      // sides could have derived, so neither can prove the other wrote it. A
      // group packet is signed by exactly one sender. Sending a deniable
      // message on it would publish the opposite of what was asked for.
      const hub = new Hub();
      const alice = spawn('alice');
      const bob = spawn('bob');
      online(hub, alice);
      online(hub, bob);

      input(alice, '/deniable on');
      alice.conn.sent.length = 0;
      input(alice, 'no proof i said this');

      assert.equal(groupFrames(alice).length, 0, 'not signed, not on the group path');
      assert.equal(pairFrames(alice).length, 1);
    });
  });

  // ── Rotation on membership change ──────────────────────────────
  // A chain ratchets forward, so the copy a member holds opens every message
  // after it. Removing them from the room stops the relay delivering to them;
  // only rotating stops them reading.

  describe('rotating the chain when the room changes', () => {
    const lastKeyId = (c) => {
      const frames = c.conn.sentOfType(MSG.GROUP_MESSAGE);
      return frames.length ? frames[frames.length - 1].keyId : null;
    };

    const roomOfThree = () => {
      const hub = new Hub();
      const alice = spawn('alice');
      const bob = spawn('bob');
      const carol = spawn('carol');
      online(hub, alice);
      online(hub, bob);
      online(hub, carol);
      return { hub, alice, bob, carol };
    };

    it('a voluntary departure draws a new chain', () => {
      const { alice, bob } = roomOfThree();

      input(alice, 'before');
      const before = lastKeyId(alice);
      assert.ok(before, 'sent on the group path to begin with');

      alice.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: bob.sid });
      input(alice, 'after');

      assert.notEqual(lastKeyId(alice), before, 'the label changed, so the chain did');
    });

    it('a kick draws a new chain the same way', () => {
      // The reason the relay now reports a kick as a departure (#482). This is
      // the case that matters most: someone removed against their will is
      // exactly who must not keep reading.
      const { alice, bob } = roomOfThree();

      input(alice, 'before the kick');
      const before = lastKeyId(alice);

      alice.conn.emit('message', {
        type: MSG.PEER_KICKED,
        nickname: 'bob',
        reason: 'spam',
        sessionId: bob.sid,
      });
      alice.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: bob.sid });
      input(alice, 'after the kick');

      assert.notEqual(lastKeyId(alice), before, 'a kick rotates like any other departure');
    });

    it('the new chain reaches everyone still in the room', () => {
      // A rotation whose redistribution never happens is the silent failure the
      // frozen vectors exist for: no error anywhere, just a room that stopped
      // being able to read this client.
      const { alice, bob, carol } = roomOfThree();

      input(alice, 'first');
      alice.conn.emit('message', { type: MSG.PEER_LEFT, sessionId: bob.sid });
      rec(carol).messages.length = 0;
      input(alice, 'after the rotation');

      assert.ok(
        rec(carol).messages.some((m) => m.text === 'after the rotation'),
        'carol got the new chain and could still read',
      );
    });

    it('an arrival does not rotate — it is given the chain as it stands', () => {
      // Rotation is about people leaving. A serialised chain carries its
      // current counter, so a newcomer is handed what opens the next message
      // and nothing before it; rotating as well would cost a redistribution to
      // the whole room for no gain.
      const hub = new Hub();
      const alice = spawn('alice');
      const bob = spawn('bob');
      online(hub, alice);
      online(hub, bob);

      input(alice, 'before carol arrives');
      const before = lastKeyId(alice);

      const carol = spawn('carol');
      online(hub, carol);
      input(alice, 'after carol arrives');

      assert.equal(lastKeyId(alice), before, 'same chain');
      assert.ok(rec(carol).messages.some((m) => m.text === 'after carol arrives'));
      assert.ok(
        !rec(carol).messages.some((m) => m.text === 'before carol arrives'),
        'and no window onto what was said before she was there',
      );
    });

    it('the distribution exchange converges instead of answering itself', () => {
      // Sending re-enters the controller: the peer receives a distribution,
      // finds it holds none of ours, and answers — and on a synchronous
      // transport its answer arrives before the send call has returned. If the
      // record of who has our chain is written after sending rather than
      // before, both sides consult a record neither has written yet and each
      // answers the other's answer.
      //
      // It converged on its own only because the test run ended. The count is
      // the assertion: a room of three costs a handful of pairwise frames, and
      // the broken version cost hundreds.
      const pairwise = (c) => c.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length;
      const hub = new Hub();
      const alice = spawn('alice');
      online(hub, alice);
      const bob = spawn('bob');
      const carol = spawn('carol');
      online(hub, bob);
      online(hub, carol);

      for (const c of [alice, bob, carol]) {
        assert.ok(
          pairwise(c) <= 4,
          `${c.nick} sent ${pairwise(c)} pairwise frames setting up a room of three`,
        );
      }

      // And it converged having actually worked, not by giving up.
      input(alice, 'reaches both');
      assert.ok(rec(bob).messages.some((m) => m.text === 'reaches both'));
      assert.ok(rec(carol).messages.some((m) => m.text === 'reaches both'));
    });

    it('a sender key arrives whichever way round the two peers met', () => {
      // The ordering that made this necessary: a client drops a ciphertext from
      // a session it has no key for, and a newcomer learns of the room in its
      // join_ack — before the room learns of the newcomer. Anyone announcing
      // themselves on arrival is talking to people who cannot hear them, so
      // distribution is answered rather than announced.
      const hub = new Hub();
      const first = spawn('first');
      const second = spawn('second');
      online(hub, first);
      online(hub, second);

      // The later arrival speaks first — the direction that used to be lost.
      input(second, 'from the one who joined last');
      assert.ok(
        rec(first).messages.some((m) => m.text === 'from the one who joined last'),
        'the earlier arrival holds the later one’s chain',
      );

      input(first, 'and back the other way');
      assert.ok(
        rec(second).messages.some((m) => m.text === 'and back the other way'),
        'and the other direction still works',
      );
    });
  });
});
