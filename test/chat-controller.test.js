import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { ChatController } from '../src/client/ChatController.js';
import {
  MSG,
  ERR,
  createJoinAck,
  createPeerJoined,
  createRoomChanged,
  createError,
} from '../src/protocol/messages.js';

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
  };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: (nick, text, isDM, ephLabel, deniable, mentioned, trust) => {
      rec.messages.push({ nick, text, isDM, mentioned, trust });
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

// Minimal in-memory relay: assigns session IDs, routes ciphertext by room.
class Hub {
  constructor() {
    this.clients = [];
    this._n = 0;
  }
  attach(client) {
    client.conn.hub = this;
    client.conn.client = client;
    this.clients.push(client);
  }
  #peersFor(me) {
    return this.clients
      .filter((c) => c !== me && c.joined && c.room === me.room)
      .map((c) => ({ sessionId: c.sid, nickname: c.nick, publicKey: c.pk }));
  }
  route(conn, msg) {
    const me = conn.client;
    if (!me) return;
    switch (msg.type) {
      case MSG.JOIN: {
        me.sid = `s${++this._n}`;
        me.room = 'general';
        me.pk = msg.publicKey;
        me.nick = msg.nickname;
        me.joined = true;
        conn.emit('message', createJoinAck(me.sid, this.#peersFor(me), 0, me.room));
        for (const c of this.clients) {
          if (c !== me && c.joined && c.room === me.room) {
            c.conn.emit(
              'message',
              createPeerJoined({ sessionId: me.sid, nickname: me.nick, publicKey: me.pk }),
            );
          }
        }
        break;
      }
      case MSG.ENCRYPTED_MESSAGE: {
        const target = this.clients.find((c) => c.sid === msg.to && c.joined);
        if (target && target.room === me.room) {
          target.conn.emit('message', msg);
        }
        break;
      }
      case MSG.CHANGE_ROOM: {
        me.room = msg.room;
        conn.emit('message', createRoomChanged(msg.room, this.#peersFor(me)));
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
    const controller = new ChatController(nick, conn, ui, opts.restoredState || null);
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
    assert.ok(
      rec(a).errors.some((m) => m.includes('Unknown command') && m.includes('/help')),
    );
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

  it('/join with no argument errors; with one it sends a change_room', () => {
    const a = spawn();
    input(a, '/join');
    assert.ok(rec(a).errors.some((m) => m.includes('Usage: /join')));
    input(a, '/join project');
    assert.equal(a.conn.sentOfType(MSG.CHANGE_ROOM).length, 1);
    assert.equal(a.conn.sentOfType(MSG.CHANGE_ROOM)[0].room, 'project');
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

  it('/plugins reports none loaded', () => {
    const a = spawn();
    input(a, '/plugins');
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
    a.conn.emit('message', { type: MSG.PEER_KICKED, nickname: 'alice', reason: 'spam', self: true });
    assert.ok(rec(a).errors.some((m) => m.includes('kicked')));
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
      'bob should receive and decrypt alice\'s message',
    );
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

    // The wire message carries the deniable flag...
    const enc = alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE);
    assert.ok(enc.length >= 1 && enc.at(-1).payload.deniable === true);
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
    assert.equal(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 0, 'queued, not sent yet');

    alice.controller.coverTick(); // slot 1: drains the real message
    assert.equal(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 1);
    assert.ok(rec(bob).messages.some((m) => m.text === 'paced message'), 'bob decrypts');

    rec(bob).messages.length = 0;
    alice.controller.coverTick(); // slot 2: queue empty → decoy on the wire
    assert.equal(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 2);
    assert.equal(rec(bob).messages.length, 0, 'decoy is dropped');
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
    assert.equal(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 0);

    input(alice, '/cover off'); // must flush the queue, not strand it
    assert.equal(alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 1, 'queued message was sent');
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
});
