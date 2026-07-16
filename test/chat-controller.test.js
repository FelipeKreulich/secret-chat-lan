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
  connected = true;
  url = 'wss://test:3600';
  sent = [];
  hub = null;
  client = null;
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
    room: null,
    cleared: 0,
  };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: (nick, text) => {
      rec.messages.push({ nick, text });
      return { lineIndex: rec.messages.length - 1 };
    },
    addPlainLines: (lines) => rec.plain.push(...lines),
    setConnectionState: (s) => rec.connState.push(s),
    handshakeConnect: (n) => rec.handshakes.push(n),
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
      rec(a).errors.some((m) => m.includes('Comando desconhecido') && m.includes('/help')),
    );
  });

  it('/deniable toggles the mode on and off', () => {
    const a = spawn();
    input(a, '/deniable on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('ativado')));
    rec(a).info.length = 0;
    input(a, '/deniable off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('desativado')));
  });

  it('/receipts toggles read receipts', () => {
    const a = spawn();
    input(a, '/receipts off');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('desativados')));
    input(a, '/receipts on');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('ativados')));
  });

  it('/away then /back toggles presence; /back alone is a no-op notice', () => {
    const a = spawn();
    input(a, '/back');
    assert.ok(rec(a).info.some((m) => m.includes('nao esta away')));
    input(a, '/away almoço');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('away')));
    input(a, '/back');
    assert.ok(rec(a).info.some((m) => m.includes('voltou')));
  });

  it('/status sets and clears the status text', () => {
    const a = spawn();
    input(a, '/status codando');
    assert.ok(rec(a).info.some((m) => m.includes('codando')));
    input(a, '/status off');
    assert.ok(rec(a).info.some((m) => m.includes('removido')));
  });

  it('/room reports the current room', () => {
    const a = spawn();
    input(a, '/room');
    assert.ok(rec(a).info.some((m) => m.includes('#general')));
  });

  it('/join with no argument errors; with one it sends a change_room', () => {
    const a = spawn();
    input(a, '/join');
    assert.ok(rec(a).errors.some((m) => m.includes('Uso: /join')));
    input(a, '/join projeto');
    assert.equal(a.conn.sentOfType(MSG.CHANGE_ROOM).length, 1);
    assert.equal(a.conn.sentOfType(MSG.CHANGE_ROOM)[0].room, 'projeto');
  });

  it('/rooms asks the server for the room list', () => {
    const a = spawn();
    input(a, '/rooms');
    assert.equal(a.conn.sentOfType(MSG.LIST_ROOMS).length, 1);
  });

  it('/owner says #general has no owner', () => {
    const a = spawn();
    input(a, '/owner');
    assert.ok(rec(a).info.some((m) => m.includes('#general') && m.includes('nao tem dono')));
  });

  it('/reject with no pending offer reports nothing pending', () => {
    const a = spawn();
    input(a, '/reject');
    assert.ok(rec(a).errors.some((m) => m.includes('Nenhuma oferta')));
  });

  it('/react with nothing to react to errors', () => {
    const a = spawn();
    input(a, '/react :fire:');
    assert.ok(rec(a).errors.some((m) => m.includes('Nenhuma mensagem para reagir')));
  });

  it('/reply with nothing to reply to errors', () => {
    const a = spawn();
    input(a, '/reply oi');
    assert.ok(rec(a).errors.some((m) => m.includes('Nenhuma mensagem para responder')));
  });

  it('/pins is empty by default', () => {
    const a = spawn();
    input(a, '/pins');
    assert.ok(rec(a).info.some((m) => m.includes('Nenhuma mensagem fixada')));
  });

  it('/plugins reports none loaded', () => {
    const a = spawn();
    input(a, '/plugins');
    assert.ok(rec(a).info.some((m) => m.toLowerCase().includes('nenhum plugin')));
  });

  it('/search without an open history store is rejected', () => {
    const a = spawn();
    input(a, '/search segredo');
    assert.ok(rec(a).errors.some((m) => m.toLowerCase().includes('historico desativado')));
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
    assert.ok(rec(a).errors.some((m) => m.includes('Uso: /kick')));
    input(a, '/kick bob motivo');
    const kicks = a.conn.sentOfType(MSG.KICK_PEER);
    assert.equal(kicks.length, 1);
    assert.equal(kicks[0].targetNickname, 'bob');
  });

  it('/mute with an invalid duration errors', () => {
    const a = spawn();
    input(a, '/mute bob zzz');
    assert.ok(rec(a).errors.some((m) => m.toLowerCase().includes('formato de tempo')));
  });

  // ── /nick ──────────────────────────────────────────────────────
  it('/nick with an invalid nickname errors', () => {
    const a = spawn();
    input(a, '/nick');
    assert.ok(rec(a).errors.some((m) => m.includes('Uso: /nick')));
  });

  it('/nick before joining re-sends a JOIN under the new name', () => {
    const a = spawn();
    input(a, '/nick renamed');
    assert.equal(a.conn.sentOfType(MSG.JOIN).length, 1);
    assert.equal(a.conn.sentOfType(MSG.JOIN)[0].nickname, 'renamed');
    assert.ok(rec(a).system.some((m) => m.includes('Tentando entrar como renamed')));
  });

  it('/nick after joining is refused', () => {
    const hub = new Hub();
    const a = spawn();
    online(hub, a); // now has a sessionId
    a.conn.sent.length = 0;
    input(a, '/nick renamed');
    assert.ok(rec(a).errors.some((m) => m.includes('Nao da para trocar')));
    assert.equal(a.conn.sentOfType(MSG.JOIN).length, 0);
  });

  // ── Send guards ────────────────────────────────────────────────
  it('sending with no connection warns and does not transmit', () => {
    const a = spawn();
    a.conn.connected = false;
    input(a, 'ola mundo');
    assert.ok(rec(a).errors.some((m) => m.includes('Sem conexao')));
    assert.equal(a.conn.sentOfType(MSG.ENCRYPTED_MESSAGE).length, 0);
  });

  it('sending with no peers online is a no-op notice', () => {
    const a = spawn();
    input(a, 'tem alguem ai?');
    assert.ok(rec(a).system.some((m) => m.includes('Nenhum peer online')));
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
    assert.ok(rec(a).errors.some((m) => m.includes('Conexao perdida')));
  });

  it('on reconnecting it shows the countdown', () => {
    const a = spawn();
    a.conn.emit('reconnecting', 3000);
    assert.ok(rec(a).connState.includes('reconnecting'));
    assert.ok(rec(a).system.some((m) => m.includes('Reconectando em 3s')));
  });

  // ── Server message handling ────────────────────────────────────
  it('JOIN_ACK registers peers and confirms E2E', () => {
    const hub = new Hub();
    const a = spawn();
    online(hub, a);
    assert.ok(rec(a).system.some((m) => m.includes('Conectado ao servidor')));
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
    assert.ok(rec(a).system.some((m) => m.includes('bob') && m.includes('saiu do chat')));
    bobKeys.destroy();
  });

  it('a NICKNAME_TAKEN error nudges toward /nick', () => {
    const a = spawn();
    a.conn.emit('message', createError(ERR.NICKNAME_TAKEN, 'Apelido em uso'));
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
    assert.ok(rec(a).errors.some((m) => m.includes('peer desconhecido')));
  });

  it('being kicked surfaces as an error to the user', () => {
    const a = spawn('alice');
    a.conn.emit('message', { type: MSG.PEER_KICKED, nickname: 'alice', reason: 'spam', self: true });
    assert.ok(rec(a).errors.some((m) => m.includes('expulso')));
  });

  it('ROOM_CHANGED updates the current room', () => {
    const a = spawn();
    a.conn.emit('message', createRoomChanged('projeto', []));
    input(a, '/room');
    assert.ok(rec(a).info.some((m) => m.includes('#projeto')));
  });

  // ── End-to-end through the hub ─────────────────────────────────
  it('delivers and decrypts a message between two clients', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob); // bob's JOIN_ACK includes alice; alice gets PEER_JOINED

    input(alice, 'ola bob, tudo certo?');

    assert.ok(
      rec(bob).messages.some((m) => m.nick === 'alice' && m.text === 'ola bob, tudo certo?'),
      'bob deve receber e decifrar a mensagem da alice',
    );
  });

  it('delivers and decrypts a deniable message', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/deniable on');
    input(alice, 'isto e negavel');

    // The wire message carries the deniable flag...
    const enc = alice.conn.sentOfType(MSG.ENCRYPTED_MESSAGE);
    assert.ok(enc.length >= 1 && enc.at(-1).payload.deniable === true);
    // ...and bob still decrypts and shows it.
    assert.ok(rec(bob).messages.some((m) => m.nick === 'alice' && m.text === 'isto e negavel'));
  });

  it('does not deliver across rooms', () => {
    const hub = new Hub();
    const alice = spawn('alice');
    const bob = spawn('bob');
    online(hub, alice);
    online(hub, bob);

    input(alice, '/join sala-secreta'); // alice leaves #general
    rec(bob).messages.length = 0;
    input(alice, 'so para quem esta na sala-secreta');

    assert.ok(
      rec(bob).messages.length === 0 || rec(alice).system.some((m) => m.includes('Nenhum peer')),
      'bob (em outra sala) nao deve receber',
    );
  });
});
