import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { P2PChatController } from '../src/p2p/P2PChatController.js';
import { OFFLINE_QUEUE_MAX_PER_PEER } from '../src/shared/constants.js';

// ── Mocks ────────────────────────────────────────────────────────
class MockConn extends EventEmitter {
  sent = [];
  route = null; // (nickname, data) => deliver to the peer's conn
  send(nickname, data) {
    this.sent.push({ nickname, data });
    if (this.route) {
      this.route(nickname, data);
    }
    return true;
  }
  connectTo() {}
  destroy() {}
  sentTo(nick) {
    return this.sent.filter((s) => s.nickname === nick);
  }
}

function mockUI() {
  const rec = { system: [], errors: [], info: [], messages: [] };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: (nick, text) => {
      rec.messages.push({ nick, text });
      return { lineIndex: 0 };
    },
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

function makeController(nick = 'alice') {
  const conn = new MockConn();
  const discovery = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const peerServer = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const ui = mockUI();
  const keys = new KeyManager();
  const controller = new P2PChatController(nick, peerServer, conn, discovery, ui, keys);
  return { conn, ui, controller, keys, nick };
}

// Wire two controllers together over their mock conns and connect them.
function connectPair(a, b) {
  a.conn.route = (nick, data) => {
    if (nick === b.nick) {
      b.conn.emit('message', a.nick, data);
    }
  };
  b.conn.route = (nick, data) => {
    if (nick === a.nick) {
      a.conn.emit('message', b.nick, data);
    }
  };
  a.conn.emit('peer-connected', { nickname: b.nick, publicKey: b.keys.publicKeyB64 });
  b.conn.emit('peer-connected', { nickname: a.nick, publicKey: a.keys.publicKeyB64 });
}

// ── Tests ────────────────────────────────────────────────────────
describe('P2PChatController', () => {
  let cwd;
  let home;
  let tempDir;
  const spawned = [];

  beforeEach(() => {
    // Contain all file I/O (TrustStore/FileTransfer use cwd, AuditLog uses HOME).
    tempDir = mkdtempSync(join(tmpdir(), 'ciphermesh-p2p-'));
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
        c.keys.destroy();
      } catch {
        /* ignore */
      }
    }
    process.chdir(cwd);
    process.env.HOME = home;
    rmSync(tempDir, { recursive: true, force: true });
  });

  const spawn = (nick) => {
    const c = makeController(nick);
    spawned.push(c);
    return c;
  };

  it('delivers and decrypts a message end-to-end between two controllers', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', 'hi bob, all good?');

    assert.ok(
      bob.ui._rec.messages.some((m) => m.nick === 'alice' && m.text === 'hi bob, all good?'),
      "bob should have received and decrypted alice's message",
    );
  });

  it('a message IS delivered to a peer in the same room', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/join projeto');
    bob.ui.emit('input', '/join projeto'); // bob announces the same room to alice

    bob.ui._rec.messages.length = 0;
    alice.ui.emit('input', 'message in room projeto');

    assert.ok(
      bob.ui._rec.messages.some((m) => m.text === 'message in room projeto'),
      'peer in the same room receives it',
    );
  });

  it('store-and-forward: queues for an offline known peer and delivers on reconnect', () => {
    const { conn, ui } = spawn('alice');
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    conn.emit('peer-disconnected', 'bob'); // bob leaves but stays "known"

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    ui.emit('input', 'message for offline bob');

    assert.equal(conn.sentTo('bob').length, 0);
    assert.ok(ui._rec.system.some((m) => m.includes('Queued')));

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });

    assert.ok(ui._rec.system.some((m) => m.includes('delivered')));
    assert.equal(conn.sentTo('bob').length, 2); // room_announce + flushed message
    bob.destroy();
  });

  it('store-and-forward: does not queue deniable messages', () => {
    const { conn, ui } = spawn('alice');
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    ui.emit('input', '/deniable on');
    conn.emit('peer-disconnected', 'bob');

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    ui.emit('input', 'secret that must not be queued');

    assert.ok(!ui._rec.system.some((m) => m.includes('Queued')), 'deniable does not queue');

    conn.sent.length = 0;
    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    assert.equal(conn.sentTo('bob').length, 1, 'only room_announce, nothing from the queue');
    bob.destroy();
  });

  it('store-and-forward: the per-peer queue is bounded', () => {
    const { conn } = spawn('alice');
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    conn.emit('peer-disconnected', 'bob');

    const { ui } = spawned[0];
    for (let i = 0; i < OFFLINE_QUEUE_MAX_PER_PEER + 20; i++) {
      ui.emit('input', `msg ${i}`);
    }

    conn.sent.length = 0;
    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    // 1 room_announce + at most the cap.
    assert.equal(conn.sentTo('bob').length, 1 + OFFLINE_QUEUE_MAX_PER_PEER);
    bob.destroy();
  });

  it('rooms: a message is not delivered to a peer in a different room', () => {
    const { conn, ui } = spawn('alice');
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 }); // bob in #general
    ui.emit('input', '/join room1'); // I move to #room1

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    ui.emit('input', 'hey everyone in room1');

    assert.equal(conn.sentTo('bob').length, 0, 'does not send to a peer in another room');
    assert.ok(ui._rec.system.some((m) => m.includes('Nobody in room')));
    bob.destroy();
  });

  it('/room reports the current room and /join changes it', () => {
    const { ui } = spawn('alice');

    ui.emit('input', '/room');
    assert.ok(ui._rec.info.some((m) => m.includes('#general')));

    ui.emit('input', '/join projeto');
    ui._rec.info.length = 0;
    ui.emit('input', '/room');
    assert.ok(ui._rec.info.some((m) => m.includes('#projeto')));
  });

  it('/deniable toggles the mode on and off', () => {
    const { ui } = spawn('alice');

    ui.emit('input', '/deniable on');
    assert.ok(ui._rec.info.some((m) => m.toLowerCase().includes('enabled')));

    ui._rec.info.length = 0;
    ui.emit('input', '/deniable off');
    assert.ok(ui._rec.info.some((m) => m.toLowerCase().includes('disabled')));
  });

  it('suggests the nearest command for a typo', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/qut');
    assert.ok(ui._rec.errors.some((m) => m.includes('/quit')));
  });

  it('reports an unknown command with no close match', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/zxcvb');
    assert.ok(ui._rec.errors.some((m) => m.includes('Unknown command') && m.includes('/help')));
  });

  it('moderation commands are not available in P2P mode', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/kick bob');
    assert.ok(ui._rec.errors.some((m) => m.toLowerCase().includes('moderation not available')));
  });

  it('/backup without a session passphrase is rejected', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/backup ./x.json');
    assert.ok(ui._rec.errors.some((m) => m.toLowerCase().includes('passphrase')));
  });

  it('/reject with no pending file offer reports nothing pending', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/reject');
    assert.ok(ui._rec.errors.some((m) => m.toLowerCase().includes('no pending file offer')));
  });

  it('/cover toggles cover traffic on and off', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/cover on');
    assert.ok(ui._rec.info.some((m) => m.toLowerCase().includes('enabled')));
    ui.emit('input', '/cover off');
    assert.ok(ui._rec.info.some((m) => m.toLowerCase().includes('disabled')));
  });

  it('a decoy is delivered on the wire but dropped silently by the peer', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    bob.ui._rec.messages.length = 0;
    alice.conn.sent.length = 0;
    alice.controller.sendCoverNow();

    assert.ok(alice.conn.sentTo('bob').length >= 1, 'decoy is transmitted to bob');
    assert.equal(bob.ui._rec.messages.length, 0, 'bob shows nothing for a decoy');
  });

  it('delivers a room message via sender-key group crypto (p2p_group)', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    bob.ui._rec.messages.length = 0;
    alice.conn.sent.length = 0;
    alice.ui.emit('input', 'hi group');

    // Sent as a single group ciphertext, not a pairwise p2p_message.
    const groupSends = alice.conn.sent.filter((s) => s.data.type === 'p2p_group');
    assert.equal(groupSends.length, 1, 'one group encryption for the room peer');
    assert.equal(groupSends[0].data.room, 'general');
    // Bob decrypts it with the sender key distributed on connect.
    assert.ok(bob.ui._rec.messages.some((m) => m.nick === 'alice' && m.text === 'hi group'));
  });

  it('deniable messages stay on the pairwise path (not group)', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/deniable on');
    bob.ui._rec.messages.length = 0;
    alice.conn.sent.length = 0;
    alice.ui.emit('input', 'deniable secret');

    assert.equal(alice.conn.sent.filter((s) => s.data.type === 'p2p_group').length, 0);
    assert.ok(alice.conn.sent.some((s) => s.data.type === 'p2p_message'));
    assert.ok(bob.ui._rec.messages.some((m) => m.text === 'deniable secret'));
  });

  it('constant cover paces a real message through the next slot', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/cover constant');
    alice.conn.sent.length = 0;
    bob.ui._rec.messages.length = 0;

    alice.ui.emit('input', 'hi paced');
    assert.equal(alice.conn.sentTo('bob').length, 0, 'queued, not on the wire yet');

    alice.controller.coverTick();
    assert.ok(
      bob.ui._rec.messages.some((m) => m.text === 'hi paced'),
      'delivered in the next slot',
    );
  });
});
