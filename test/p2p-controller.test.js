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
  const rec = { system: [], errors: [], info: [], messages: [], locks: [], badges: [] };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: (nick, text) => {
      rec.messages.push({ nick, text });
      return { lineIndex: rec.messages.length - 1 };
    },
    getLine: (i) => rec.messages[i]?.text ?? null,
    appendBadge: (lineIndex, baseLine, badge) => {
      rec.badges.push({ lineIndex, badge });
    },
    notifyEnabled: false,
    addActionMessage: (nick, text) => {
      rec.messages.push({ nick, text, isAction: true });
      return { lineIndex: rec.messages.length - 1 };
    },
    setTopic: (t) => {
      rec.topic = t;
    },
    showLock: (verify) => {
      rec.locks.push(verify);
    },
    isLocked: false,
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

function makeController(nick = 'alice', opts = {}) {
  const conn = new MockConn();
  const discovery = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const peerServer = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const ui = mockUI();
  const keys = new KeyManager();
  const controller = new P2PChatController(
    nick,
    peerServer,
    conn,
    discovery,
    ui,
    keys,
    opts.restoredState || null,
    null,
    opts.historyStore || null,
  );
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

  const spawn = (nick, opts = {}) => {
    const c = makeController(nick, opts);
    spawned.push(c);
    return c;
  };

  // ── Which path a room is on, and why (#481, item 3) ─────────────
  //
  // The mesh saves encryptions, not frames: one frame per peer goes out either
  // way. So the thing worth reporting here is how many times the line was
  // encrypted, and what pushed it back to one per peer.
  const sendLine = (c) => c.ui._rec.info.find((m) => m.startsWith('Sending:'));

  it('reports one encryption for the room by default', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    assert.deepEqual(alice.controller.groupSendStatus(), {
      group: true,
      reason: null,
      peers: 1,
    });
    alice.ui.emit('input', '/room');
    assert.match(sendLine(alice), /one encryption for the room, sent to 1/);
  });

  it('reports deniable mode as the reason for going pairwise', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/deniable on');
    assert.equal(alice.controller.groupSendStatus().reason, 'deniable');
    alice.ui.emit('input', '/room');
    assert.match(sendLine(alice), /1 encryption per message/);
    assert.match(sendLine(alice), /deniable mode is on/);
  });

  it('reports constant cover as the reason, which the relay path does not have', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/cover constant');
    assert.equal(alice.controller.groupSendStatus().reason, 'cover');
    alice.ui.emit('input', '/room');
    assert.match(sendLine(alice), /constant cover paces messages through pairwise slots/);
  });

  it('counts only the peers in this room', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/join projeto'); // bob stays in general
    assert.deepEqual(alice.controller.groupSendStatus(), {
      group: false,
      reason: 'alone',
      peers: 0,
    });
    alice.ui.emit('input', '/room');
    assert.match(sendLine(alice), /no one else is in this room/);
  });

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
    // room_announce + sender-key distribution + the flushed message
    assert.equal(conn.sentTo('bob').length, 3);
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
    assert.equal(
      conn.sentTo('bob').length,
      2,
      'only the connect handshake (announce + sender key), nothing from the queue',
    );
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
    // announce + sender key, then at most the cap.
    assert.equal(conn.sentTo('bob').length, 2 + OFFLINE_QUEUE_MAX_PER_PEER);
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

  it('moderation is refused in P2P, and points at the thing that does work', () => {
    // P2P has no room owners, so /kick, /mute and /ban have nobody to act on
    // anyone's behalf. Rejecting them is right — but leaving the user with
    // nothing was not, so the message has to name /block.
    const { ui } = spawn('alice');
    ui.emit('input', '/kick bob');

    const refusal = ui._rec.errors.find((m) => m.toLowerCase().includes('moderation'));
    assert.ok(refusal, 'moderation commands must be refused');
    assert.match(refusal, /\/block/);
  });

  it('/block works in P2P, where nothing else does', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/block');
    assert.ok(ui._rec.errors.some((m) => m.includes('Usage: /block')));

    // Blocking someone never seen is refused rather than silently recorded.
    ui.emit('input', '/block ghost');
    assert.ok(ui._rec.errors.some((m) => m.toLowerCase().includes('no record of')));
  });

  it('/blocklist reports an empty list rather than nothing', () => {
    const { ui } = spawn('alice');
    ui.emit('input', '/blocklist');
    assert.ok(ui._rec.info.some((m) => m.toLowerCase().includes('nobody blocked')));
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

  // ── Parity with the relay client (#352) ────────────────────
  it('P2P: messages flow BOTH ways right after connecting (#353)', () => {
    // Both sides connect at once; a pairwise message from a peer we have not
    // registered yet is dropped, so whoever announced first used to never get
    // the other's sender key — and silently could not read their messages.
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', 'da alice para o bob');
    bob.ui.emit('input', 'do bob para a alice');

    assert.ok(
      bob.ui._rec.messages.some((m) => m.text === 'da alice para o bob'),
      'alice → bob',
    );
    assert.ok(
      alice.ui._rec.messages.some((m) => m.text === 'do bob para a alice'),
      'bob → alice',
    );
  });

  it('P2P: read receipts mark the sent message and honour /receipts off', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', 'chegou?');
    assert.ok(
      alice.ui._rec.badges.some((b) => b.badge.includes('✓✓')),
      'bob confirmed the read and alice shows ✓✓',
    );

    // Turning them off stops bob from confirming.
    bob.ui.emit('input', '/receipts off');
    alice.ui._rec.badges.length = 0;
    alice.ui.emit('input', 'e agora?');
    assert.equal(alice.ui._rec.badges.length, 0, 'no confirmation once disabled');

    bob.ui.emit('input', '/receipts on');
    alice.ui.emit('input', 'de novo');
    assert.ok(
      alice.ui._rec.badges.some((b) => b.badge.includes('✓✓')),
      're-enabled',
    );
  });

  it('P2P: deniable and ephemeral messages are never acknowledged', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/deniable on');
    alice.ui._rec.badges.length = 0;
    alice.ui.emit('input', 'mensagem negavel');
    assert.equal(
      alice.ui._rec.badges.length,
      0,
      'acknowledging a deniable message would defeat its purpose',
    );

    alice.ui.emit('input', '/deniable off');
    alice.ui.emit('input', '/ephemeral 30s');
    alice.ui._rec.badges.length = 0;
    alice.ui.emit('input', 'mensagem efemera');
    assert.equal(alice.ui._rec.badges.length, 0, 'ephemeral leaves no trace either');
  });

  it('P2P: /me and /topic reach the peer like they do on the relay', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/me está compilando');
    const action = bob.ui._rec.messages.find((m) => m.text === 'está compilando');
    assert.ok(action?.isAction, 'peer renders it as an action');

    alice.ui.emit('input', '/topic sala de testes');
    assert.equal(alice.ui._rec.topic, 'sala de testes');
    assert.equal(bob.ui._rec.topic, 'sala de testes', 'topic propagates E2EE');
    assert.ok(bob.ui._rec.system.some((m) => m.includes('alice') && m.includes('sala de testes')));
  });

  it('P2P: presence commands announce to peers', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/away almoço');
    assert.ok(bob.ui._rec.system.some((m) => m.includes('alice is away')));

    alice.ui.emit('input', '/back');
    assert.ok(bob.ui._rec.system.some((m) => m.includes('alice is back')));

    alice.ui.emit('input', '/status codando');
    assert.ok(bob.ui._rec.system.some((m) => m.includes('codando')));
  });

  it('P2P: /lock needs a passphrase and /mentions tracks mentions', () => {
    const noPass = spawn('alice');
    noPass.ui.emit('input', '/lock');
    assert.ok(noPass.ui._rec.errors.some((m) => m.includes('passphrase')));

    const ana = spawn('ana', { restoredState: { passphrase: 'segredo' } });
    const bob = spawn('bob');
    connectPair(ana, bob);

    ana.ui.emit('input', '/lock');
    assert.equal(ana.ui._rec.locks.length, 1);
    assert.equal(ana.ui._rec.locks[0]('errada'), false);
    assert.equal(ana.ui._rec.locks[0]('segredo'), true);

    ana.ui._rec.info.length = 0;
    ana.ui.emit('input', '/mentions');
    assert.ok(ana.ui._rec.info.some((m) => m.includes('No mentions')));

    bob.ui.emit('input', 'oi @ana tudo bem?');
    ana.ui._rec.info.length = 0;
    ana.ui.emit('input', '/mentions');
    assert.ok(ana.ui._rec.info.some((m) => m.includes('bob') && m.includes('@ana')));
  });

  it('P2P: /contacts and /watch work like on the relay', () => {
    const alice = spawn('alice');
    const bob = spawn('bob');
    connectPair(alice, bob);

    alice.ui.emit('input', '/contacts add bob Bob da Firma');
    assert.ok(alice.ui._rec.info.some((m) => m.includes('Contact saved')));

    alice.ui.emit('input', '/watch add deploy');
    bob.ui.emit('input', 'fazer deploy amanha');
    assert.ok(alice.ui._rec.system.some((m) => m.includes('👁') && m.includes('deploy')));
  });

  it('P2P: history commands report the feature as off without a passphrase', () => {
    const alice = spawn('alice');
    for (const cmd of ['/search termo', '/history', '/export', '/retention 7d']) {
      alice.ui._rec.errors.length = 0;
      alice.ui.emit('input', cmd);
      assert.ok(
        alice.ui._rec.errors.some((m) => /History (disabled|is not active)/.test(m)),
        `${cmd} explains why it is unavailable`,
      );
    }
  });
});
