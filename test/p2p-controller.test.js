import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyManager } from '../src/crypto/KeyManager.js';
import { P2PChatController } from '../src/p2p/P2PChatController.js';

// ── Mocks ────────────────────────────────────────────────────────
class MockConn extends EventEmitter {
  sent = [];
  send(nickname, data) {
    this.sent.push({ nickname, data });
    return true;
  }
  connectTo() {}
  destroy() {}
  sentTo(nick) {
    return this.sent.filter((s) => s.nickname === nick);
  }
}

function mockUI() {
  const rec = { system: [], errors: [], info: [] };
  const emitter = new EventEmitter();
  const target = {
    addSystemMessage: (m) => rec.system.push(m),
    addErrorMessage: (m) => rec.errors.push(m),
    addInfoMessage: (m) => rec.info.push(m),
    addMessage: () => ({ lineIndex: 0 }),
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

function makeController() {
  const conn = new MockConn();
  const discovery = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const peerServer = Object.assign(new EventEmitter(), { start() {}, stop() {} });
  const ui = mockUI();
  const myKeys = new KeyManager();
  const controller = new P2PChatController('alice', peerServer, conn, discovery, ui, myKeys);
  return { conn, ui, controller, myKeys };
}

// ── Tests ────────────────────────────────────────────────────────
describe('P2PChatController', () => {
  let cwd;
  let home;
  let tempDir;

  beforeEach(() => {
    // Contain all file I/O (TrustStore/FileTransfer use cwd, AuditLog uses HOME).
    tempDir = mkdtempSync(join(tmpdir(), 'ciphermesh-p2p-'));
    cwd = process.cwd();
    home = process.env.HOME;
    process.chdir(tempDir);
    process.env.HOME = tempDir;
  });

  afterEach(() => {
    process.chdir(cwd);
    process.env.HOME = home;
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('store-and-forward: queues for an offline known peer and delivers on reconnect', () => {
    const { conn, ui, controller, myKeys } = makeController();
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });
    conn.emit('peer-disconnected', 'bob'); // bob leaves but stays "known"

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    ui.emit('input', 'mensagem para o bob offline');

    // Nothing sent (bob offline), but it was queued.
    assert.equal(conn.sentTo('bob').length, 0);
    assert.ok(
      ui._rec.system.some((m) => m.includes('Enfileirada')),
      'deve avisar que enfileirou',
    );

    // Reconnect → the queue is flushed to bob.
    conn.sent.length = 0;
    ui._rec.system.length = 0;
    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 });

    assert.ok(
      ui._rec.system.some((m) => m.includes('entregue')),
      'deve avisar que entregou a fila',
    );
    // On reconnect: 1 room_announce + 1 flushed message.
    assert.equal(conn.sentTo('bob').length, 2);

    controller.destroy();
    bob.destroy();
    myKeys.destroy();
  });

  it('rooms: a message is not delivered to a peer in a different room', () => {
    const { conn, ui, controller, myKeys } = makeController();
    const bob = new KeyManager();

    conn.emit('peer-connected', { nickname: 'bob', publicKey: bob.publicKeyB64 }); // bob in #general
    ui.emit('input', '/join sala1'); // I move to #sala1

    conn.sent.length = 0;
    ui._rec.system.length = 0;
    ui.emit('input', 'oi galera da sala1');

    assert.equal(conn.sentTo('bob').length, 0, 'nao envia para peer de outra sala');
    assert.ok(
      ui._rec.system.some((m) => m.includes('Ninguem na sala')),
      'avisa que nao ha ninguem na sala',
    );

    controller.destroy();
    bob.destroy();
    myKeys.destroy();
  });

  it('/room reports the current room and /join changes it', () => {
    const { ui, controller, myKeys } = makeController();

    ui.emit('input', '/room');
    assert.ok(ui._rec.info.some((m) => m.includes('#general')));

    ui.emit('input', '/join projeto');
    ui._rec.info.length = 0;
    ui.emit('input', '/room');
    assert.ok(ui._rec.info.some((m) => m.includes('#projeto')));

    controller.destroy();
    myKeys.destroy();
  });

  it('suggests the nearest command for a typo', () => {
    const { ui, controller, myKeys } = makeController();

    ui.emit('input', '/qut');
    assert.ok(
      ui._rec.errors.some((m) => m.includes('/quit')),
      'deve sugerir /quit',
    );

    controller.destroy();
    myKeys.destroy();
  });
});
