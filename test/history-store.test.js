import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HistoryStore } from '../src/crypto/HistoryStore.js';

describe('HistoryStore', () => {
  let dir;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ciphermesh-history-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('opens empty when the file does not exist', () => {
    const store = new HistoryStore(dir);
    assert.equal(store.open('pass123'), true);
    assert.equal(store.size, 0);
    store.destroy();
  });

  test('persists and reloads with the same passphrase', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'felipe', text: 'hello world' });
    store.append({ room: 'games', nickname: 'davi', text: 'play time', isDM: false });
    store.destroy(); // flush + wipe

    const reopened = new HistoryStore(dir);
    assert.equal(reopened.open('pass123'), true);
    assert.equal(reopened.size, 2);
    assert.equal(reopened.recent(1)[0].text, 'play time');
    reopened.destroy();
  });

  test('purgeOlderThan removes entries older than the cutoff', async () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'a', text: 'old' });
    await new Promise((r) => setTimeout(r, 40));
    store.append({ room: 'general', nickname: 'a', text: 'new' });

    const removed = store.purgeOlderThan(20); // > 20ms ago → the 'old' one
    assert.equal(removed, 1);
    assert.equal(store.size, 1);
    assert.equal(store.recent(1)[0].text, 'new');
    store.destroy();
  });

  test('purgeOlderThan returns 0 when the store is closed', () => {
    const store = new HistoryStore(dir);
    assert.equal(store.purgeOlderThan(1000), 0);
  });

  test('rejects a wrong passphrase', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'felipe', text: 'secret' });
    store.destroy();

    const wrong = new HistoryStore(dir);
    assert.equal(wrong.open('wrong-pass'), false);
    assert.equal(wrong.isOpen, false);
    assert.equal(wrong.size, 0);
  });

  test('the file on disk does not contain plaintext', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'felipe', text: 'sensitive-content-xyz' });
    store.flush();
    store.destroy();

    const raw = readFileSync(join(dir, 'history', 'history.enc.json'), 'utf-8');
    assert.ok(!raw.includes('sensitive-content-xyz'));
    assert.ok(!raw.includes('felipe'));
  });

  test('search filters by text and nickname, case-insensitive', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'felipe', text: 'Testing Tailscale' });
    store.append({ room: 'general', nickname: 'davi', text: 'connected at last' });
    store.append({ room: 'general', nickname: 'felipe', text: 'here we go' });

    assert.equal(store.search('TAILSCALE').length, 1);
    assert.equal(store.search('davi').length, 1);
    assert.equal(store.search('nothing-here').length, 0);
    store.destroy();
  });

  test('recent respects the requested limit', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    for (let i = 1; i <= 30; i++) {
      store.append({ room: 'general', nickname: 'felipe', text: `msg ${i}` });
    }
    const last5 = store.recent(5);
    assert.equal(last5.length, 5);
    assert.equal(last5[4].text, 'msg 30');
    store.destroy();
  });

  test('append is ignored when the store was not opened', () => {
    const store = new HistoryStore(dir);
    store.append({ room: 'general', nickname: 'felipe', text: 'lost' });
    assert.equal(store.size, 0);
  });

  test('exportTo produces readable txt and valid json', () => {
    const store = new HistoryStore(dir);
    store.open('pass123');
    store.append({ room: 'general', nickname: 'felipe', text: 'first' });
    store.append({ room: 'games', nickname: 'davi', text: 'second', isDM: true });

    const txtPath = join(dir, 'export.txt');
    assert.equal(store.exportTo(txtPath), 2);
    const txt = readFileSync(txtPath, 'utf-8');
    assert.match(txt, /\[#general\] felipe: first/);
    assert.match(txt, /\[#games\] \(DM\) davi: second/);

    const jsonPath = join(dir, 'export.json');
    assert.equal(store.exportTo(jsonPath), 2);
    const parsed = JSON.parse(readFileSync(jsonPath, 'utf-8'));
    assert.equal(parsed.length, 2);
    assert.equal(parsed[1].text, 'second');
    store.destroy();
  });
});
