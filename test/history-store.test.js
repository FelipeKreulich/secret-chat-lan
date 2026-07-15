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

  test('abre vazio quando nao existe arquivo', () => {
    const store = new HistoryStore(dir);
    assert.equal(store.open('senha123'), true);
    assert.equal(store.size, 0);
    store.destroy();
  });

  test('persiste e recarrega com a mesma passphrase', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'felipe', text: 'ola mundo' });
    store.append({ room: 'jogos', nickname: 'davi', text: 'bora jogar', isDM: false });
    store.destroy(); // flush + wipe

    const reopened = new HistoryStore(dir);
    assert.equal(reopened.open('senha123'), true);
    assert.equal(reopened.size, 2);
    assert.equal(reopened.recent(1)[0].text, 'bora jogar');
    reopened.destroy();
  });

  test('purgeOlderThan remove entradas mais antigas que o corte', async () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'a', text: 'antiga' });
    await new Promise((r) => setTimeout(r, 40));
    store.append({ room: 'general', nickname: 'a', text: 'nova' });

    const removed = store.purgeOlderThan(20); // > 20ms atras → a 'antiga'
    assert.equal(removed, 1);
    assert.equal(store.size, 1);
    assert.equal(store.recent(1)[0].text, 'nova');
    store.destroy();
  });

  test('purgeOlderThan retorna 0 quando o store esta fechado', () => {
    const store = new HistoryStore(dir);
    assert.equal(store.purgeOlderThan(1000), 0);
  });

  test('rejeita passphrase errada', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'felipe', text: 'segredo' });
    store.destroy();

    const wrong = new HistoryStore(dir);
    assert.equal(wrong.open('senha-errada'), false);
    assert.equal(wrong.isOpen, false);
    assert.equal(wrong.size, 0);
  });

  test('arquivo em disco nao contem plaintext', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'felipe', text: 'conteudo-sensivel-xyz' });
    store.flush();
    store.destroy();

    const raw = readFileSync(join(dir, 'history', 'history.enc.json'), 'utf-8');
    assert.ok(!raw.includes('conteudo-sensivel-xyz'));
    assert.ok(!raw.includes('felipe'));
  });

  test('search filtra por texto e nickname, case-insensitive', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'felipe', text: 'Bora testar o Tailscale' });
    store.append({ room: 'general', nickname: 'davi', text: 'conectou finalmente' });
    store.append({ room: 'general', nickname: 'felipe', text: 'agora vai' });

    assert.equal(store.search('TAILSCALE').length, 1);
    assert.equal(store.search('davi').length, 1);
    assert.equal(store.search('nada-disso').length, 0);
    store.destroy();
  });

  test('recent respeita o limite pedido', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    for (let i = 1; i <= 30; i++) {
      store.append({ room: 'general', nickname: 'felipe', text: `msg ${i}` });
    }
    const last5 = store.recent(5);
    assert.equal(last5.length, 5);
    assert.equal(last5[4].text, 'msg 30');
    store.destroy();
  });

  test('append ignorado quando store nao foi aberto', () => {
    const store = new HistoryStore(dir);
    store.append({ room: 'general', nickname: 'felipe', text: 'perdida' });
    assert.equal(store.size, 0);
  });

  test('exportTo gera txt legivel e json valido', () => {
    const store = new HistoryStore(dir);
    store.open('senha123');
    store.append({ room: 'general', nickname: 'felipe', text: 'primeira' });
    store.append({ room: 'jogos', nickname: 'davi', text: 'segunda', isDM: true });

    const txtPath = join(dir, 'export.txt');
    assert.equal(store.exportTo(txtPath), 2);
    const txt = readFileSync(txtPath, 'utf-8');
    assert.match(txt, /\[#general\] felipe: primeira/);
    assert.match(txt, /\[#jogos\] \(DM\) davi: segunda/);

    const jsonPath = join(dir, 'export.json');
    assert.equal(store.exportTo(jsonPath), 2);
    const parsed = JSON.parse(readFileSync(jsonPath, 'utf-8'));
    assert.equal(parsed.length, 2);
    assert.equal(parsed[1].text, 'segunda');
    store.destroy();
  });
});
