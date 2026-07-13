import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInvite, parseInvite } from '../src/shared/invite.js';

describe('Invite', () => {
  test('build gera URI com host, porta e sala', () => {
    assert.equal(buildInvite('100.124.6.27:3600', 'geral'), 'ciphermesh://100.124.6.27:3600/geral');
  });

  test('build usa sala general por padrao', () => {
    assert.equal(buildInvite('10.0.0.5:3600'), 'ciphermesh://10.0.0.5:3600/general');
  });

  test('build rejeita entradas invalidas', () => {
    assert.equal(buildInvite('sem-porta'), null);
    assert.equal(buildInvite('host:0'), null);
    assert.equal(buildInvite('host:99999'), null);
    assert.equal(buildInvite('host com espaco:3600'), null);
    assert.equal(buildInvite('10.0.0.5:3600', 'sala com espaco'), null);
  });

  test('parse faz roundtrip com build', () => {
    const uri = buildInvite('felipe.tail9c569f.ts.net:3600', 'jogos');
    const parsed = parseInvite(uri);
    assert.deepEqual(parsed, {
      host: 'felipe.tail9c569f.ts.net',
      port: 3600,
      room: 'jogos',
      wsUrl: 'wss://felipe.tail9c569f.ts.net:3600',
    });
  });

  test('parse assume general sem sala na URI', () => {
    const parsed = parseInvite('ciphermesh://192.168.1.10:3600');
    assert.equal(parsed.room, 'general');
    assert.equal(parsed.wsUrl, 'wss://192.168.1.10:3600');
  });

  test('parse aceita barra final sem sala', () => {
    assert.equal(parseInvite('ciphermesh://192.168.1.10:3600/').room, 'general');
  });

  test('parse rejeita URIs invalidas', () => {
    assert.equal(parseInvite('http://10.0.0.1:3600'), null);
    assert.equal(parseInvite('ciphermesh://semporta'), null);
    assert.equal(parseInvite('ciphermesh://host:abc'), null);
    assert.equal(parseInvite('ciphermesh://host:3600/sala invalida'), null);
    assert.equal(parseInvite(null), null);
    assert.equal(parseInvite(''), null);
  });
});
