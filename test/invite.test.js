import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInvite, parseInvite } from '../src/shared/invite.js';

describe('Invite', () => {
  test('build generates a URI with host, port and room', () => {
    assert.equal(buildInvite('100.124.6.27:3600', 'general'), 'ciphermesh://100.124.6.27:3600/general');
  });

  test('build uses the general room by default', () => {
    assert.equal(buildInvite('10.0.0.5:3600'), 'ciphermesh://10.0.0.5:3600/general');
  });

  test('build rejects invalid inputs', () => {
    assert.equal(buildInvite('no-port'), null);
    assert.equal(buildInvite('host:0'), null);
    assert.equal(buildInvite('host:99999'), null);
    assert.equal(buildInvite('host with space:3600'), null);
    assert.equal(buildInvite('10.0.0.5:3600', 'room with space'), null);
  });

  test('parse round-trips with build', () => {
    const uri = buildInvite('felipe.tail9c569f.ts.net:3600', 'games');
    const parsed = parseInvite(uri);
    assert.deepEqual(parsed, {
      host: 'felipe.tail9c569f.ts.net',
      port: 3600,
      room: 'games',
      wsUrl: 'wss://felipe.tail9c569f.ts.net:3600',
    });
  });

  test('parse assumes general when the URI has no room', () => {
    const parsed = parseInvite('ciphermesh://192.168.1.10:3600');
    assert.equal(parsed.room, 'general');
    assert.equal(parsed.wsUrl, 'wss://192.168.1.10:3600');
  });

  test('parse accepts a trailing slash with no room', () => {
    assert.equal(parseInvite('ciphermesh://192.168.1.10:3600/').room, 'general');
  });

  test('parse rejects invalid URIs', () => {
    assert.equal(parseInvite('http://10.0.0.1:3600'), null);
    assert.equal(parseInvite('ciphermesh://noport'), null);
    assert.equal(parseInvite('ciphermesh://host:abc'), null);
    assert.equal(parseInvite('ciphermesh://host:3600/invalid room'), null);
    assert.equal(parseInvite(null), null);
    assert.equal(parseInvite(''), null);
  });
});
