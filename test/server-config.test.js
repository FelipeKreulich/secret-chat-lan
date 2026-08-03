import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseServerConfig, clientAddress, normalizeIp } from '../src/server/config.js';

describe('server config — limits from the environment', () => {
  it('falls back to the LAN defaults when nothing is set', () => {
    const c = parseServerConfig({});
    assert.equal(c.maxConnectionsPerIp, 20);
    assert.equal(c.maxConnectionsTotal, 500);
    assert.equal(c.maxRoomsPerSession, 10);
    assert.equal(c.trustProxy, false);
    assert.equal(c.motd, '');
    assert.equal(c.bannedIps.size, 0);
  });

  it('lets an operator tighten every cap', () => {
    const c = parseServerConfig({
      MAX_CONNECTIONS_TOTAL: '200',
      MAX_CONNECTIONS_PER_IP: '3',
      MESSAGE_RATE_LIMIT: '20',
      MAX_ROOMS_TOTAL: '50',
      MAX_ROOMS_PER_SESSION: '4',
    });
    assert.equal(c.maxConnectionsTotal, 200);
    assert.equal(c.maxConnectionsPerIp, 3);
    assert.equal(c.messageRateLimitPerSecond, 20);
    assert.equal(c.maxRoomsTotal, 50);
    assert.equal(c.maxRoomsPerSession, 4);
  });

  it('ignores junk instead of disabling a limit by accident', () => {
    const c = parseServerConfig({ MAX_CONNECTIONS_PER_IP: '0' });
    assert.equal(c.maxConnectionsPerIp, 20, 'zero would mean nobody can connect');
    assert.equal(parseServerConfig({ MAX_CONNECTIONS_PER_IP: 'abc' }).maxConnectionsPerIp, 20);
    assert.equal(parseServerConfig({ MAX_CONNECTIONS_PER_IP: '-5' }).maxConnectionsPerIp, 20);
  });

  it('reads the MOTD inline or from a file, and never crashes on a bad path', () => {
    assert.equal(parseServerConfig({ MOTD: '  hello  ' }).motd, 'hello');

    const dir = mkdtempSync(join(tmpdir(), 'cm-motd-'));
    const file = join(dir, 'motd.txt');
    writeFileSync(file, 'maintenance at 22h\n');
    assert.equal(parseServerConfig({ MOTD_FILE: file }).motd, 'maintenance at 22h');

    assert.equal(parseServerConfig({ MOTD_FILE: '/no/such/file' }).motd, '', 'boots anyway');
  });

  it('reads the banlist from env and file, ignoring comments and blanks', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cm-ban-'));
    const file = join(dir, 'banned.txt');
    writeFileSync(file, '# abuse 2026-08\n203.0.113.9\n\n198.51.100.4\n');

    const c = parseServerConfig({ BANNED_IPS: '192.0.2.1, 192.0.2.2', BANNED_IPS_FILE: file });
    assert.equal(c.bannedIps.has('192.0.2.1'), true);
    assert.equal(c.bannedIps.has('192.0.2.2'), true);
    assert.equal(c.bannedIps.has('203.0.113.9'), true);
    assert.equal(c.bannedIps.has('198.51.100.4'), true);
    assert.equal(c.bannedIps.has('#'), false, 'comments are not addresses');
    assert.equal(c.bannedIps.size, 4);
  });
});

describe('server config — client address behind a proxy', () => {
  const req = (ip, forwarded) => ({
    socket: { remoteAddress: ip },
    headers: forwarded ? { 'x-forwarded-for': forwarded } : {},
  });

  it('uses the socket address when no proxy is declared', () => {
    // Without TRUST_PROXY a client could otherwise forge its own address and
    // walk straight past the per-IP cap and the banlist.
    assert.equal(clientAddress(req('10.0.0.5', '1.2.3.4'), false), '10.0.0.5');
  });

  it('uses the forwarded client when a proxy IS declared', () => {
    assert.equal(clientAddress(req('10.0.0.5', '1.2.3.4'), true), '1.2.3.4');
    assert.equal(
      clientAddress(req('10.0.0.5', '1.2.3.4, 10.0.0.1'), true),
      '1.2.3.4',
      'the original client is the first entry',
    );
  });

  it('falls back to the socket when the header is missing or empty', () => {
    assert.equal(clientAddress(req('10.0.0.5'), true), '10.0.0.5');
    assert.equal(clientAddress(req('10.0.0.5', '   '), true), '10.0.0.5');
  });

  it('normalizes IPv6-mapped IPv4 so a banlist entry actually matches', () => {
    assert.equal(normalizeIp('::ffff:203.0.113.9'), '203.0.113.9');
    assert.equal(normalizeIp('203.0.113.9'), '203.0.113.9');
  });
});
