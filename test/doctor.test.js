import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { parseTarget, diagnose, formatDiagnosis } from '../src/shared/doctor.js';

// Fake sockets: the diagnose() steps are driven by events, so each stub emits
// the outcome we want on the next tick.
function fakeSocket(emitWhat, payload = {}) {
  const s = new EventEmitter();
  s.setTimeout = () => {};
  s.destroy = () => {};
  s.getPeerCertificate = () => payload.cert || {};
  s.authorized = payload.authorized === true;
  setImmediate(() => s.emit(emitWhat, payload.arg));
  return s;
}

const deps = ({
  dns = '1.2.3.4',
  tcp = 'connect',
  tls = 'secureConnect',
  tlsPayload = {},
} = {}) => ({
  lookup: (host, cb) => setImmediate(() => (dns ? cb(null, dns) : cb(new Error('ENOTFOUND')))),
  netConnect: () =>
    tcp === 'connect'
      ? fakeSocket('connect')
      : fakeSocket(tcp === 'timeout' ? 'timeout' : 'error', { arg: { code: 'ECONNREFUSED' } }),
  tlsConnect: () =>
    tls === 'secureConnect'
      ? fakeSocket('secureConnect', tlsPayload)
      : fakeSocket('error', { arg: { code: 'EPROTO' } }),
});

const byName = (steps, name) => steps.find((s) => s.name === name);

describe('doctor — parseTarget', () => {
  it('accepts host:port with or without a scheme and defaults the port', () => {
    assert.deepEqual(parseTarget('192.168.1.10:3600'), {
      host: '192.168.1.10',
      port: 3600,
      tls: true,
      url: 'wss://192.168.1.10:3600',
    });
    assert.equal(parseTarget('ws://host:1234').tls, false, 'ws:// is plain');
    assert.equal(parseTarget('host').port, 3600, 'defaults to the CipherMesh port');
  });

  it('rejects junk instead of guessing', () => {
    assert.equal(parseTarget(''), null);
    assert.equal(parseTarget('   '), null);
    assert.equal(parseTarget('host:99999'), null, 'port out of range');
  });
});

describe('doctor — diagnose', () => {
  it('reports every layer when the path is healthy', async () => {
    const steps = await diagnose('192.168.1.10:3600', { deps: deps() });
    assert.equal(
      steps.every((s) => s.ok),
      true,
      'nothing failed',
    );
    assert.match(byName(steps, 'TCP port').detail, /open/);
    assert.match(byName(steps, 'TLS').detail, /self-signed/);
    assert.match(byName(steps, 'Protocol').detail, /v2/);
  });

  it('flags localhost, which is the classic "he cannot reach me" mistake', async () => {
    const steps = await diagnose('localhost:3600', { deps: deps() });
    const target = byName(steps, 'Target');
    assert.ok(target, 'localhost gets its own note');
    assert.match(target.hint, /YOUR machine|never leaves/i);
  });

  it('stops at the TCP step and explains a dropped port', async () => {
    const steps = await diagnose('10.0.0.9:3600', { deps: deps({ tcp: 'timeout' }) });
    const tcp = byName(steps, 'TCP port');
    assert.equal(tcp.ok, false);
    assert.match(tcp.hint, /firewall|isolation/i);
    assert.equal(byName(steps, 'TLS'), undefined, 'later checks are skipped');
  });

  it('stops at DNS when the name does not resolve', async () => {
    const steps = await diagnose('nao-existe.local:3600', { deps: deps({ dns: null }) });
    assert.equal(byName(steps, 'DNS').ok, false);
    assert.equal(byName(steps, 'TCP port'), undefined);
  });

  it('distinguishes a CA-signed certificate from a self-signed one', async () => {
    const steps = await diagnose('hub.example.com:443', {
      deps: deps({ tlsPayload: { authorized: true, cert: { issuer: { O: "Let's Encrypt" } } } }),
    });
    assert.match(byName(steps, 'TLS').detail, /public CA \(Let's Encrypt\)/);
  });

  it('never sets SNI for an IP target (Node throws if you do)', async () => {
    let sniSeen;
    const spy = {
      ...deps(),
      tlsConnect: (opts) => {
        sniSeen = opts.servername;
        return fakeSocket('secureConnect');
      },
    };
    await diagnose('192.168.1.7:3600', { deps: spy });
    assert.equal(sniSeen, undefined, 'no servername for an IP literal');

    await diagnose('hub.example.com:3600', { deps: spy });
    assert.equal(sniSeen, 'hub.example.com', 'but a hostname still gets SNI');
  });

  it('reports a bad address without touching the network', async () => {
    let touched = false;
    const steps = await diagnose('   ', {
      deps: { ...deps(), netConnect: () => ((touched = true), fakeSocket('connect')) },
    });
    assert.equal(steps.length, 1);
    assert.equal(steps[0].ok, false);
    assert.equal(touched, false, 'no connection attempted for unparseable input');
  });
});

describe('doctor — formatDiagnosis', () => {
  it('marks each step and names where it stopped', () => {
    const lines = formatDiagnosis([
      { name: 'Address', ok: true, detail: 'host:3600' },
      { name: 'TCP port', ok: false, detail: 'unreachable', hint: 'check the firewall' },
    ]);
    assert.ok(lines[0].startsWith('✓'));
    assert.ok(lines[1].startsWith('✗'));
    assert.match(lines[2], /check the firewall/);
    assert.match(lines[3], /Blocked at "TCP port"/);
  });

  it('says so plainly when everything passed', () => {
    const lines = formatDiagnosis([{ name: 'Address', ok: true, detail: 'ok' }]);
    assert.match(lines.at(-1), /All checks passed/);
  });
});
