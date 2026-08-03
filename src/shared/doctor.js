// Connection doctor: answers "why can't I connect?" in the order the failures
// actually happen, so a user without a terminal debugger can fix it alone.
//
// Every step reports what was checked, whether it passed, and — when it fails
// — what to do about it. A failing step stops the run: there is no point
// testing TLS when the TCP port never opened.
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { lookup as dnsLookup } from 'node:dns';
import { PROTOCOL_VERSION } from './constants.js';

const DEFAULT_TIMEOUT_MS = 6000;

/** Split "wss://host:3600" (or "host:3600") into its parts. */
export function parseTarget(raw) {
  const value = String(raw || '').trim();
  if (!value) {
    return null;
  }
  const withScheme = /^wss?:\/\//.test(value) ? value : `wss://${value}`;
  try {
    const url = new URL(withScheme);
    // No explicit port: mirror what the WebSocket client will actually do —
    // wss:// goes to 443 and ws:// to 80. Assuming 3600 here would have made
    // /doctor test a different port than the one the chat connects to, which
    // is exactly the confusion the command exists to prevent.
    const defaultPort = url.protocol === 'wss:' ? 443 : 80;
    const port = Number(url.port) || defaultPort;
    if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
      return null;
    }
    return { host: url.hostname, port, tls: url.protocol === 'wss:', url: withScheme };
  } catch {
    return null;
  }
}

const isIpLiteral = (host) => /^[\d.]+$/.test(host) || host.includes(':');

function step(name, ok, detail, hint = null) {
  return hint ? { name, ok, detail, hint } : { name, ok, detail };
}

function resolveHost(host, deps) {
  return new Promise((resolve) => {
    deps.lookup(host, (err, address) => resolve(err ? null : address));
  });
}

function probeTcp(host, port, timeoutMs, deps) {
  return new Promise((resolve) => {
    const socket = deps.netConnect({ host, port });
    const done = (result) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => done({ ok: true }));
    socket.on('timeout', () => done({ ok: false, reason: 'timeout' }));
    socket.on('error', (err) => done({ ok: false, reason: err.code || err.message }));
  });
}

function probeTls(host, port, timeoutMs, deps) {
  return new Promise((resolve) => {
    // SNI is a hostname field: Node throws outright if given an IP, and on a
    // LAN the target is almost always an IP. Send it only when we have a name.
    const sni = isIpLiteral(host) ? {} : { servername: host };
    // Diagnostic socket only: it completes the handshake, reads the
    // certificate, reports it and closes — no data is ever sent over it.
    // rejectUnauthorized is off precisely so a self-signed LAN certificate
    // still reaches this point and can be DESCRIBED to the user instead of
    // failing opaquely. The real chat connection does not run this way: it
    // enforces strict verification for hosts that ever presented a CA-valid
    // certificate (see crypto/CertPinStore.js).
    const socket = deps.tlsConnect({ host, port, rejectUnauthorized: false, ...sni });
    const done = (result) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate?.() || {};
      done({
        ok: true,
        authorized: socket.authorized === true,
        // WHY it failed matters: a self-signed LAN cert is expected, but a
        // hostname mismatch means you reached a different server entirely —
        // usually stale DNS. Reporting both as "self-signed" hides that.
        reason: socket.authorizationError || null,
        subject: cert.subject?.CN || null,
        issuer: cert.issuer?.O || cert.issuer?.CN || 'unknown',
        fingerprint: cert.fingerprint256 || null,
      });
    });
    socket.on('timeout', () => done({ ok: false, reason: 'timeout' }));
    socket.on('error', (err) => done({ ok: false, reason: err.code || err.message }));
  });
}

/**
 * Run the connection checks against `target`.
 *
 * @param {string} target - what the user typed at the Server prompt
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs]
 * @param {object} [opts.deps] - injectable node primitives (tests)
 * @returns {Promise<Array<{name, ok, detail, hint?}>>}
 */
export async function diagnose(target, opts = {}) {
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const deps = {
    lookup: dnsLookup,
    netConnect,
    tlsConnect,
    ...(opts.deps || {}),
  };
  const steps = [];

  const parsed = parseTarget(target);
  if (!parsed) {
    steps.push(
      step(
        'Address',
        false,
        `cannot parse "${target}"`,
        'Use host:port — for example 192.168.1.10:3600 — or a ciphermesh:// invite.',
      ),
    );
    return steps;
  }
  steps.push(
    step('Address', true, `${parsed.host}:${parsed.port} (${parsed.tls ? 'TLS' : 'plain'})`),
  );

  if (/^(localhost|127\.|::1)/.test(parsed.host)) {
    steps.push(
      step(
        'Target',
        true,
        'localhost — this points at YOUR machine',
        'To reach someone else, use THEIR address. localhost never leaves this computer.',
      ),
    );
  }

  if (!isIpLiteral(parsed.host)) {
    const address = await resolveHost(parsed.host, deps);
    steps.push(
      address
        ? step('DNS', true, `${parsed.host} → ${address}`)
        : step(
            'DNS',
            false,
            `cannot resolve ${parsed.host}`,
            'Check the name, or use the IP directly.',
          ),
    );
    if (!address) {
      return steps;
    }
  }

  const tcp = await probeTcp(parsed.host, parsed.port, timeoutMs, deps);
  if (!tcp.ok) {
    steps.push(
      step(
        'TCP port',
        false,
        `port ${parsed.port} unreachable (${tcp.reason})`,
        tcp.reason === 'timeout'
          ? 'Something is dropping the packets: a firewall on either side, or client isolation on the Wi-Fi router. If you can ping the host but not open the port, that is the usual cause.'
          : 'Nothing is listening there. Is the server running, and is the port right?',
      ),
    );
    return steps;
  }
  steps.push(step('TCP port', true, `${parsed.host}:${parsed.port} is open`));

  if (parsed.tls) {
    const tls = await probeTls(parsed.host, parsed.port, timeoutMs, deps);
    if (!tls.ok) {
      steps.push(
        step(
          'TLS',
          false,
          `handshake failed (${tls.reason})`,
          'The port answered but did not negotiate TLS. Is that really a CipherMesh relay?',
        ),
      );
      return steps;
    }
    if (tls.authorized) {
      steps.push(step('TLS', true, `verified against a public CA (${tls.issuer})`));
    } else if (tls.reason === 'ERR_TLS_CERT_ALTNAME_INVALID') {
      // The certificate is valid but belongs to someone else: you are talking
      // to the wrong machine. Almost always a stale or wrong DNS record.
      steps.push(
        step(
          'TLS',
          false,
          `the certificate is for "${tls.subject || '?'}", not ${parsed.host}`,
          'You reached a different server than you meant to. Check the DNS record for this name, ' +
            'and flush your resolver cache if it was changed recently.',
        ),
      );
      return steps;
    } else {
      steps.push(
        step(
          'TLS',
          true,
          `self-signed certificate (normal on a LAN)${tls.reason ? ` — ${tls.reason}` : ''}`,
          'Trust is pinned on first use — compare fingerprints out-of-band if you want certainty.',
        ),
      );
    }
  }

  steps.push(
    step(
      'Protocol',
      true,
      `this client speaks v${PROTOCOL_VERSION}`,
      'If the server refuses with a protocol mismatch, update BOTH sides: npx ciphermesh@latest, or git pull && npm install from source.',
    ),
  );

  return steps;
}

/** Render diagnose() output as lines ready for the chat log. */
export function formatDiagnosis(steps) {
  const lines = [];
  for (const s of steps) {
    lines.push(`${s.ok ? '✓' : '✗'} ${s.name}: ${s.detail}`);
    if (s.hint) {
      lines.push(`    ↳ ${s.hint}`);
    }
  }
  const failed = steps.find((s) => !s.ok);
  lines.push(
    failed
      ? `Blocked at "${failed.name}". Fix that first — the checks after it were skipped.`
      : 'All checks passed. If the chat still fails, the problem is above the network layer.',
  );
  return lines;
}
