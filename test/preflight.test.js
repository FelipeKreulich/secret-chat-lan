import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { formatPreflight, preflight } from '../src/server/preflight.js';

const has = (findings, needle) => findings.some((f) => f.text.includes(needle));
const errors = (findings) => findings.filter((f) => f.level === 'error');

describe('preflight', () => {
  it('is silent on a plain LAN relay', () => {
    // The defaults were chosen for exactly this case. If it warns here, the
    // check becomes noise on the most common setup and people stop reading it.
    assert.deepEqual(preflight({}), []);
  });

  it('catches the misconfiguration that protects nobody', () => {
    // TRUST_PROXY off behind a proxy is invisible from outside: chat works, and
    // the per-IP cap, the rate limit and the banlist all silently apply to the
    // proxy instead of to anyone. Nothing breaks, so nobody looks.
    const findings = preflight({ CIPHERMESH_DOMAIN: 'hub.example.com' });
    assert.equal(errors(findings).length, 1);
    assert.ok(has(findings, 'TRUST_PROXY is off'));
  });

  it('catches the reverse, where a header can be forged', () => {
    // Trusting X-Forwarded-For on a directly reachable relay is worse than not
    // trusting it: any client can then claim any address it likes.
    const findings = preflight({ TRUST_PROXY: 'true' });
    assert.ok(has(findings, 'forge'));
  });

  it('says nothing about proxies when the proxy is actually there', () => {
    const findings = preflight({
      CIPHERMESH_DOMAIN: 'hub.example.com',
      TRUST_PROXY: 'true',
      MAX_CONNECTIONS_PER_IP: '4',
      CONNECTION_RATE_PER_MINUTE: '15',
    });
    assert.deepEqual(findings, []);
  });

  it('points out LAN defaults left on a public relay', () => {
    const findings = preflight({ PUBLIC_RELAY: 'true' });
    assert.ok(has(findings, 'MAX_CONNECTIONS_PER_IP'));
    assert.ok(has(findings, 'CONNECTION_RATE_PER_MINUTE'));
    // Advice, not refusal: they are defensible choices, just rarely the right
    // ones on the open internet.
    assert.deepEqual(errors(findings), []);
  });

  it('treats an unreadable banlist as a finding, because it fails open', () => {
    // A missing mount leaves the banlist empty and says nothing. Everyone gets
    // in, and the operator believes the file is doing something.
    const findings = preflight({ BANNED_IPS_FILE: '/nope/banned.txt' });
    assert.ok(has(findings, 'BANNED_IPS_FILE'));
  });

  it('refuses to call it fine when TLS is off and nothing fronts it', () => {
    const findings = preflight({ PUBLIC_RELAY: 'true', TLS: 'false' });
    assert.ok(errors(findings).some((f) => f.text.includes('TLS')));
  });

  it('formats an empty result as a plain all-clear', () => {
    assert.deepEqual(formatPreflight([]), ['Configuration looks fine.']);
    assert.ok(formatPreflight(preflight({ TRUST_PROXY: 'true' }))[0].startsWith('warn'));
  });
});
