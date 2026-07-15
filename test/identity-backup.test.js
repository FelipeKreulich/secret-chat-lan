import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { exportBackup, importBackup } from '../src/crypto/IdentityBackup.js';

describe('IdentityBackup', () => {
  const data = {
    identity: { secretKey: 'c2s=', publicKey: 'cHVi', fingerprint: 'ab:cd' },
    trust: { alice: { publicKey: 'pkA', verified: true } },
  };

  it('round-trips identity + trust with the correct passphrase', () => {
    const env = exportBackup(data, 'strong-pass');
    const restored = importBackup(env, 'strong-pass');
    assert.deepEqual(restored.identity, data.identity);
    assert.deepEqual(restored.trust, data.trust);
    assert.equal(restored.version, 1);
  });

  it('returns null with the wrong passphrase', () => {
    const env = exportBackup(data, 'right');
    assert.equal(importBackup(env, 'wrong'), null);
  });

  it('returns null for a non-backup / corrupt envelope', () => {
    assert.equal(importBackup('{"kind":"other"}', 'x'), null);
    assert.equal(importBackup('not json', 'x'), null);
  });

  it('produces a self-describing encrypted envelope (no plaintext identity)', () => {
    const env = exportBackup(data, 'pass');
    assert.ok(env.includes('ciphermesh-backup'));
    assert.ok(!env.includes('fingerprint'), 'identity fields must be encrypted');
  });
});
