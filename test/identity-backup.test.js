import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { exportBackup, importBackup } from '../src/crypto/IdentityBackup.js';
import { KeyManager } from '../src/crypto/KeyManager.js';

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

  it('carries a real identity across a machine, signing key included', () => {
    // /backup is what makes two devices reachable at all today, and it is the
    // path multi-device is replacing (docs/design/multi-device.md). Until it
    // is, the Ed25519 identity has to survive it — a backup that quietly
    // dropped it would hand the new machine a different identity with no sign
    // that anything was lost.
    const km = new KeyManager();
    const envelope = exportBackup({ identity: km.serialize(), trust: {} }, 'a strong pass');
    const restored = KeyManager.deserialize(importBackup(envelope, 'a strong pass').identity);

    assert.equal(restored.identityPublicKeyB64, km.identityPublicKeyB64);
    assert.equal(restored.identityFingerprint, km.identityFingerprint);
    assert.equal(restored.deviceId, km.deviceId);

    km.destroy();
    restored.destroy();
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
