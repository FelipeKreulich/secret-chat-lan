import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CertPinStore, PinResult } from '../src/crypto/CertPinStore.js';

function tempStore() {
  const dir = mkdtempSync(join(tmpdir(), 'ciphermesh-pin-'));
  return { dir, store: new CertPinStore(dir) };
}

describe('CertPinStore', () => {
  it('pins on first use, matches after, and detects a changed fingerprint', () => {
    const { dir, store } = tempStore();
    try {
      assert.equal(store.check('host:3600', 'AA:BB:CC'), PinResult.PINNED);
      assert.equal(store.check('host:3600', 'AA:BB:CC'), PinResult.MATCH);
      assert.equal(store.check('host:3600', 'DD:EE:FF'), PinResult.MISMATCH);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('persists the pin across instances (same base dir)', () => {
    const { dir, store } = tempStore();
    try {
      store.check('host:3600', 'AA:BB:CC');
      const store2 = new CertPinStore(dir);
      assert.equal(store2.check('host:3600', 'AA:BB:CC'), PinResult.MATCH);
      assert.equal(store2.getPinned('host:3600'), 'AA:BB:CC');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('treats a null fingerprint (plain ws://) as a match (nothing to pin)', () => {
    const { dir, store } = tempStore();
    try {
      assert.equal(store.check('host:3600', null), PinResult.MATCH);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('repin accepts a new fingerprint after a legitimate rotation', () => {
    const { dir, store } = tempStore();
    try {
      store.check('host:3600', 'AA:BB:CC');
      store.repin('host:3600', 'NEW:FP');
      assert.equal(store.check('host:3600', 'NEW:FP'), PinResult.MATCH);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
