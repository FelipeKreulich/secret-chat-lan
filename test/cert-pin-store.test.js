import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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

describe('CertPinStore — CA-validated hosts (public relays)', () => {
  it('remembers a CA-valid host and demands strict TLS from then on', () => {
    const { dir, store } = tempStore();
    try {
      assert.equal(store.requiresStrictTLS('hub.example.com:443'), false);

      store.markCAValidated('hub.example.com:443');
      assert.equal(store.requiresStrictTLS('hub.example.com:443'), true);
      assert.equal(store.requiresStrictTLS('lan.local:3600'), false, 'per host');

      // Survives a restart — the downgrade protection must be durable.
      const reopened = new CertPinStore(dir);
      assert.equal(reopened.requiresStrictTLS('hub.example.com:443'), true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps pinning working alongside the CA flag', () => {
    const { dir, store } = tempStore();
    try {
      store.check('hub.example.com:443', 'AA:BB');
      store.markCAValidated('hub.example.com:443');

      const reopened = new CertPinStore(dir);
      assert.equal(reopened.getPinned('hub.example.com:443'), 'AA:BB');
      assert.equal(reopened.check('hub.example.com:443', 'AA:BB'), PinResult.MATCH);
      assert.equal(reopened.check('hub.example.com:443', 'ZZ:ZZ'), PinResult.MISMATCH);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('reads legacy v1 files (bare fingerprint strings)', () => {
    const { dir, store } = tempStore();
    try {
      store.check('old.host:3600', 'AA:BB');
      // Rewrite in the old format to simulate an upgrade in place.
      const path = join(dir, '.ciphermesh', 'pinned-certs.json');
      writeFileSync(path, JSON.stringify({ 'old.host:3600': 'AA:BB' }));

      const reopened = new CertPinStore(dir);
      assert.equal(reopened.getPinned('old.host:3600'), 'AA:BB');
      assert.equal(reopened.requiresStrictTLS('old.host:3600'), false, 'v1 had no CA flag');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
