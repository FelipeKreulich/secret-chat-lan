import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrustStore } from '../src/crypto/TrustStore.js';
import { AuditLog } from '../src/shared/AuditLog.js';
import { panicWipe } from '../src/shared/panic.js';

describe('panic / duress wipe', () => {
  let tempDir;
  let cwd;
  let home;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'ciphermesh-panic-'));
    cwd = process.cwd();
    home = process.env.HOME;
    process.chdir(tempDir);
    process.env.HOME = tempDir;
  });

  afterEach(() => {
    process.chdir(cwd);
    process.env.HOME = home;
    rmSync(tempDir, { recursive: true, force: true });
  });

  const dummyKey = Buffer.alloc(32, 7).toString('base64');

  it('TrustStore.wipe securely removes the trust file', () => {
    const trust = new TrustStore(tempDir);
    trust.recordPeer('bob', dummyKey);
    const path = join(tempDir, '.ciphermesh', 'trusted-peers.json');
    assert.ok(existsSync(path), 'trust file created');
    trust.wipe();
    assert.equal(existsSync(path), false, 'trust file wiped');
  });

  it('AuditLog.wipe removes the audit log', () => {
    const audit = new AuditLog();
    audit.log('TEST_EVENT', { x: 1 });
    const path = join(tempDir, '.ciphermesh', 'audit.log');
    assert.ok(existsSync(path), 'audit file created');
    audit.wipe();
    assert.equal(existsSync(path), false, 'audit file wiped');
  });

  it('panicWipe erases every store and reports what it wiped', () => {
    const trust = new TrustStore(tempDir);
    trust.recordPeer('bob', dummyKey);
    const audit = new AuditLog();
    audit.log('X');

    const wiped = panicWipe({ trustStore: trust, auditLog: audit });

    assert.ok(wiped.includes('confianca'));
    assert.ok(wiped.includes('auditoria'));
    assert.equal(existsSync(join(tempDir, '.ciphermesh', 'trusted-peers.json')), false);
    assert.equal(existsSync(join(tempDir, '.ciphermesh', 'audit.log')), false);
  });

  it('panicWipe never throws, even with nothing to wipe', () => {
    assert.doesNotThrow(() => panicWipe({}));
    assert.doesNotThrow(() => panicWipe());
  });
});
