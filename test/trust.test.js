import { test } from 'node:test';
import assert from 'node:assert/strict';
import { trustBadge, TrustBadge } from '../src/shared/trust.js';
import { tipAt, TIPS } from '../src/shared/tips.js';

test('trustBadge — no record is a brand-new peer (no badge)', () => {
  assert.equal(trustBadge(null, 'keyA'), TrustBadge.NONE);
  assert.equal(trustBadge(undefined, 'keyA'), TrustBadge.NONE);
});

test('trustBadge — unknown current key never shows a false mismatch', () => {
  assert.equal(trustBadge({ publicKey: 'keyA', verified: true }, undefined), TrustBadge.NONE);
  assert.equal(trustBadge({ publicKey: 'keyA', verified: true }, ''), TrustBadge.NONE);
});

test('trustBadge — TOFU-trusted but unverified shows no badge', () => {
  const record = { publicKey: 'keyA', verified: false };
  assert.equal(trustBadge(record, 'keyA'), TrustBadge.NONE);
});

test('trustBadge — verified with matching key is VERIFIED', () => {
  const record = { publicKey: 'keyA', verified: true };
  assert.equal(trustBadge(record, 'keyA'), TrustBadge.VERIFIED);
});

test('trustBadge — a changed key is a MISMATCH, even if previously verified', () => {
  assert.equal(trustBadge({ publicKey: 'keyA', verified: false }, 'keyB'), TrustBadge.MISMATCH);
  assert.equal(trustBadge({ publicKey: 'keyA', verified: true }, 'keyB'), TrustBadge.MISMATCH);
});

test('tipAt — wraps around and never throws on any integer index', () => {
  assert.equal(tipAt(0), TIPS[0]);
  assert.equal(tipAt(TIPS.length), TIPS[0]);
  assert.equal(tipAt(-1), TIPS[TIPS.length - 1]);
  assert.equal(tipAt(TIPS.length + 2), TIPS[2]);
});

test('tipAt — empty tip list returns an empty string', () => {
  assert.equal(tipAt(3, []), '');
});
