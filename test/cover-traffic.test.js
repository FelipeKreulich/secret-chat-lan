import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nextCoverDelay, coverPayload, isCover } from '../src/shared/coverTraffic.js';
import { COVER_MIN_MS, COVER_MAX_MS } from '../src/shared/constants.js';

test('nextCoverDelay stays within [min, max]', () => {
  assert.equal(nextCoverDelay(() => 0), COVER_MIN_MS);
  assert.equal(nextCoverDelay(() => 1), COVER_MAX_MS);
  assert.equal(nextCoverDelay(() => 0.5), Math.round((COVER_MIN_MS + COVER_MAX_MS) / 2));
});

test('nextCoverDelay honours custom bounds', () => {
  assert.equal(nextCoverDelay(() => 0, 1000, 2000), 1000);
  assert.equal(nextCoverDelay(() => 1, 1000, 2000), 2000);
});

test('coverPayload is a valid decoy message', () => {
  const obj = JSON.parse(coverPayload(1234, () => 0));
  assert.equal(obj.action, 'cover');
  assert.equal(obj.sentAt, 1234);
  assert.equal(obj.x, ''); // no filler when rand()=0
});

test('coverPayload filler length varies with the RNG (spreads padding buckets)', () => {
  const small = JSON.parse(coverPayload(0, () => 0)).x.length;
  const big = JSON.parse(coverPayload(0, () => 0.99)).x.length;
  assert.ok(big > small, 'higher rand → longer filler');
  assert.ok(big > 100, 'filler is substantial at the top of the range');
});

test('isCover only matches decoys', () => {
  assert.equal(isCover({ action: 'cover' }), true);
  assert.equal(isCover({ action: 'clear' }), false);
  assert.equal(isCover({ text: 'hi' }), false);
  assert.equal(isCover(null), false);
  assert.equal(isCover(undefined), false);
});
