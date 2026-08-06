import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { ByteBudget, ConnectionRateLimiter } from '../src/server/ConnectionGuard.js';
import { MAX_PAYLOAD_SIZE } from '../src/shared/constants.js';

// Every test drives its own clock. Sleeping for real would make the suite take
// minutes to prove a thirty-minute ban.
const MINUTE = 60_000;
const HOUR = 3_600_000;

test('allows connections up to the rate, then refuses', () => {
  const limiter = new ConnectionRateLimiter(10);
  const now = 1_000_000;

  for (let i = 0; i < 10; i++) {
    assert.equal(limiter.check('1.2.3.4', now).allowed, true, `attempt ${i + 1}`);
  }
  assert.equal(limiter.check('1.2.3.4', now).allowed, false);
});

test('one source going too fast does not affect another', () => {
  const limiter = new ConnectionRateLimiter(2);
  const now = 1_000_000;

  limiter.check('1.1.1.1', now);
  limiter.check('1.1.1.1', now);
  assert.equal(limiter.check('1.1.1.1', now).allowed, false);
  assert.equal(limiter.check('2.2.2.2', now).allowed, true);
});

test('refills continuously rather than resetting on a boundary', () => {
  // A fixed window lets a caller spend the whole allowance at the very end of
  // one window and again at the start of the next — twice the intended rate for
  // an instant, which is exactly the moment an attacker aims for.
  const limiter = new ConnectionRateLimiter(60); // one per second
  let now = 1_000_000;

  for (let i = 0; i < 60; i++) {
    limiter.check('1.2.3.4', now);
  }
  assert.equal(limiter.check('1.2.3.4', now).allowed, false);

  // Half a minute later only half the allowance is back, not all of it.
  now += 30_000;
  const limiter2 = new ConnectionRateLimiter(60);
  let start = 1_000_000;
  for (let i = 0; i < 60; i++) {
    limiter2.check('9.9.9.9', start);
  }
  start += 30_000;
  let allowed = 0;
  for (let i = 0; i < 60; i++) {
    if (limiter2.check('9.9.9.9', start).allowed) allowed++;
  }
  assert.ok(allowed >= 25 && allowed <= 32, `expected about 30, got ${allowed}`);
});

test('the ban escalates and then holds at the longest step', () => {
  const limiter = new ConnectionRateLimiter(1);
  let now = 1_000_000;
  const steps = [];

  for (let strike = 0; strike < 4; strike++) {
    limiter.check('1.2.3.4', now); // spends the single token
    const refused = limiter.check('1.2.3.4', now);
    steps.push(refused.retryAfterMs);
    now += refused.retryAfterMs + 1;
  }

  assert.deepEqual(steps, [MINUTE, 5 * MINUTE, 30 * MINUTE, 30 * MINUTE]);
});

test('a refusal says how long to wait', () => {
  // A client that is told nothing retries immediately and extends its own ban;
  // one that is told can back off. The number has to be real, not a constant.
  const limiter = new ConnectionRateLimiter(1);
  const now = 1_000_000;

  limiter.check('1.2.3.4', now);
  limiter.check('1.2.3.4', now); // first strike: banned for a minute

  const midway = limiter.check('1.2.3.4', now + 20_000);
  assert.equal(midway.allowed, false);
  assert.equal(midway.retryAfterMs, 40_000);
});

test('behaving for an hour clears the record', () => {
  // Otherwise a NAT gateway collects strikes over months and ends up
  // permanently at the longest ban because of one bad afternoon.
  const limiter = new ConnectionRateLimiter(1);
  let now = 1_000_000;

  limiter.check('1.2.3.4', now);
  const first = limiter.check('1.2.3.4', now);
  assert.equal(first.retryAfterMs, MINUTE);

  now += HOUR + MINUTE;
  limiter.check('1.2.3.4', now);
  const afterQuiet = limiter.check('1.2.3.4', now);
  assert.equal(afterQuiet.retryAfterMs, MINUTE, 'should be back at the first step');
});

test('prune forgets quiet sources but keeps the banned ones', () => {
  // The map is keyed by anything that ever connected. Without pruning it is a
  // slow leak an attacker can drive on purpose by cycling source addresses.
  const limiter = new ConnectionRateLimiter(10);
  let now = 1_000_000;

  limiter.check('1.1.1.1', now); // quiet, will refill
  for (let i = 0; i < 11; i++) {
    limiter.check('2.2.2.2', now); // struck, banned
  }
  assert.equal(limiter.size, 2);

  now += 2 * MINUTE; // the bucket refills, the ban has expired
  limiter.prune(now);
  assert.equal(limiter.size, 1, 'the quiet one is forgotten, the struck one is not');

  now += HOUR + MINUTE;
  limiter.prune(now);
  assert.equal(limiter.size, 0, 'and forgotten too once its strike has decayed');
});

test('a byte budget throttles a sustained stream but allows a burst', () => {
  // Both numbers have to clear MAX_PAYLOAD_SIZE, or the burst is clamped up to
  // it and the budget under test is not the one configured.
  const perSecond = 100_000;
  const burst = 200_000;
  const budget = new ByteBudget(perSecond, burst, 0);

  assert.equal(budget.allow(burst, 0), true, 'the whole burst at once');
  assert.equal(budget.allow(1, 0), false, 'and nothing more until it refills');

  assert.equal(budget.allow(perSecond, 1000), true, 'a second later, a second of budget');
  assert.equal(budget.allow(1, 1000), false);
});

test('a full-size frame always fits, however small the burst is configured', () => {
  // A burst below one frame could never be paid for, so every message would be
  // refused and the connection would wedge shut instead of being throttled —
  // a misconfiguration turning into a total outage for that client.
  const budget = new ByteBudget(1000, 1, 0);
  assert.equal(budget.allow(MAX_PAYLOAD_SIZE, 0), true);
});
