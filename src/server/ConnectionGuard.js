// Limits on how *fast* a source may connect, and how much it may push once in.
//
// The existing caps bound how many sockets exist at once and how many messages
// a session sends per second. Neither bounds the two things that actually cost
// the relay:
//
//   1. Handshake churn. Connect, run the hybrid handshake, disconnect, repeat.
//      Every attempt makes the relay do X25519 and ML-KEM-768 work while the
//      attacker does almost nothing, and a concurrency cap never trips because
//      the sockets are never held open.
//
//   2. Bandwidth. The message limit counts messages, and messages are padded
//      into buckets up to 32 KiB, so a session at the limit is a multi-megabit
//      stream. The resource that runs out is bytes, not messages.
//
// Both are token buckets, and both take their clock as an argument so the tests
// can move time without sleeping.
import { MAX_PAYLOAD_SIZE } from '../shared/constants.js';

/** A bucket that refills continuously rather than resetting on a boundary. */
class TokenBucket {
  #capacity;
  #perMs;
  #tokens;
  #last;

  constructor(capacity, perMs, now) {
    this.#capacity = capacity;
    this.#perMs = perMs;
    this.#tokens = capacity;
    this.#last = now;
  }

  /** Spend `cost` if it is there. Returns false without spending if it is not. */
  take(cost, now) {
    // A fixed window lets a caller spend the whole allowance at the end of one
    // window and again at the start of the next, which is twice the intended
    // rate for a moment. Refilling by elapsed time has no such seam.
    this.#tokens = Math.min(this.#capacity, this.#tokens + (now - this.#last) * this.#perMs);
    this.#last = now;

    if (this.#tokens < cost) {
      return false;
    }
    this.#tokens -= cost;
    return true;
  }

  /** True once the bucket is full again — the entry is then worth forgetting. */
  idle(now) {
    return this.#tokens + (now - this.#last) * this.#perMs >= this.#capacity;
  }
}

/**
 * How long a source is refused after going too fast, by how many times it has
 * done so. Short enough that a burst of reconnects after a relay restart is
 * forgiven; long enough that a script grinding away gets nothing done.
 */
const BAN_STEPS_MS = [60_000, 300_000, 1_800_000];

/** Strikes are forgotten after this long behaving, so the ban never ratchets up forever. */
const STRIKE_DECAY_MS = 3_600_000;

export class ConnectionRateLimiter {
  #perMinute;
  #entries = new Map();

  constructor(perMinute) {
    this.#perMinute = perMinute;
  }

  /**
   * @returns {{allowed: boolean, retryAfterMs: number}} — `retryAfterMs` is
   *   worth telling the client, since a well-behaved one can then back off
   *   instead of hammering and extending its own ban.
   */
  check(ip, now = Date.now()) {
    let entry = this.#entries.get(ip);
    if (!entry) {
      entry = {
        bucket: new TokenBucket(this.#perMinute, this.#perMinute / 60_000, now),
        strikes: 0,
        bannedUntil: 0,
        lastStrike: 0,
      };
      this.#entries.set(ip, entry);
    }

    if (now < entry.bannedUntil) {
      return { allowed: false, retryAfterMs: entry.bannedUntil - now };
    }

    if (entry.bucket.take(1, now)) {
      return { allowed: true, retryAfterMs: 0 };
    }

    // Behaving for an hour wipes the record. Without this a long-lived NAT
    // gateway would collect strikes over months and end up permanently at the
    // longest ban for one bad afternoon.
    if (entry.lastStrike && now - entry.lastStrike > STRIKE_DECAY_MS) {
      entry.strikes = 0;
    }

    const step = BAN_STEPS_MS[Math.min(entry.strikes, BAN_STEPS_MS.length - 1)];
    entry.strikes += 1;
    entry.lastStrike = now;
    entry.bannedUntil = now + step;

    return { allowed: false, retryAfterMs: step };
  }

  /**
   * Forget sources that have gone quiet. Called on a timer — without it the map
   * is a slow memory leak keyed by anything that ever connected, which is a
   * denial of service of its own.
   */
  prune(now = Date.now()) {
    for (const [ip, entry] of this.#entries) {
      if (now < entry.bannedUntil) {
        continue;
      }
      if (entry.lastStrike && now - entry.lastStrike <= STRIKE_DECAY_MS) {
        continue;
      }
      if (entry.bucket.idle(now)) {
        this.#entries.delete(ip);
      }
    }
  }

  get size() {
    return this.#entries.size;
  }
}

/**
 * A sustained bytes-per-second budget for one connection, with a burst
 * allowance so a legitimate file transfer is not mistaken for an attack.
 *
 * One of these lives on the socket, so it disappears with it and there is
 * nothing to prune.
 */
export class ByteBudget {
  #bucket;

  constructor(perSecond, burst, now = Date.now()) {
    // A burst smaller than one frame could never be paid for, so the connection
    // would wedge shut instead of being throttled. Callers get the larger of
    // the two rather than a silently broken socket.
    this.#bucket = new TokenBucket(Math.max(burst, MAX_PAYLOAD_SIZE), perSecond / 1000, now);
  }

  /** @returns {boolean} false when the connection has outrun its budget. */
  allow(bytes, now = Date.now()) {
    return this.#bucket.take(bytes, now);
  }
}
