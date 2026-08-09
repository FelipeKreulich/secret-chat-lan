import { MAX_CAPABILITIES, MAX_CAPABILITY_LENGTH, OWN_CAPABILITIES } from '../shared/constants.js';

// ── Capability negotiation ─────────────────────────────────────
//
// `PROTOCOL_VERSION` is checked for exact equality, so it can only say "same" or
// "refuse to talk". It cannot express a client that is newer but still willing
// to speak the old way, which is precisely what rolling a protocol change
// through a public hub needs. Capabilities carry that: advertised in JOIN,
// relayed verbatim with the peer list, and read here.
//
// The rule for turning a feature on is deliberately the strict one — *every*
// member of the room must advertise it. One peer on an older build is enough to
// keep the whole room on the old path, which is the outcome that keeps a
// half-upgraded room readable.

/**
 * Defensive read of a capability list that arrived over the wire.
 *
 * The relay validates what it accepts, but a client should not depend on the
 * relay having done so — this list is used to decide how to encrypt.
 *
 * @returns {string[]} the valid entries, or an empty list
 */
export function normalizeCaps(caps) {
  if (!Array.isArray(caps)) {
    return [];
  }
  const clean = [];
  for (const cap of caps.slice(0, MAX_CAPABILITIES)) {
    if (typeof cap !== 'string' || cap.length === 0 || cap.length > MAX_CAPABILITY_LENGTH) {
      continue;
    }
    if (!/^[a-z0-9][a-z0-9_-]*$/.test(cap) || clean.includes(cap)) {
      continue;
    }
    clean.push(cap);
  }
  return clean;
}

/** Does a single peer record advertise `cap`? */
export function peerSupports(peer, cap) {
  return normalizeCaps(peer?.caps).includes(cap);
}

/**
 * Can the whole room use `cap`?
 *
 * True only when this client advertises it and so does every peer. An empty
 * room is vacuously true — there is nobody who could fail to understand.
 *
 * A hostile relay can edit these lists, so it is worth being explicit about what
 * that buys it. Stripping capabilities forces the room back onto the per-peer
 * path, which is the status quo and reveals nothing new. Adding a capability a
 * peer never claimed makes senders encrypt in a form that peer cannot read —
 * denial of service, visible immediately as a room that stopped working, and
 * never a way to read plaintext. The strict-consensus rule is what keeps the
 * damage on that side of the line.
 *
 * @param {Iterable<{caps?: string[]}>} peers - the room's peers, excluding self
 * @param {string} cap
 * @param {string[]} [own] - what this build advertises
 */
export function roomSupports(peers, cap, own = OWN_CAPABILITIES) {
  if (!normalizeCaps(own).includes(cap)) {
    return false;
  }
  for (const peer of peers) {
    if (!peerSupports(peer, cap)) {
      return false;
    }
  }
  return true;
}
