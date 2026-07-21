// Pure trust-verdict helpers, decoupled from the TrustStore so they can be
// unit-tested and shared by both controllers. The store records peers as
// { fingerprint, publicKey, firstSeen, lastSeen, verified }.

export const TrustBadge = {
  VERIFIED: 'verified', // SAS-confirmed identity
  MISMATCH: 'mismatch', // stored key != current key (possible MITM / rotation)
  NONE: 'none', // unknown peer, or TOFU-trusted but identity unconfirmed
};

// Decide which badge to show next to a peer, from their stored record (or null)
// and the public key they are presenting right now.
//   - no record            -> NONE  (brand-new peer)
//   - key changed          -> MISMATCH
//   - verified & key match -> VERIFIED
//   - else                 -> NONE  (TOFU-trusted, not verified)
export function trustBadge(record, currentPublicKey) {
  // No record, or we don't know the key they're presenting right now (e.g. a
  // store-and-forward message from a peer who isn't currently connected) — we
  // can't make a claim, so show nothing rather than a false mismatch.
  if (!record || !currentPublicKey) {
    return TrustBadge.NONE;
  }
  if (record.publicKey !== currentPublicKey) {
    return TrustBadge.MISMATCH;
  }
  if (record.verified) {
    return TrustBadge.VERIFIED;
  }
  return TrustBadge.NONE;
}
