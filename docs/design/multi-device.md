# Multi-device

Status: **design, not implemented.** Written 2026-08-23, from the code as it
stands, so the next session starts from the constraints rather than
rediscovering them. Item 4 of #481, and the last one left on it.

This follows the shape of [sender-keys-on-relay.md](sender-keys-on-relay.md),
which was written the same way and turned out to be worth it. Where that
document got something wrong — step 5 — the mistake is left visible.

## The problem, measured

Multi-device is not a missing feature. It is a **reachable configuration that
produces the wrong thing**, and the client has a command that walks people into
it.

`/backup` writes `{ identity: keyManager.serialize(), trust: ... }` encrypted
with the session passphrase — and `serialize()` includes the secret key. On
another machine, the startup prompt _"Restore identity from a backup? (path or
Enter)"_ reads it straight back in. Both machines now hold the same X25519
secret key. What follows is what the code actually does, not what it ought to:

- **They cannot both use the name.** `WebSocketServer` rejects a JOIN whose
  nickname is taken (`isNicknameTaken`, line 296). The second device gets
  `NICKNAME_TAKEN`. One person is in the room as two people under two names.
- **Nothing notices they are the same identity.** `addSession` has no
  uniqueness check on `publicKey`, so the relay is perfectly happy to hold two
  sessions with one key, and treats them as unrelated peers. So does every
  other client.
- **Each message reaches exactly one of them.** `MessageRouter.route` delivers
  to `msg.to`, a session id. Both devices _could_ open the envelope — same
  secret key — but only one is sent it. Which one depends on which session the
  sender's peer map happened to address. Read a conversation on your laptop,
  and half of it is on your phone.
- **Verification teaches the wrong lesson.** `TrustStore` is
  `Map<lowerNickname, record>`, so a peer verifies each device separately, as
  two different people. And `computeSAS` hashes the two X25519 keys, so both
  comparisons produce **the same digits** — the peer is asked to verify one
  fingerprint under two names and told that is normal.
- **Losing one device loses the identity.** One secret key, copied. There is no
  way to revoke a device: `KeyManager.rotate()` replaces the identity
  everywhere at once, for everybody, and the peers see a key change they cannot
  distinguish from an impersonation attempt.
- **One thing is accidentally right.** Bans key on `session.publicKey`
  (`WebSocketServer` lines 480, 573, 754, 1039), so banning one device does
  correctly ban them all.

So the honest summary is not "we do not have multi-device". It is: **the
project ships a way to get two devices, and the result is a doubled presence, a
halved conversation, a fingerprint that means less than the user is told, and a
key that cannot be revoked.** Everything below is about replacing that with
something defensible.

## What multi-device has to mean here

The shape is not novel and there is no reason to invent one. **Per-device keys
under one identity:**

- A long-term **identity key** (Ed25519) that signs and is never used to
  encrypt a message.
- A **device key** (X25519, plus the ML-KEM half) per device, exactly what
  `KeyManager` already produces — but no longer the identity.
- A **device list**: the set of device keys currently valid for an identity,
  signed by the identity key, with a monotonic counter so an old list cannot be
  replayed over a newer one.
- The thing users verify becomes the **identity key**, not a device key.

That last point is the one that makes the rest usable. If verification stays on
the device key, then adding a device invalidates every verification you have,
and a person with three devices is three SAS comparisons — nine, pairwise, in a
room of two such people. Moving verification up one level means you verify a
person once and their devices inherit it, which is the only version anyone will
actually do.

## What changes

1. `KeyManager` grows an **identity keypair** alongside the device keypair, and
   `fingerprint` is computed from the identity key.
2. A device publishes a **descriptor** — its X25519 key, its ML-KEM key, a
   label, a creation time — signed by the identity key.
3. A **device list** (identity key + descriptors + counter, signed) is
   distributed to peers over the pairwise channel, the same way a sender key is
   and for the same reason: it is authenticated by opening the envelope it
   arrived in, never asserted by the relay.
4. A pairwise send goes to **every live device** of the recipient. A group send
   still goes out once; only distribution multiplies.
5. Your own other devices are recipients too, which is what makes a message you
   sent from your phone appear on your laptop.
6. **Revocation** is a new signed list with the device removed and the counter
   raised. Peers drop the key on receipt.

## The hard parts

### The fingerprint changes meaning

Every existing verified record was verified against a device key. Moving the
fingerprint to the identity key makes all of them stale at once, and a stale
verification is exactly what `TrustResult.VERIFIED_MISMATCH` is built to scream
about — so a careless rollout tells every user, simultaneously, that everyone
they trust has been replaced.

This is the single most dangerous part of the change. It cannot ride a
capability check the way sender keys did, because it is not about what the
_other_ side can do; it is about what a local file means.

### The nickname is the identity, as far as the relay is concerned

Nicknames are unique and rooms are keyed by session. Two options, both with a
cost:

- **The relay learns about identities.** N sessions may share a nickname if
  they prove the same identity key. This is the honest model and it is a
  protocol change on the relay, plus a proof-of-possession on JOIN so the name
  cannot be taken by asserting somebody else's identity.
- **Devices get distinct names.** No relay change, and it leaks how many
  devices you have to everyone in the room — metadata this project otherwise
  works hard to withhold.

The first is more work and is the right one. It should not be decided by which
is easier to build.

### Fan-out multiplies, and #481 just decided to keep the loop

Item 3 of #481 concluded the per-peer loop stays — deniability and sender-key
distribution both need it permanently. With D devices per peer that loop
becomes **N × D**, and sender-key _distribution_ becomes N × D too, even though
the group send itself stays at one.

That is the same scaling wall sender keys were built to remove, re-entered
through a different door. It has to be sized before anything ships:
`/room` already reports the send path and the cost, so the measurement has
somewhere to live.

### Sealed sender leaks the device count

An envelope is sealed to one recipient key. Per-device keys mean one envelope
per device, and the relay can count them. Today the relay learns the recipient
and not the sender; after this it learns _how many devices the recipient has_,
which is a stable fingerprint of a person across sessions. Padding the fan-out
to a fixed bucket is the obvious answer and it is not free.

### Rotation on membership change now fires on device churn

`#rotateGroupFor` runs when a member leaves, because a departed member holds a
chain that ratchets forward. With devices, closing a laptop is a departure.
Rotating the room every time somebody's second device sleeps is expensive and
makes a real guarantee look like noise.

The rule probably becomes: rotate when the **last** device of a member leaves,
or when a device is **revoked**. That is a different predicate from the one in
the code today and it needs its own test per route in, exactly as the departure
routes did in #482.

### Where the identity key lives

If it is on every device, losing any device loses the identity. If it is on one
primary, that device is a single point of failure for ever adding another. The
Signal answer is a primary that provisions, and it is probably right here too —
but this project has no second channel to provision over except the pairwise
one it is trying to bootstrap, so the provisioning step needs a real design of
its own.

**Decided (2026-08-23): the identity secret never moves.** A secondary device
generates its own box keypair and receives only the identity's *public* half
plus a device list signed by it. A stolen phone is then a stolen phone rather
than a stolen identity, and a secondary cannot add or revoke devices — only the
device holding the secret can.

The provisioning channel is the user, and it is two hops because neither side
can sign for the other: the new device has to say what its key is before the
identity can sign for it, and has to be told what identity it belongs to
afterwards.

```
B: /device request        → ciphermesh-device://request/…   (~150 characters)
A: /device add <request>  → ciphermesh-device://grant/…     (~740 characters)
B: /device accept <grant>
```

Neither string is secret — a request is a public key, a grant is a signed
statement that was going to be broadcast to every peer anyway — so interception
achieves nothing. Substitution is caught: a grant only applies if the list names
the exact device that asked, by both id and key.

Two costs, both accepted rather than hidden:

- **Losing the primary means no more adding or revoking.** The standard
  trade-off, and the safer side of it.
- **A secondary cannot rotate its box key**, because it cannot re-sign the list
  that names it. `KeyManager.rotate()` is a no-op there. Fixing that needs a
  channel for a secondary to ask the primary to re-sign, which does not exist
  yet.

**Also decided: no ML-KEM key in a device descriptor.** A list is a set of
claims about identity; a KEM key is transport material, already advertised per
session in JOIN, and a device could change it without changing who it is.
Carrying it cost 1 584 bytes of base64 per device — the difference between a
grant that fits in a QR code and one that does not. Changed while the format
was still unreleased, which is the only time it is free.

### Message history for a device that was not there

A device added today cannot read what the room said yesterday: a sender key
handed over serialises the chain at its _current_ counter. That is already
decided for the offline queue in
[sender-keys-on-relay.md](sender-keys-on-relay.md) and the arithmetic is the
same here. "A new device starts from now" is a defensible answer. It has to be
said out loud, in the UI, at the moment somebody adds one — not discovered.

## What to be careful about

- **The mlock ceiling.** `sodium_malloc` pages are locked and Linux caps how
  much a process may lock. #481 already recorded a SIGABRT from exactly this,
  surfacing in an unrelated ratchet call because it was the next allocation to
  fail. Per-device keys multiply guarded allocations by D, per peer, per room.
  This is the failure this change is most likely to hit, and it is invisible on
  macOS, where the limit is unlimited. Instrument `sodium_malloc` by call site
  before, not after.
- **`DoubleRatchet.js` has the same zero-without-free pattern at 19 sites.**
  Noted and deliberately not fixed in #481 because 1,164 allocations is nowhere
  near a limit. Multiply by D and re-check that judgement.
- **P2P is a different problem.** `P2PChatController` keys peers by _nickname_
  and has no session ids and no relay. Multi-device in the mesh is not the same
  design, and pretending one document covers both is how the relay path ended
  up with assumptions from the mesh baked into it. Out of scope for v1, and say
  so in the UI.
- **The offline queue keys on nickname + publicKey.** Both halves change
  meaning. Re-read `OfflineQueue.dequeue` against the new model rather than
  assuming it still lines up.
- **A device list is a replay target.** The counter is not optional, and
  "highest counter wins" has to be enforced on receipt, not on send.

## Suggested order

The sender-keys rollout worked because each step was landable on its own and
the risky one arrived after its safety net. Same shape:

*Steps 1 to 5 are done; the notes below are as written, with what shipped
recorded against each.*

1. **`DeviceIdentity`: an identity keypair, a signed device descriptor, and
   frozen vectors** — a crypto module with no callers. Nothing on the wire,
   nothing in the UI, no behaviour change. **Shipped (#493).**
2. **Carry the identity key in `KeyManager`, persisted and backed up,
   advertised in JOIN and used by nobody.** This is the trick that worked for
   the Ed25519 sender signature: land the field while the wire is still free.
3. **A signed device list, distributed pairwise, behind a capability** — still
   one device per identity. The plumbing is exercised before it carries weight.
4. **Move verification to the identity key**, with the device fingerprint still
   shown, a migration for existing records, and a loud, deliberate story for
   `VERIFIED_MISMATCH`.
5. **A second device, receive-only.** Provisioning, and the relay change that
   lets two sessions share a nickname.
6. **Sending from a second device, and own-device fan-out.** The point at which
   a conversation stops being split.
7. **Revocation**, with a test per route out — the way #482 did for departures.
8. **Only then**, the mesh, if at all.

Steps 1 and 2 are safe enough to do before the rest is agreed. Step 4 is the
one to slow down on.

## Why it is worth it

It is the largest functional gap in the project, and unlike the others it is
one the product actively invites people into: `/backup` is in the README's
command table and the restore prompt is the second thing the client asks at
startup. Together they produce the configuration described at the top. The
choice is not between multi-device and no multi-device. It is between a
designed one and the accidental one that exists now.
