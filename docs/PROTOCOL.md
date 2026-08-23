# CipherMesh wire protocol

Version **2**. This document describes the protocol as implemented, so that an
audit has something to check against and a second implementation has something
to build against.

Where behaviour is pinned by test vectors, that is said explicitly — the vectors
in `test/vectors/` are the normative artefact and this document describes them,
not the other way round. Where the relay is *forbidden* to do something, the
reason is given, because those are the places where an innocent-looking change
silently removes a guarantee.

Reference implementation: `src/protocol/` (framing and validation),
`src/crypto/` (everything else), `src/server/WebSocketServer.js` (relay).

---

## 1. Transport

WebSocket. TLS is expected in deployment and self-signed by default — **no
security property in this document depends on the TLS certificate.** End-to-end
trust comes from TOFU pinning and SAS verification of identity keys.

| Property | Value | Source |
|---|---|---|
| Default port | 3600 | `SERVER_PORT` |
| Max frame | 65 536 bytes | `MAX_PAYLOAD_SIZE` |
| Heartbeat | 30 s | `HEARTBEAT_INTERVAL_MS` |
| Idle session timeout | 300 s | `SESSION_TIMEOUT_MS` |
| Must JOIN within | 15 s | `JOIN_TIMEOUT_MS` |

Every frame is a single JSON object, UTF-8. Binary frames are not used; all
byte strings are base64 in JSON fields.

### Rate and resource limits

A conforming relay may refuse service; a conforming client must cope with being
refused. These are the reference values.

| Limit | Value | Scope |
|---|---|---|
| Messages per second | 60 | per connection, **all** message types |
| Routed messages per second | 30 | per session, `encrypted_message` and `group_message` |
| Bytes per second | 1 MiB sustained, 4 MiB burst | per connection, charged on inbound frames before parsing |
| Connections | 500 total, 20 per IP | per relay |
| New connections | 60 per minute per IP | escalating bans on repeat |

The byte budget is charged **before** parsing: the bytes have already been
received by then, so refusing to spend further effort on them is the only saving
left. A connection that exhausts it is closed with code 1008.

---

## 2. Framing

Every message carries three fields:

```json
{ "type": "<string>", "version": 2, "timestamp": 1739800000000 }
```

`version` is checked for **exact equality** and a mismatch is fatal
(`src/protocol/validators.js`). It is not a negotiation mechanism — see §3.

`timestamp` is the sender's clock in milliseconds. The relay does not trust it
and does not correct it; it exists for the recipient.

Unknown fields are ignored. This is load-bearing: it is what lets an optional
field like `pqPublicKey`, `caps`, `room` or `identityKey` be added without a
version bump, and
what lets an older relay pass through a message it does not fully understand.

---

## 3. Capability negotiation

`version` can only say "same" or "refuse to talk". It cannot express *newer, but
still willing to speak the old way*, which is what a protocol change rolled
through a public hub needs. Capabilities carry that.

1. A client lists what it can do in `JOIN` (`caps: ["sk1"]`).
2. The relay validates the list, stores it, and hands it on **verbatim** in
   `join_ack` (per peer) and `peer_joined`. It never acts on a capability.
3. The relay advertises **its own** abilities in `join_ack.serverCaps`. No client
   can promise these on the relay's behalf.
4. A feature turns on only when **every member of the room** advertises it *and*
   the relay does — for features that need the relay to play along. A capability
   whose feature rides a channel the relay already carries has no relay half and
   is decided per peer; `dl1` is the first of those.

Absent or empty means an older participant, which is a fallback, not an error.

**Bounds** (the list arrives from a public hub, so it is attacker-controlled):
at most 16 entries, each 1–24 characters matching `^[a-z0-9][a-z0-9_-]*$`. A
malformed list gets the whole `JOIN` **rejected**, not filtered — the relay hands
this list to other clients, and forwarding the good half of a bad list would make
a peer look capable of something it never claimed.

| Capability | Advertised by | Meaning |
|---|---|---|
| `sk1` | client | I can *receive* a group message (§7) |
| `sk1` | relay | I can fan a room-addressed message out |
| `dl1` | client | I can read a signed device list handed to me over the pairwise channel (§7) |

Neither means "I send group messages". Receive and fan-out ship a release ahead
of send, because the switch is *every member agrees*: if reading and writing
arrived together, the switch would only ever be true in rooms where everybody
upgraded at the same moment.

`dl1` has no relay half. A device list travels on the pairwise sealed channel
the relay already carries, so there is nothing for the relay to agree to and
nothing it can withhold beyond the frame itself.

**What a hostile relay gains by editing these lists:** stripping a capability
forces the room onto the older path, which is the status quo and reveals nothing
new. Adding one a peer never claimed makes senders encrypt in a form that peer
cannot read — denial of service, immediately visible, never a way to read
plaintext. The all-members rule is what keeps the damage on that side.

---

## 4. Session lifecycle

```
client                          relay                        other clients
  │  join(nickname, publicKey,    │                                  │
  │       pqPublicKey?, caps?,    │                                  │
  │       identityKey?)           │                                  │
  ├──────────────────────────────▶│                                  │
  │                               │  peer_joined(peer)               │
  │  join_ack(sessionId, peers,   ├─────────────────────────────────▶│
  │           room, serverCaps?)  │                                  │
  │◀──────────────────────────────┤                                  │
```

A session is identified by a server-assigned `sessionId` (UUID). It is **not** an
identity: identity is the Curve25519 public key, and nicknames are neither unique
across time nor authenticated. A client that reconnects gets a new `sessionId`
and must be recognised by key.

### `join` (client → relay)

| Field | Type | Required | Notes |
|---|---|---|---|
| `nickname` | string | yes | 1–20 chars, `^[a-zA-Z0-9_-]+$`, control characters stripped, case-insensitively unique among live sessions — **except for another device of the same identity**, see below |
| `publicKey` | base64(32) | yes | Curve25519 identity key |
| `pqPublicKey` | base64(1184) | no | ML-KEM-768 encapsulation key; absent = classical-only peer |
| `caps` | string[] | no | §3; omitted when empty |
| `identityKey` | base64(32) | no | Ed25519 signing key for multi-device; absent = a client from before it existed |
| `deviceList` | object | no | The signed list from §7, sent to claim a nickname another of your own devices already holds |

### `join_ack` (relay → client)

| Field | Type | Notes |
|---|---|---|
| `sessionId` | string | UUID for this connection |
| `peers` | object[] | `{ sessionId, nickname, publicKey, pqPublicKey?, caps?, identityKey? }` |
| `room` | string | always `general` on join |
| `queuedCount` | number | omitted when 0 |
| `serverCaps` | string[] | omitted when empty |
| `roomOwner` | string | nickname, when the room has one |
| `motd` | string | operator notice, when configured |

**`identityKey` is relayed verbatim and the relay cannot verify it.** It forwards
whatever the JOIN carried, so a hostile relay can substitute one: presence in a
`join_ack` is not evidence of anything. What makes an identity key trustworthy is
a device list signed by it and checked by the client — never the relay repeating
it. It is also not what a ban keys on; that stays the Curve25519 `publicKey`.

**One nickname may be held by several devices of one identity.** A second
session is admitted under a name already in use only if its JOIN carries a
`deviceList` that

1. is signed by the identity the existing sessions under that name are using,
2. names *this* JOIN's own `publicKey`, and
3. would not take the name past the eight-device limit.

No challenge is issued and none is needed. Replaying a list somebody else
published buys a seat in a room under a name whose messages you cannot read,
because you do not hold the box secret the list names — and peers do their own
checking, so they learn nothing from the relay having allowed it. The relay is
doing admission control on a nickname here, not attesting to an identity.

The name is released when the **last** of its sessions leaves, not the first.

### `peer_joined` / `peer_left` (relay → clients)

`peer_joined` carries the same peer object as `join_ack.peers`. Both carry an
optional `room`; absent means the session's only room. Old clients ignore it.

`peer_left` is emitted for **every** way a session stops being in a room:
leaving, switching, disconnecting, being kicked, being banned. That completeness
is load-bearing rather than tidy. A sender chain (§7) is shared with exactly the
members of a room, so the set of departures a client hears about is the set of
moments it can rotate that chain at — and a departure it never hears about is a
chain that outlives the membership it was drawn for.

### `ping` / `pong`

Either direction, no payload beyond the framing.

---

## 5. Identity and key agreement

Each client holds a long-term Curve25519 keypair. Peers learn each other's public
key from `join_ack` / `peer_joined` — that is, **from the relay**, which is why
TOFU pinning and out-of-band SAS verification exist: the relay is trusted to
route, never to attest.

`key_update` (client → relay) announces a new public key; the relay forwards it
as `peer_key_updated` to every session sharing a room. The previous key is kept
briefly on both sides so messages in flight still open.

**What a SAS compares is moving.** Historically the code is BLAKE2b over the two
Curve25519 keys — the device keys — which means it is invalidated by a key
rotation and says nothing about a person with more than one device. Once both
sides advertise `dl1` **and** each holds the other's device list, the code is
computed over the two Ed25519 identity keys instead, under a separate domain
tag. The switch is symmetric: both sides reach that state together, so a pair
never sees two different codes. Against a peer without `dl1` both sides compute
the device code, exactly as before. `/verify` names which of the two it is
showing.

**Existing verifications are carried across, never re-asked.** A record verified
against a device key gains its identity when a signed device list arrives that
**names that same device key**, over the pairwise channel only the holder of
that key could have written to. The identity is then vouched for by precisely
what the user compared digits over. A list that does not name the key it arrived
under binds nothing — it is not an attack, a rotation can race a distribution,
but it proves nothing. A *second, different* identity for a record that already
has one is never accepted silently; on a verified record it is reported in the
same voice as a verified-key mismatch, and nothing is changed.

**Another device is not a key that changed.** A peer's second device arrives
under the same nickname with a box key the record has never seen — which is
exactly the shape of a man-in-the-middle, and is reported as one. The alarm is
never suppressed in advance: claiming the right `identityKey` in a JOIN proves
nothing, since the relay forwards that field unchecked. It is *answered*, once a
device list signed by the identity bound to that record names the key. From then
on the key is recognised silently, and the record keeps the verified key as its
primary — a device is added beside it, never over it. A list may only add
devices to the record its own identity is bound to.

**Hybrid post-quantum.** When both sides advertised `pqPublicKey`, the ratchet
root is mixed once at initialisation:

```
root' = BLAKE2b(root ‖ ML-KEM-768.shared ‖ "ciphermesh/pq-hybrid-v3")
```

The KEM ciphertext rides in `payload.pqCiphertext` until the peer replies. The
mix happens exactly once, before any chain key is derived, so the two sides
cannot desynchronise: an envelope without the expected mix simply fails its MAC.

---

## 6. Pairwise messages

`encrypted_message` is the unicast path. On the wire it is **only**:

```json
{
  "type": "encrypted_message",
  "version": 2,
  "timestamp": 1739800001000,
  "to": "<recipient sessionId>",
  "sealed": "base64(crypto_box_seal({ from, payload }, recipientPublicKey))"
}
```

There is deliberately **no `from`**. The sender's identity and the whole
already-encrypted payload are sealed to the recipient's public key with an
anonymous box. A relay implementation must:

- route on `to` alone
- strip any `from` a client sets, so it can never be forwarded
- never log, store or stamp the sender

The inner `payload`, once unsealed, is one of:

**Ratcheted** (the normal case) — Double Ratchet, per-message keys:

```json
{ "ephemeralPublicKey": "b64", "counter": 0, "previousCounter": 0,
  "ciphertext": "b64", "nonce": "b64(24)", "pqCiphertext": "b64?" }
```

**Static** (no ratchet yet) — `crypto_box_easy` under the two identity keys:

```json
{ "ciphertext": "b64", "nonce": "b64(24)" }
```

**Deniable** — symmetric `crypto_secretbox` under a derived shared key, marked
`"deniable": true`. No signature, so neither party can prove authorship to a
third party.

Decrypted content is JSON. `text` and `sentAt` are the common case; an `action`
field selects everything else (typing, receipts, reactions, edits, file
transfer, topic, sender-key distribution — §7).

### Replay and ordering

Static and deniable messages carry a structured nonce: 8 bytes big-endian
timestamp, then a per-peer counter. Recipients reject a nonce outside the
freshness window or with a non-increasing counter. Ratcheted messages are
protected by the ratchet's own counters, which also bound how many skipped
message keys may be cached.

---

## 7. Group messages (sender keys)

The unicast path costs one encryption and one envelope **per recipient**. Sender
keys make it one of each for the whole room.

### When this path is used

Three conditions, all required, each failing for a different reason:

| Condition | Fails when |
| --- | --- |
| every member of the room advertises `sk1` | one peer is on an older build |
| `join_ack.serverCaps` contains `sk1` | the hub is older |
| the message is not deniable | see below |

Any one false and the per-peer path runs unchanged. A sender **must** re-check
per message rather than caching the answer: a single arrival can take a room off
this path, and encrypting for a member who cannot decrypt is silent.

**Deniable messages never take this path.** Deniability comes from a symmetric
key both sides could have derived, so neither can prove the other wrote it. A
group packet is signed by exactly one sender — sending a deniable message on it
would publish precisely what deniability is for hiding.

**Cover traffic takes whichever path real messages take.** A decoy that travelled
the per-peer path while the room was sending group messages would be
distinguishable from the thing it exists to imitate.

### The chain

Each member owns a symmetric ratchet chain per room:

```
messageKey  = BLAKE2b-256(key = chainKey, message = 0x01)
chainKey'   = BLAKE2b-256(key = chainKey, message = 0x02)
```

Note the argument order: the one-byte domain tag is the *message*, the chain key
is the *key*. Counters start at 0 and increment by one per message. Receivers may
cache up to 1000 skipped keys for out-of-order delivery; a larger gap is refused,
as is a counter already consumed.

**Pinned in `test/vectors/sender-key.json`.** Those values are frozen: a change
that forces them to move is a protocol version bump, not a regeneration.

### Distribution

A member hands their chain to another member over the **pairwise sealed
channel**, never on the group path — the envelope is what authenticates who sent
it. The payload is:

```json
{ "action": "sk_dist", "room": "general",
  "dist": { "chainKey": "b64(32)", "counter": 7,
            "keyId": "b64(16)", "signPk": "b64(32)" },
  "sentAt": 1739800000000 }
```

A distribution serialises the chain at its **current** counter. A member who
receives one mid-conversation therefore cannot read anything sent before it —
that is forward secrecy, not a defect, and it is why the backlog question in §8
answers itself.

**Who speaks first is not a free choice.** A client drops a ciphertext from a
session it holds no public key for, and a joiner learns the room from its
`join_ack` *before* the room learns of the joiner from `peer_joined`. A newcomer
that distributed on arrival would be talking to peers who cannot yet hear it, and
would have no way to discover that.

So distribution is **answered, never announced**:

1. the peers who already know the newcomer distribute to it (on `peer_joined`);
2. the newcomer replies with its own to anyone whose distribution it receives and
   who does not already hold its current chain.

Receiving a distribution proves the sender holds your public key, so the reply
cannot race. A sender must also distribute to any room member it has not yet
given its current chain to before sending — the exchange above covers every
ordinary path, and that check covers the rest.

### The message

```json
{
  "type": "group_message",
  "version": 2,
  "timestamp": 1739800001000,
  "room": "general",
  "keyId": "b64(16)",
  "counter": 7,
  "ciphertext": "b64",
  "nonce": "b64(24)",
  "signature": "b64(64)"
}
```

No `to`, because there is no single recipient. **No `from`**, because the relay
must not become the one place on this wire that asserts who is speaking.

`keyId` names the sender's *chain*, not the sender. Members resolve it through
the distribution they were handed; to the relay it is a random string, and it
already knows which socket sent the frame, so it learns nothing from it. It is
redrawn on every rotation and dropped when a member is removed.

`signature` is Ed25519 over the length-prefixed concatenation of
`keyId`, `counter`, `ciphertext`, `nonce`, under the `signPk` from the sender's
distribution. **It is not optional.** A sender chain is symmetric — every member
holds the key that decrypts a given sender, and can therefore also produce
ciphertext on it — so without a signature "Alice said this" would only ever mean
"somebody in this room said this".

A recipient must **verify before touching the chain**. `messageKeyFor()` mutates
state, so an unauthenticated packet carrying a large counter would otherwise be a
way to make the receiver derive and cache a thousand message keys.

A member whose distribution carried no usable `signPk` is registered but
unverifiable: nothing they send is accepted. Fail closed.

### Rotation

`rotate()` replaces the chain, the `keyId` and the signing key together. It must
follow **every** membership change, and the caller must redistribute afterwards —
nothing signals a failure to do so, and the room simply stops being able to read
the rotator.

Concretely, a departure rotates: leaving, switching rooms, disconnecting, being
kicked, being banned. All five reach the client as `peer_left` (§4), which is why
that message has to be emitted for all five and not only the voluntary ones — a
departure the client never hears about is a chain that is never rotated, and a
removed member whose copy still opens everything that follows.

**An arrival does not rotate.** A distribution carries the chain's current
counter, so a newcomer is handed what opens the next message and nothing before
it. Rotating on arrival would cost a redistribution to the whole room and buy
nothing.

A full room switch drops every chain rather than rotating one: the client is no
longer in the rooms those chains were drawn for, and carrying one across would
use a chain drawn for one membership against another.

### What the relay does

Validates the shape, checks the sender **is a member of `room`**, spends the same
per-sender budget as the unicast path, and fans the message out to every other
member. It cannot verify the signature — it holds no signing keys — and does not
try.

Room membership is not a formality: without it one connection could inject into
every room on the hub at once, which the unicast path cannot do because it needs
a `sessionId` it could only have been told.

### Device lists

A second thing travels the pairwise channel, gated on `dl1` and read by nothing
yet: a **device list**, the set of box keys that belong to one identity, signed
by the Ed25519 `identityKey` from §4. Multi-device is designed in
`docs/design/multi-device.md`; this is the plumbing landing ahead of it. Today
every list names exactly one device, because nothing can add a second.

```json
{ "action": "device_list",
  "list": {
    "identityPk": "b64(32)",
    "counter": 1,
    "devices": [ { "deviceId": "hex(32)", "boxPk": "b64(32)",
                   "label": "", "createdAt": 1739800000000 } ],
    "signature": "b64(64)"
  },
  "sentAt": 1739800000000 }
```

The signature covers a domain tag, the identity key, the counter, **the number
of devices**, and every field of each one, each length-prefixed by its byte
count. There is no ML-KEM key in a descriptor: a list is a set of claims about
identity, a KEM key is transport material already advertised per session in
JOIN, and carrying it cost 1584 bytes of base64 per device. The count is in there so a device cannot be dropped off the end
unnoticed; byte prefixes are there so a multi-byte label cannot shift a field
boundary.

**`counter` only ever goes up, and the reader enforces it.** A list at the same
counter is not newer and is refused, so an edit cannot slip in sideways; a lower
one is a replay. Without this a relay that kept an old copy could play it back,
and once revocation exists that is how a removed device would be put back. The
sender's counter is persisted and moves whenever its descriptor does — a
box-key rotation changes `boxPk`, so it changes the list.

**What authenticates a list is the channel, not the seal.** `crypto_box_seal` is
anonymous: anyone can seal a blob to you claiming any sender. The payload
underneath is `crypto_box` to your key from the peer's, so it only opens if the
sender holds that peer's box secret. That is what makes the list theirs. The
`identityKey` the relay repeated in `join_ack` is a *hint* — it decides whether
handing a list over is worth the round trip, and nothing more. A relay that
tampers with it can stop the exchange happening; it cannot put words in a peer's
mouth, because it cannot produce the payload.

**Answered, not announced**, for the same reason as *Distribution* above: a
newcomer learns the room before the room learns of the newcomer, so a client
that announced itself on arrival would be talking to peers holding no key for
it. Peers who already know you speak first; you answer, and you mark them as
holding your list **before** sending, because on a synchronous transport their
answer can arrive before the send call returns.

**Revocation is a shorter list with a higher counter**, and the list is only
half of it. A removed device still holds every member's sender chain, and a
chain ratchets forward — dropping it from the list stops the relay delivering to
it and does not stop it reading. So every reader that sees devices disappear
from a list **rotates its own chain for the room**, exactly as it does when a
member leaves.

On the receiving side a list is a *replacement*, not an addition: the keys it
names are the keys that are that person, and one that is no longer named stops
being honoured — including the key the trust record was originally built on. A
revoked primary that stayed trusted would make revocation decorative.

Two limits, stated rather than discovered. A revoked device that is already
connected keeps its session until it disconnects; it is refused on its next
JOIN, because the list no longer names its key. And it keeps whatever it
received before the rotation, which is what forward secrecy means and not a
defect.

**Provisioning happens off the wire.** A second device is added by the user
carrying two short strings between the two machines, not by anything the relay
sees:

```
ciphermesh-device://request/<base64url>   { deviceId, boxPk, label }
ciphermesh-device://grant/<base64url>     { identityPk, list }
```

The identity secret never moves. A secondary holds only the public half and the
list it was granted, so it can prove which identity it belongs to and can
publish that list, but it cannot sign a new one — adding and revoking stay with
the device that holds the secret. Neither string is confidential; a grant is
caught if substituted, because it only applies when the list names the exact
device that asked, by both id and key.

A secondary therefore does not rotate its box key: it could not re-sign the list
that names it, and the result would be a device nothing vouches for.

**The label is empty**, and stays empty until there is a second device to tell
apart. A hostname is the obvious filler and exactly the kind of thing that does
not go on this wire.

---

## 8. Offline delivery

`encrypted_message` addressed to a session that has just left is queued by
nickname + public key, for at most 1 hour, 100 per peer and 1000 in total. On
rejoin with the **same public key** the queue is delivered with `to` rewritten to
the new session. A different key drops the queue: it could not be opened anyway.

**`group_message` is never queued.** Not policy — arithmetic. A sender key handed
over on someone's return serialises the chain at its current counter, so the
backlog is unreadable to them whatever the relay does with it. Queueing would
store ciphertext on the relay that provably nobody can open: all of the storage
and the liability, none of the delivery.

---

## 9. Rooms

Room names are 1–30 characters, `^[a-zA-Z0-9_-]+$`, lowercased by the relay.
`general` always exists and can never be private.

| Message | Direction | Effect |
|---|---|---|
| `change_room` | c → r | Leave every room, enter one |
| `room_changed` | r → c | Confirmed, with `peers` and `private` |
| `join_room` | c → r | Enter an **additional** room |
| `room_joined` | r → c | Confirmed |
| `leave_room` / `room_left` | c ↔ r | Leave one; the last is refused |
| `list_rooms` / `room_list` | c ↔ r | `[{ name, memberCount, private }]` |

`change_room` and `join_room` carry an optional `roomAuthPk` — an Ed25519
verifier key, present only when **creating** a private room.

### Private rooms, without the relay learning the password

```
client                                   relay
  │  join_room(room)                        │
  ├────────────────────────────────────────▶│
  │  room_challenge(room, nonce)            │
  │◀────────────────────────────────────────┤
  │  room_auth(room, nonce, signature)      │
  ├────────────────────────────────────────▶│   verify against stored roomAuthPk
  │  room_joined(room, peers, private)      │
  │◀────────────────────────────────────────┤
```

The password is stretched with Argon2id into a room key and an Ed25519 keypair.
Only the **verifier public key** is ever sent, at creation. Joining proves
knowledge by signing `(room, nonce, sessionId)` — binding to the session, so a
signature observed from another member cannot be replayed.

Challenges expire in 60 s. Five failures in 60 s on one connection stops further
attempts.

Room content gets a second encryption layer under the room key, **inside** the
transport layer: a message in a private room is room-encrypted and then sent
through the pairwise or group path as usual.

---

## 10. Moderation

`kick_peer`, `mute_peer` (with `durationMs`), `ban_peer` — owner only, with an
optional `room`. Reasons are truncated to 200 characters. The relay broadcasts
`peer_kicked` / `peer_muted` to the room. A muted session is refused for
`encrypted_message` and `group_message` alike.

A kick or a ban emits **`peer_kicked` and then `peer_left`**, in that order, for
the same session. `peer_kicked` carries an optional `sessionId` alongside the
nickname; a client that has it can match the two and report one event once,
while one that does not — every client before this — simply sees an ordinary
departure and a kick notice. Nicknames could not do this job: `/nick` reassigns
them, so unwinding a peer by name drops the wrong session as soon as two people
have ever shared one.

These are relay-enforced conveniences and nothing more. A relay that ignores them
breaks no cryptographic guarantee, which is why blocking is *also* implemented
client-side, where it cannot be overruled.

---

## 11. Errors

```json
{ "type": "error", "version": 2, "timestamp": 0, "code": "...", "message": "..." }
```

| Code | Meaning |
|---|---|
| `NICKNAME_TAKEN` | Another live session holds it |
| `INVALID_MESSAGE` | Failed validation, or sent before `join` |
| `PEER_NOT_FOUND` | No such session, and nothing queued |
| `RATE_LIMITED` | Over a per-second budget |
| `PAYLOAD_TOO_LARGE` | Frame above `MAX_PAYLOAD_SIZE` |
| `ROOM_AUTH_FAILED` | Bad signature, expired challenge, too many attempts |
| `ROOM_EXISTS` | Cannot create; already there |

Error messages are for humans and must never quote the content that caused them.

---

## 12. Padding

Every plaintext is padded before encryption to the smallest bucket that fits:

```
128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768
```

Format: 2 bytes big-endian length, the plaintext, then random filler. A payload
larger than the biggest bucket is sent unpadded — file chunks are the reason —
and a single plaintext may not exceed 65 535 bytes.

This is what makes "the relay sees a bucketed size" true rather than a slogan.
It is asserted in `test/guarantees.test.js`.

---

## 13. What the relay learns

Stated plainly, because a specification that only lists the protections is
misleading.

**It sees:** who is connected and under what nickname and public key; which
rooms exist and who is in them; for a unicast message, the recipient; for a group
message, the room; the timing and bucketed size of everything; and, since a
connection is authenticated and persistent, which socket sent any given frame.

**It does not see:** any plaintext; any private-room password; the sender named
*in* a message; the contents of a sender-key distribution.

**Sealed sender is a guarantee against an honest-but-curious relay**, the same
one Signal makes. A malicious relay can correlate the sending socket to a
session — inherent to a persistent authenticated connection, and not something
this protocol claims to solve. P2P mode removes the relay entirely.

**Sender keys give confidentiality and per-member authenticity within a room, not
anonymity within it.** Members can tell each other apart, which is the point.

---

## 14. Conformance

An implementation claiming compatibility should:

- reproduce `test/vectors/sender-key.json` exactly
- send no `from` on any frame, ever
- reject a `join` whose `caps` is malformed rather than filtering it
- verify a group signature before advancing the chain
- treat an absent capability as an older peer, never as an error
- never queue a `group_message`

`test/guarantees.test.js` asserts the properties above that can be observed from
outside a single implementation.
