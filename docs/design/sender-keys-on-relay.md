# Sender keys on the relay

Status: **design, not implemented.** Written 2026-08-07, straight after
measuring the problem, so the next session starts from the constraints rather
than rediscovering them.

## The problem, measured

`ChatController.#broadcastPayload` loops over every peer in the room and seals
one envelope each:

```js
for (const [peerId] of this.#peers) {
  const peerPublicKey = this.#handshake.getPeerPublicKey(peerId);
  ...
  this.#sealAndSend(peerPublicKey, msg);
}
```

One typed line in a room of N people is **N encryptions and N envelopes on the
wire**. Cost grows linearly with room size, on the sender's CPU and on the
sender's uplink — the two places least able to absorb it.

2.10.0 made this a ceiling rather than a slope. `MAX_BYTES_PER_SECOND` bounds a
connection at 1 MiB/s by default, and messages are padded into buckets of up to
32 KiB. A 32 KiB bucket sent to fifty people is 1.6 MiB for one line: the sender
is throttled, or disconnected, for saying one thing.

P2P does not have this problem. `P2PChatController` already uses
`GroupSession` from `src/crypto/SenderKey.js`, encrypts once, and distributes
the sender key per member. The code is written and tested; it is only the relay
path that never adopted it.

## What changes

1. Each member holds a **sender chain** for the room and distributes its
   `distribution()` to every other member — sealed per member, once, rather
   than per message.
2. A message is encrypted **once** with the sender's chain and handed to the
   relay with a room destination rather than a peer destination.
3. The relay fans the single ciphertext out to the room's members. It still
   cannot read anything, and it still never learns the sender under sealed
   sender.
4. On any membership change, the leaver's departure triggers `rotate()` and a
   redistribution — exactly what `P2PChatController` does today at lines 320
   and 487, with the comment already written there.

Cost per message goes from N encryptions and N envelopes to **one and one**.
Distribution cost is N, but paid on join and on membership change rather than
on every line.

## The hard part: two versions in one room

This is a protocol change. A 2.11 client encrypting once to a group and a 2.10
client expecting an envelope addressed to it **cannot read each other**. The hub
is public and people upgrade whenever they upgrade, so "everyone updates at
once" is not available.

Rolling this out badly breaks live conversations for strangers. Options, in the
order they should be considered:

- **Negotiate, do not assume.** The JOIN acknowledgement already carries each
  peer's public key; it can carry a capability list too. A sender uses group
  encryption only when *every* member of the room advertises it, and falls back
  to the current per-peer loop otherwise. Costs a room-wide check per send,
  which is cheap and already computed.
- **Both paths coexist for at least one minor.** Deleting the fan-out in the
  same release that adds sender keys leaves no way back if the new path has a
  bug that only shows at scale — which is exactly the kind of bug it would have.
- **The relay needs a room-addressed message type** that does not exist yet.
  It must not weaken sealed sender: today the relay learns the recipient and not
  the sender, and a room-addressed envelope must not accidentally invert that.

## What to be careful about

- **Rotation must be wired to every departure**, not just voluntary leaves.
  `/kick`, `/mute`, `/ban` and a dropped connection all change membership. The
  P2P side rotates on `peer_left`; the relay side has more ways to lose a member.
- **`SenderKey.rotate()` is a caller responsibility** — its own comment says
  so. The distribution has to follow it or the room silently stops being able to
  read the rotator.
- **Private rooms add a second layer** (`encryptRoomPayload` with the
  password-derived key). Group encryption goes *inside* that, not instead of it.
- **The offline queue** stores envelopes addressed to a peer. A room-addressed
  message needs an answer for someone who was offline when it was sent, and
  "they get the sender key on rejoin but not the backlog" is a decision to make
  deliberately rather than discover.

  **Decided (2026-08-10): room-addressed messages are not queued.** The reason is
  not policy but arithmetic — a sender key handed over on someone's return
  serialises the chain at its *current* counter, so the backlog is unreadable to
  them whatever the relay does with it. Queueing would hold ciphertext nobody can
  open: all of the storage and the liability, none of the delivery. The unicast
  queue survives because an envelope addressed to a peer is still openable when
  they return with the same key. Pinned in `test/group-receive.test.js`.

- **Sender keys are symmetric, so any member can forge another.** Not in the
  original list, and it does not matter much in a P2P mesh where membership is
  small and deliberate. It matters on a public hub. **Closed (2026-08-10)** with
  an Ed25519 key per sender chain, distributed alongside the chain and verified
  before the ratchet is touched. Doing it before the send path existed meant it
  cost a field on a wire nobody was using yet.

## Suggested order

1. Test vectors for `SenderKey` distribution and rotation, so both sides of the
   change are pinned before either moves.
2. Capability advertisement in JOIN, with the fallback path left untouched.
3. Group send/receive behind that capability, both paths live.
4. Rotation wired to every membership change, with a test per route in.
5. Only then, consider retiring the per-peer loop — a release later, at least.

## Why it is worth it

It is the one change that is simultaneously a feature, a fix and an
improvement: it removes a scaling limit the project just made visible to itself,
it reuses code that already exists and is already tested, and it is the
difference between the hub holding a room of five and a room of fifty.
