# Changelog

Notable changes per release. Older versions are reconstructed from the git
history — the commit bodies and pull requests remain the fuller record.

## 2.12.0

Sender keys now send. 2.11.0 shipped the half that reads a group message; this
is the half that writes one, and a line in a room of fifty costs one encryption
instead of fifty.

The switch is unchanged and still strict — every member of the room and the hub
itself must say they can handle it. On a public hub the per-peer path remains
the common case, and it is untouched.

### Added

- **Group sending on the relay.** 2.11.0 shipped the half that reads one; this
  is the half that writes one. A line in a room of fifty cost fifty encryptions
  and fifty envelopes — against the 1 MiB/s byte budget, a padded message to
  fifty people throttled the sender for saying one thing. It now costs one of
  each.

  The switch is still the strict one: every member of the room advertises
  `sk1`, **and** the hub does, **and** the message is not deniable. Any one
  false and the per-peer path runs exactly as before, which on a public hub is
  the common case rather than the exception. Nothing was removed.

  Deniable messages stay pairwise permanently. Deniability comes from a key both
  sides could have derived; a group packet is signed by one sender, which is the
  opposite claim.

- **Sender keys rotate on every membership change.** Leaving, switching rooms,
  disconnecting, being kicked, being banned. A chain ratchets forward, so the
  copy a member holds opens every message after it: removing someone stopped the
  relay delivering to them and did not stop them reading. Rotation is what
  closes that, and `test/guarantees.test.js` now asserts it from outside the
  code that implements it.

### Fixed

- **A kick or a ban is announced as a departure, not only as a notification.**
  Both moved the target out of the room and told the room `peer_kicked`, which
  carries a nickname — and a nickname is not something a client can unwind a
  member by, since `/nick` reassigns them. Every remaining client kept the
  removed peer in its roster indefinitely. They now emit `peer_left` like every
  other way out of a room, which is also what makes rotation reachable for the
  two cases where it matters most.

- **Peer capabilities survive a room switch.** `room_changed` and `room_joined`
  carried them and the client dropped them, so after switching rooms every peer
  looked incapable and the room silently never turned the group path on. No
  error, no failure — just an optimisation that quietly never applied.

- **Sender-key memory is released, not merely zeroed.** `sodium_malloc` pages are
  `mlock`'d, and an operating system caps how much a process may lock at once.
  Zeroing a spent key left its pages locked until the garbage collector happened
  to run the buffer's finaliser, so a long session derived keys faster than it
  released them. The ceiling is generous on macOS and small on Linux, where a
  busy client would eventually have hit an allocation failure that aborts the
  process rather than returning an error.

## 2.11.0

Groundwork for sender keys on the relay. **Nothing sends a group message yet** —
this release is the half that has to be in the field first, and the reason is in
"Added" below.

### Added

- **Capability negotiation in `JOIN`.** `PROTOCOL_VERSION` is checked for exact
  equality, so it can only say "same" or "refuse to talk". It cannot express
  _newer, but still willing to speak the old way_, which is the only thing that
  makes a protocol change survivable on a public hub where people upgrade
  whenever they upgrade.

  A client now lists what it can do in its `JOIN`; the relay validates the list,
  stores it, and hands it on verbatim with the peer list, without ever acting on
  it. A feature turns on only when **every member of the room** advertises it, so
  one peer on an older build holds the whole room on the old path — which is the
  outcome that keeps a half-upgraded room readable.

  The relay advertises its own abilities separately, in `join_ack.serverCaps`. No
  client can promise those on the relay's behalf, and some features need the
  relay to play along, so a capable room sitting on an older hub is still not a
  room that can switch paths.

- **Receiving group messages, and the relay fan-out that carries them.** The
  relay path seals one envelope per peer, so a line in a room of fifty costs
  fifty encryptions and fifty envelopes — against a 1 MiB/s byte budget, a padded
  message to fifty people throttles the sender for saying one thing. Sender keys
  make it one of each.

  Reading ships a release ahead of writing on purpose. The switch is _every
  member agrees_: if both arrived together it would only ever be true in rooms
  where everybody upgraded in the same moment.

  A room-addressed message carries no `to`, because there is no single recipient,
  and no `from`, because the relay must not become the one place on this wire
  that asserts who is speaking. A packet names its _chain_ instead — an opaque
  label members resolve through the sender key they were handed over the pairwise
  channel, and which the relay cannot invert.

- **Per-sender signatures on group messages.** A sender chain is symmetric: every
  member holds the key that decrypts a given sender, and can therefore also
  produce ciphertext on it. Without something asymmetric on top, "Alice said
  this" only ever meant "somebody in this room said this" — tolerable in a small
  P2P mesh, not on a public hub where `general` has no owner and no admission
  control.

  Each sender now holds an Ed25519 keypair for the life of its chain, rotated
  with it. Recipients verify before touching the ratchet, so an unauthenticated
  packet carrying a large counter cannot make them derive and cache a thousand
  message keys.

- **`docs/PROTOCOL.md`.** The wire format field by field, with the limits, the
  failure modes, and the reason attached wherever the relay is forbidden to do
  something. It also states what the relay _does_ learn, because a specification
  that lists only the protections is misleading.

### Changed

- **Room-addressed messages are never queued for absent members**, unlike
  unicast. Not policy — arithmetic: a sender key handed over on someone's return
  serialises the chain at its current counter, so the backlog is unreadable to
  them whatever the relay does with it. Queueing would store ciphertext on the
  relay that provably nobody can open.

### Internal

- **Frozen test vectors for sender keys.** The previous tests round-tripped a
  sender against a receiver built from that same sender — a mirror, not a
  reference, which agrees with itself however the KDF is defined. Swapping the
  two domain tags left the old suite fully green while making two clients unable
  to read each other. The vectors pin the absolute values, and moving them is a
  protocol version bump rather than a regeneration.

- **A guarantees test that lives apart from the features it checks.** In August a
  squash reverted the entire plugin-approval control and nothing failed, because
  that pull request's tests were reverted in the same commit. `test/guarantees.test.js`
  asserts what the project promises — through the surfaces a user goes through,
  and deliberately not next to any feature — so deleting a feature now leaves its
  proof behind, failing. Verified by mutation rather than assumed.

- **Branch protection and CODEOWNERS.** `dev` and `master` now require CI, and
  refuse force pushes and deletions.

## 2.10.0

### Added

- **\`--check\` for operators.** The deploy guide already explained every
  footgun here, which is the problem: a document is read once, by whoever set
  the machine up, while the misconfiguration lasts as long as the machine does.
  The worst of them — \`TRUST_PROXY\` left off behind a reverse proxy — is
  invisible from outside, because everything works and the per-IP cap, the rate
  limit and the banlist simply apply to the proxy and protect nobody.

  \`ciphermesh-server --check\` validates and exits without opening a socket, so
  it is safe against a live host, and exits non-zero on an error so a deploy
  script can gate on it. The same findings print at every startup, because a
  warning you have to ask for is a warning nobody sees.

- **Connection-rate limiting.** The relay capped how many sockets one address
  could hold, and how many messages a session could send, but nothing capped how
  fast an address could _open_ connections. Connect, run the hybrid handshake,
  disconnect, repeat: the concurrency cap never trips because the sockets are
  never held, and every attempt costs the relay an X25519 and an ML-KEM-768
  operation while costing the client almost nothing. That asymmetry was the one
  real denial-of-service route into a public hub.

  An address that exceeds `CONNECTION_RATE_PER_MINUTE` (60 by default, still
  LAN-friendly) is refused for a minute, then five, then thirty. An hour of
  behaving clears the record, so a shared NAT gateway cannot accumulate strikes
  forever, and the refusal says how long to wait so a well-behaved client backs
  off instead of extending its own ban.

- **A byte budget per connection** (`MAX_BYTES_PER_SECOND`,
  `MAX_BYTES_BURST`). The message limit counts messages, and messages are padded
  into buckets of up to 32 KiB, so a session sitting at the limit is a
  multi-megabit stream. Bytes are the resource that runs out. The burst
  allowance keeps a legitimate file transfer from looking like an attack.

  Both are continuously refilling token buckets rather than fixed windows: a
  fixed window lets a caller spend its whole allowance at the end of one window
  and again at the start of the next, which is twice the intended rate at
  exactly the moment an attacker aims for.

## 2.9.0

### Added

- `/block` now works in **P2P** as well. It matters more there than on a relay:
  P2P has no room owners at all, so `/kick`, `/mute` and `/ban` have nobody to
  act on anyone's behalf. Refusing to listen is the only protection there is, and
  the refusal message for the moderation commands now says so instead of leaving
  the user with nothing.

## 2.8.0

### Added

- **`/block`, `/unblock`, `/blocklist`.** Stop seeing someone, just for you.
  Entirely local: nothing is sent, the relay never learns, and the other person
  is not told. That is why everyone gets it — moderating a room acts on
  everybody and so has to belong to the owner, while refusing to listen acts
  only on yourself and needs no authority at all.

  It is also the only protection that works in `general`, which has no owner and
  therefore no moderation. Blocks live in the trust store, so they survive a
  restart, are stored `0600`, and are wiped by `/panic` along with everything
  else.

### Fixed

- **A room ban was undone by `/nick`.** Bans were stored against the nickname,
  and anyone can pick a new one whenever they like: get banned, rename, walk
  back in. Room owners are the only moderation in the system — the operator
  cannot read content and deliberately holds no in-chat authority — so their one
  tool was defeated by a single word. Bans are now bound to the public key
  (#438).

  The correct pattern was already in the codebase: the offline queue looks up by
  nickname but verifies the public key before delivering. The ban list was the
  one place a nickname was treated as an identity.

## 2.7.2

### Fixed

- **The standalone binaries now run on machines other than the one that built
  them.** `sodium-native` resolves its prebuilt addon at runtime, which bun
  cannot follow, so the addon was never embedded — the binary kept an absolute
  path back to the build checkout and died with `Cannot find addon` anywhere
  else. Every binary published before this, including the relay binaries dating
  back to 2.3.0, was affected (#427).

  The verification was the deeper problem: it ran the binary _on the runner that
  built it_, where the addon resolved through `node_modules`, so every check
  passed while every download was broken. CI now hides the build tree before
  running anything, and the cross-compiled binary is executed under Rosetta
  rather than merely asserting its architecture.

  **If you downloaded a binary from an earlier release, replace it.**

## 2.7.1

### Fixed

- The banner no longer reads a font from disk. `figlet.textSync` loads
  `fonts/ANSI Shadow.flf` at startup — fine under Node, fatal inside a compiled
  binary, where the file does not exist and the process died before printing
  anything. The word never changes, so the art is now the constant it always
  was, pinned against figlet's own output by a test. figlet moved to a
  devDependency and the 1.11.4 hold is gone (#414).

## 2.7.0

### Added

- **Public hub at [ciphermesh.de](https://ciphermesh.de).** An always-on relay
  anyone can connect to, so using CipherMesh no longer means already knowing
  someone who runs one. `general` is the default room. Governed by
  [TERMS.md](TERMS.md).
- **The website and the relay share one domain.** Caddy routes WebSocket
  upgrades to the relay and everything else to the landing page. No client
  change: the client connects to `/` with no path, so the split is on the
  `Upgrade` handshake rather than a path.
- **Presence endpoint** (`PRESENCE_PORT`, off by default). Publishes how busy a
  relay is as a coarse **range** — `1-5`, `6-20` — never an exact count, a room
  name or a nickname. An exact live number would let anyone polling it watch
  people arrive and leave, which is the metadata the relay exists to withhold.
  Runs on its own listener so it cannot affect chat.
- **Standalone client binary.** Every release now ships
  `ciphermesh-<platform>` with the client, relay and P2P, alongside the
  relay-only `ciphermesh-server-<platform>`. No Node needed. Closes the
  long-standing bundling blocker (#328).
- **External hub monitoring.** A scheduled probe checks the WebSocket upgrade,
  the site and the certificate, and opens an issue when any of them fails.

### Fixed

- A Caddyfile change never reached the running Caddy. `git reset --hard`
  replaces the file, giving it a new inode, and a file bind-mount follows the
  inode it was created with — the container kept reading the old, unlinked copy
  while `docker compose up -d` saw nothing to recreate. `deploy/deploy.sh` is
  now versioned and recreates Caddy when the file changes.
- The automatic deploy never fired on a release: GitHub does not trigger
  workflows from events created by `GITHUB_TOKEN`.

### Changed

- Both READMEs describe the hub and link to the site; `homepage` now points at
  ciphermesh.de.
- `bonjour-service` 1.4.3 → 1.4.4.
- **`figlet` held at 1.11.3.** 1.11.4 reads its `.flf` font from disk at
  runtime, and that file is not inside a compiled binary, so every standalone
  build died with `ENOENT` on `/$bunfs/fonts/ANSI Shadow.flf` before printing
  the banner. The test suite runs under Node, where the font exists, so CI
  stayed green while the binaries were broken. Tracked in #414.
- Dependabot now targets `dev`. It was opening PRs straight into `master`,
  which left `dev` behind and dragged unrelated commits into the next release.

## 2.6.0 and earlier

See the [release history](https://github.com/FelipeKreulich/secret-chat-lan/releases).
Highlights: hybrid post-quantum handshake (X25519 + ML-KEM-768), sealed sender,
multi-room buffers, private rooms with zero-knowledge passwords, the plugin API,
`/doctor`, screen lock, and the standalone relay binary.
