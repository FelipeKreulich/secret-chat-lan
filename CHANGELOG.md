# Changelog

Notable changes per release. Older versions are reconstructed from the git
history — the commit bodies and pull requests remain the fuller record.

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
