# Hosting a public CipherMesh hub

Everything here is for running a relay on the open internet, optionally with the
landing page on the same domain. For LAN or Tailscale use, the root
`docker-compose.yml` is simpler and already enough.

## What you need

- A host with a public IP (a €4–5/month VPS is plenty — the relay only shuffles
  ciphertext; CPU and RAM are near idle)
- A domain name pointing at it (`A`/`AAAA` record)
- Ports 80 and 443 open

## Deploy

```bash
git clone https://github.com/FelipeKreulich/secret-chat-lan.git
cd secret-chat-lan
export CIPHERMESH_DOMAIN=hub.example.com
export CIPHERMESH_EMAIL=you@example.com
docker compose -f deploy/docker-compose.public.yml up -d
```

Caddy obtains a Let's Encrypt certificate on first start and renews it
automatically. Your users connect to `hub.example.com:443`.

Prefer no Docker? Each release also ships a standalone relay binary
(`ciphermesh-server-linux-x64` and friends) — run it behind the same Caddy
config.

## The relay and the site on one domain

The compose file starts a `site` container next to the relay and Caddy routes
between them. A browser hitting `https://hub.example.com` gets the landing page;
the CipherMesh client hitting the same address gets the relay.

The split is on the **WebSocket handshake**, not on a path:

```caddy
@websocket {
	header Connection *Upgrade*
	header Upgrade    websocket
}
reverse_proxy @websocket relay:3600
reverse_proxy site:3000
```

That matters. The client connects to `wss://hub.example.com` with **no path**
(`src/client/index.js`), so splitting on a path would break every client already
installed and every invite string ever sent. Matching the upgrade header needs
no client change and no new release.

Don't want the site? Delete the `site` service and both `reverse_proxy` lines,
and put back the single `reverse_proxy relay:3600`.

### Knowing when it breaks

`.github/workflows/hub-monitor.yml` probes the hub every ten minutes from
GitHub — deliberately not from the VPS, since a monitor hosted on the machine it
watches dies with it. It checks three things:

| Check                      | Expected              |
| -------------------------- | --------------------- |
| HTTP/1.1 WebSocket upgrade | `101`                 |
| `GET /en`                  | `200`                 |
| Certificate validity       | more than 5 days left |

The upgrade has to be **HTTP/1.1**. Over HTTP/2 the `Connection` header is
forbidden and curl drops it, so the matcher never fires, the landing page
answers, and a broken relay looks healthy. The client is a Node `ws` client and
always speaks HTTP/1.1 — the probe does the same.

Each check retries three times before it counts as a failure, so a network blip
does not wake anyone. A failure opens an issue labelled `hub-down` (which
arrives as an email) and later runs comment on that same issue instead of
opening new ones. When the hub recovers, the issue closes itself.

Override the target with the repository variables `HUB_HOST` and
`HUB_CERT_MIN_DAYS`.

### A Caddyfile change needs Caddy recreated, not reloaded

Caddy mounts the Caddyfile as a **single file**. `git pull` and `git reset`
replace that file rather than editing it, so it gets a new inode — and a file
bind-mount follows the inode it was created with. The running container keeps
reading the old, now-unlinked copy, and `docker compose up -d` sees no change to
recreate.

A Caddyfile edit therefore looks deployed and silently never applies. Even
`caddy reload` does not help: it re-reads the same stale path inside the
container.

`deploy/deploy.sh` handles this — it hashes the file across the update and
recreates Caddy when it moved. By hand:

```bash
docker compose -f deploy/docker-compose.public.yml --env-file .env \
  up -d --force-recreate --no-deps caddy
```

Certificates live in the `caddy_data` volume, so recreating the container does
not re-issue anything.

### Automatic site updates

`deploy/deploy-site.sh` pulls the published image and recreates **only** the
site container, so nobody in a room is disconnected because the website changed.

On the hub:

```bash
install -m 755 deploy/deploy-site.sh /opt/ciphermesh/deploy-site.sh
```

Then restrict a dedicated key to it in the deploy user's `authorized_keys` —
one line, no line breaks:

```
command="/opt/ciphermesh/deploy-site.sh",no-port-forwarding,no-agent-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA... site-deploy
```

The restriction is the whole security model: that key cannot open a shell, read
a file or touch the relay. If it leaks, the worst an attacker achieves is
redeploying the image the site's `master` branch already published.

The site repository's workflow calls it after publishing to GHCR. It needs the
secrets `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS`, `DEPLOY_HOST` and `DEPLOY_USER`,
plus the variable `DEPLOY_SITE_ENABLED=true` to arm it.

## What TLS does and does not do here

Messages are end-to-end encrypted before they reach the relay, so TLS is not
what keeps them private — it protects **metadata in transit** (who is
connecting, when) from the network path, and it authenticates the server.

Because a public certificate chains to a real CA, the CipherMesh client
verifies it **strictly**: no trust-on-first-use window, and a host that once
served a CA-valid certificate can never be silently downgraded to a
self-signed one (`src/crypto/CertPinStore.js`).

## Operator controls

Everything below is read from the environment **on the server**. That is
deliberate: there are no in-chat admin commands, so there is no token to leak,
no authentication to bypass, and no way for a user to reach these levers. The
access control is your SSH access.

| Variable                         | Default | What it does                                                         |
| -------------------------------- | ------- | -------------------------------------------------------------------- |
| `MAX_CONNECTIONS_TOTAL`          | 500     | Global socket ceiling                                                |
| `MAX_CONNECTIONS_PER_IP`         | 20      | Per-address socket ceiling — **lower this for a public relay** (3–5) |
| `CONNECTION_RATE_PER_MINUTE`     | 60      | How fast one address may _open_ connections — see below              |
| `MESSAGE_RATE_LIMIT`             | 60      | Messages per second, per connection, all types                       |
| `MAX_BYTES_PER_SECOND`           | 1048576 | Sustained bytes per second, per connection                           |
| `MAX_BYTES_BURST`                | 4194304 | Burst allowance, so a file transfer is not mistaken for an attack    |
| `MAX_ROOMS_TOTAL`                | 500     | Live rooms server-wide                                               |
| `MAX_ROOMS_PER_SESSION`          | 10      | Rooms one connection may hold open                                   |
| `TRUST_PROXY`                    | `false` | **Set to `true` behind Caddy/nginx** — see below                     |
| `MOTD` / `MOTD_FILE`             | —       | Notice shown to everyone on join (maintenance, rules)                |
| `BANNED_IPS` / `BANNED_IPS_FILE` | —       | Addresses refused at connect; the file accepts `#` comments          |

### Rate, not just count

`MAX_CONNECTIONS_PER_IP` bounds how many sockets one address **holds**.
`CONNECTION_RATE_PER_MINUTE` bounds how fast it **opens** them, which is a
different attack: connect, run the handshake, disconnect, repeat. That never
trips a concurrency cap — the sockets are never held — while every attempt
costs the relay an X25519 and an ML-KEM-768 operation and costs the client
almost nothing.

An address that exceeds the rate is refused for **1 minute**, then 5, then 30 if
it keeps going. An hour of behaving clears the record, so a NAT gateway shared
by a hundred people does not accumulate strikes forever. The refusal tells the
client how long to wait, so a well-behaved one backs off instead of extending
its own ban.

`MAX_BYTES_PER_SECOND` exists for the same reason in the other direction: the
message limit counts _messages_, and messages are padded into buckets of up to
32 KiB, so a session sitting at 60/s is a multi-megabit stream. Bytes are the
resource that actually runs out. A connection that outruns its budget is closed
rather than throttled — a client honest enough to be worth keeping will not get
near it.

For a public relay, lowering `CONNECTION_RATE_PER_MINUTE` to 10–20 costs real
users nothing.

### Check it before it serves

\`\`\`bash
docker compose -f deploy/docker-compose.public.yml run --rm relay --check
\`\`\`

Validates the environment and exits without opening a socket, so it is safe to
run against a live host. It exits non-zero on an error, which makes it something
a deploy script can gate on, and warnings do not fail — a check that cries wolf
is one people learn to skip.

The same findings are printed at every startup. A warning you have to ask for is
a warning nobody sees, and the misconfiguration below is invisible from the
outside: chat works perfectly while the limits protect nobody.

### TRUST_PROXY is not optional behind a proxy

With Caddy in front, every connection arrives **from Caddy** — so the per-IP
cap and the banlist would apply to the proxy and protect nobody. `TRUST_PROXY=true`
makes the relay read the real client from `X-Forwarded-For`.

It must stay `false` when the relay is directly exposed: otherwise a client
could forge that header and walk past both the cap and the banlist.

### Room owners are a different thing

Whoever creates a room moderates it (`/kick`, `/mute`, `/ban`) — but only
inside that room, and only while it exists. Those powers never reach the
server: they cannot ban an address, change the MOTD, or affect other rooms.
Keep it that way; it is why letting anyone create a room is safe.

## Before you open it to strangers

Running a public, anonymous, end-to-end encrypted chat means **you cannot
moderate content** — you can't read it, by design. That is the product, and it
is also the risk. Decide deliberately:

- The built-in limits already cap connections per IP, total connections,
  message rate, and payload size (`src/shared/constants.js`). Tune them for
  your box before announcing anything.
- Rooms are ephemeral: they exist only while someone is inside, and private
  rooms keep their password verifier in memory only. Nothing is persisted
  server-side, which is excellent for privacy and means there is nothing to
  hand over — or to recover.
- Publish terms of use and an abuse contact — there is a ready template in
  [`TERMS-TEMPLATE.md`](TERMS-TEMPLATE.md) (English + Portuguese) written for
  exactly this situation: it states plainly what the operator can and cannot
  see, and that requests to remove or hand over content cannot be fulfilled
  because the content does not exist in readable form. Fill in the brackets.
  "Zero logs of content by architecture" is honest and worth stating plainly.
- Consider a soft launch: share the address in the README first, watch the
  logs for abuse patterns, then announce more widely.

## Operating notes

- **Logs**: the relay logs connections and room events, never content.
- **Certificates**: the `caddy_data` volume holds them. Keep it, or you will
  hit Let's Encrypt rate limits on redeploys.
- **Updates**: `docker compose -f deploy/docker-compose.public.yml up -d --build`
- **Health**: `docker logs ciphermesh-relay` shows the startup banner and the
  live connection count.
