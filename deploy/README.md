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

| Variable | Default | What it does |
|---|---|---|
| `MAX_CONNECTIONS_TOTAL` | 500 | Global socket ceiling |
| `MAX_CONNECTIONS_PER_IP` | 20 | Per-address socket ceiling — **lower this for a public relay** (3–5) |
| `MESSAGE_RATE_LIMIT` | 60 | Messages per second, per connection, all types |
| `MAX_ROOMS_TOTAL` | 500 | Live rooms server-wide |
| `MAX_ROOMS_PER_SESSION` | 10 | Rooms one connection may hold open |
| `TRUST_PROXY` | `false` | **Set to `true` behind Caddy/nginx** — see below |
| `MOTD` / `MOTD_FILE` | — | Notice shown to everyone on join (maintenance, rules) |
| `BANNED_IPS` / `BANNED_IPS_FILE` | — | Addresses refused at connect; the file accepts `#` comments |

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
