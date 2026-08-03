#!/usr/bin/env bash
# Pulls the published site image and restarts only that container.
#
# Installed on the hub at /opt/ciphermesh/deploy-site.sh and forced as the sole
# command for the site deploy key in authorized_keys:
#
#   command="/opt/ciphermesh/deploy-site.sh",no-port-forwarding,\
#   no-agent-forwarding,no-pty,no-X11-forwarding ssh-ed25519 AAAA... site-deploy
#
# That restriction is the point: the key cannot open a shell, read a file or
# reach the relay. The worst a leaked key can do is redeploy the image that
# master already published.
set -euo pipefail

COMPOSE_DIR="${COMPOSE_DIR:-/opt/ciphermesh}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.public.yml}"

cd "$COMPOSE_DIR"

echo "==> Pulling the site image"
docker compose -f "$COMPOSE_FILE" pull site

# Only the site is recreated. The relay keeps running, so nobody in a room gets
# disconnected because the website changed.
echo "==> Restarting the site"
docker compose -f "$COMPOSE_FILE" up -d --no-deps site

echo "==> Waiting for it to answer"
for _ in $(seq 1 20); do
  if docker compose -f "$COMPOSE_FILE" exec -T site \
       node -e "fetch('http://127.0.0.1:3000/en').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then
    echo "==> Site is up"
    docker image prune -f --filter "until=168h" >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 3
done

echo "The site container did not answer after the deploy" >&2
docker compose -f "$COMPOSE_FILE" logs --tail 50 site >&2
exit 1
