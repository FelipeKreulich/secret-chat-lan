#!/usr/bin/env bash
# Deploy of the relay. This is the ONLY command the GitHub Actions key can run
# (a command= restriction in authorized_keys), so even a leaked key does not get
# a shell.
#
# Installed on the hub at /opt/ciphermesh/deploy.sh. It lives here so it is
# reviewed and versioned like everything else; copy it over with:
#
#   install -m 755 deploy/deploy.sh /opt/ciphermesh/deploy.sh
set -euo pipefail
cd /opt/ciphermesh

COMPOSE=(docker compose -f deploy/docker-compose.public.yml --env-file .env)

# Caddy mounts the Caddyfile as a single file. `git reset --hard` REPLACES that
# file, giving it a new inode, and a file bind-mount follows the inode it was
# created with — so the running container keeps reading the old, now-unlinked
# copy. `up -d` will not notice, because the service definition did not change.
#
# The result is a config change that appears to deploy and silently never
# applies. Compare the file across the update and recreate Caddy when it moved.
caddyfile_hash() { sha256sum deploy/Caddyfile 2>/dev/null | cut -d' ' -f1; }
CADDY_BEFORE="$(caddyfile_hash)"

echo "→ updating the code"
git fetch --quiet origin master
git reset --quiet --hard origin/master
echo "  commit: $(git log --oneline -1)"

echo "→ rebuilding"
"${COMPOSE[@]}" up -d --build

if [ "$(caddyfile_hash)" != "$CADDY_BEFORE" ]; then
  echo "→ Caddyfile changed, recreating Caddy so the new file is actually mounted"
  "${COMPOSE[@]}" up -d --force-recreate --no-deps caddy
fi

echo "→ verifying"
for _ in $(seq 1 20); do
  sleep 2
  if docker logs ciphermesh-relay 2>&1 | tail -30 | grep -q "Server started"; then
    echo "  relay: $(docker ps --format '{{.Status}}' -f name=ciphermesh-relay)"
    echo "  caddy: $(docker ps --format '{{.Status}}' -f name=ciphermesh-caddy)"
    echo "  site:  $(docker ps --format '{{.Status}}' -f name=ciphermesh-site)"
    exit 0
  fi
done

echo "  FAILED: the relay did not come up. Last logs:" >&2
docker logs ciphermesh-relay 2>&1 | tail -20 >&2
exit 1
