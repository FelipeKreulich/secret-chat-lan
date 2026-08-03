import { createServer } from 'node:http';
import { createLogger } from '../shared/logger.js';

const log = createLogger('presence');

/**
 * Buckets, not counts.
 *
 * A live "3 people online" would let anyone with a polling script watch people
 * arrive and leave — exactly the metadata the relay is built not to hand out.
 * Bucketing hides that: within a bucket, joins and leaves are invisible, and the
 * only thing an observer learns is roughly how busy the hub is.
 *
 * Crossing a boundary is still observable (5 → 6 says somebody joined). That is
 * inherent to publishing anything at all, and it is a far smaller disclosure
 * than an exact number. Wider buckets would leak less and say less; this is the
 * trade-off, stated out loud rather than hidden.
 */
const BUCKETS = [
  { max: 0, label: '0' },
  { max: 5, label: '1-5' },
  { max: 20, label: '6-20' },
  { max: 50, label: '21-50' },
  { max: Infinity, label: '50+' },
];

export function bucketFor(count) {
  const n = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
  return BUCKETS.find((b) => n <= b.max).label;
}

/**
 * A tiny HTTP listener that publishes how busy the hub is, and nothing else.
 *
 * Deliberately a SEPARATE server from the WebSocket one: if anything here
 * misbehaves, chat is untouched. It is meant to be reachable only from the
 * internal network (the landing page's container asks it), never published to
 * the host — see deploy/docker-compose.public.yml.
 *
 * What it will never expose: room names, nicknames, addresses, or an exact
 * count. Those are the things the relay's whole design refuses to hand over,
 * and a convenience endpoint is not a good reason to start.
 *
 * @param {{ size: number }} sessionManager
 * @param {number} port - 0 or unset disables the listener entirely
 */
export function startPresenceServer(sessionManager, port) {
  if (!port) {
    return null;
  }

  const server = createServer((req, res) => {
    if (req.method !== 'GET' || !req.url.startsWith('/presence')) {
      res.writeHead(404).end();
      return;
    }

    const body = JSON.stringify({ online: bucketFor(sessionManager.size) });
    res.writeHead(200, {
      'content-type': 'application/json',
      // The caller caches; this only stops an intermediary from serving a
      // stale bucket for longer than the bucket is meaningful.
      'cache-control': 'public, max-age=30',
      'content-length': Buffer.byteLength(body),
    });
    res.end(body);
  });

  server.on('error', (err) => {
    // Presence is a nice-to-have. It must never take the relay down with it.
    log.error(`Presence server error: ${err.message}`);
  });

  // Bind to all interfaces so the site's container can reach it over the Docker
  // network. The port is never published to the host.
  server.listen(port, () => log.info(`Presence endpoint on port ${port}`));

  return server;
}
