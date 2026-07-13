const INVITE_SCHEME = 'ciphermesh://';
const ROOM_REGEX = /^[a-zA-Z0-9_-]{1,20}$/;
const HOST_REGEX = /^[a-zA-Z0-9._-]+$/;

/**
 * Build an invite URI: ciphermesh://host:port/room
 * @param {string} hostPort - "host:port" (ex: 100.124.6.27:3600)
 * @param {string} [room] - room name (default: general)
 * @returns {string|null} invite URI or null if input is invalid
 */
export function buildInvite(hostPort, room = 'general') {
  const parsed = parseHostPort(hostPort);
  if (!parsed || !ROOM_REGEX.test(room)) {
    return null;
  }
  return `${INVITE_SCHEME}${parsed.host}:${parsed.port}/${room}`;
}

/**
 * Parse an invite URI into its parts.
 * @param {string} uri - ciphermesh://host:port[/room]
 * @returns {{ host: string, port: number, room: string, wsUrl: string }|null}
 */
export function parseInvite(uri) {
  if (typeof uri !== 'string' || !uri.startsWith(INVITE_SCHEME)) {
    return null;
  }

  const rest = uri.slice(INVITE_SCHEME.length);
  const slash = rest.indexOf('/');
  const hostPort = slash === -1 ? rest : rest.slice(0, slash);
  const room = slash === -1 ? 'general' : rest.slice(slash + 1) || 'general';

  const parsed = parseHostPort(hostPort);
  if (!parsed || !ROOM_REGEX.test(room)) {
    return null;
  }

  return {
    host: parsed.host,
    port: parsed.port,
    room,
    wsUrl: `wss://${parsed.host}:${parsed.port}`,
  };
}

function parseHostPort(hostPort) {
  if (typeof hostPort !== 'string') {
    return null;
  }
  const colon = hostPort.lastIndexOf(':');
  if (colon === -1) {
    return null;
  }
  const host = hostPort.slice(0, colon);
  const port = parseInt(hostPort.slice(colon + 1), 10);
  if (!HOST_REGEX.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }
  return { host, port };
}
