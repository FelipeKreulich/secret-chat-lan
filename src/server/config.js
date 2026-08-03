// Server limits and operator settings, read from the environment so whoever
// hosts a relay can tighten it for the open internet without touching code.
//
// The defaults are the LAN-friendly ones the project always had. A public
// relay should lower the connection caps and set TRUST_PROXY — see deploy/.
import { readFileSync } from 'node:fs';
import {
  MAX_CONNECTIONS_TOTAL,
  MAX_CONNECTIONS_PER_IP,
  MESSAGE_RATE_LIMIT_PER_SECOND,
} from '../shared/constants.js';

const DEFAULTS = {
  maxConnectionsTotal: MAX_CONNECTIONS_TOTAL,
  maxConnectionsPerIp: MAX_CONNECTIONS_PER_IP,
  messageRateLimitPerSecond: MESSAGE_RATE_LIMIT_PER_SECOND,
  // Multi-room means ONE connection can open many rooms; without a cap a
  // single client could exhaust the room table on its own.
  maxRoomsTotal: 500,
  maxRoomsPerSession: 10,
};

function positiveInt(raw, fallback) {
  const n = Number.parseInt(raw, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function readMotd(env) {
  if (env.MOTD_FILE) {
    try {
      return readFileSync(env.MOTD_FILE, 'utf-8').trim().slice(0, 500);
    } catch {
      return ''; // a missing file must never stop the server from booting
    }
  }
  return String(env.MOTD || '')
    .trim()
    .slice(0, 500);
}

function readBannedIps(env) {
  const inline = String(env.BANNED_IPS || '');
  let fromFile = '';
  if (env.BANNED_IPS_FILE) {
    try {
      fromFile = readFileSync(env.BANNED_IPS_FILE, 'utf-8');
    } catch {
      fromFile = '';
    }
  }
  // Strip comments PER LINE before splitting: a naive split would turn
  // "# abuse 2026-08" into three bogus banlist entries.
  const entries = `${inline}\n${fromFile}`
    .split('\n')
    .map((line) => line.split('#')[0])
    .flatMap((line) => line.split(/[\s,]+/))
    .map((ip) => ip.trim())
    .filter(Boolean);
  return new Set(entries);
}

/**
 * Build the server configuration from an environment object.
 * Pure — exported so tests can feed it any env.
 */
export function parseServerConfig(env = process.env) {
  return {
    maxConnectionsTotal: positiveInt(env.MAX_CONNECTIONS_TOTAL, DEFAULTS.maxConnectionsTotal),
    maxConnectionsPerIp: positiveInt(env.MAX_CONNECTIONS_PER_IP, DEFAULTS.maxConnectionsPerIp),
    messageRateLimitPerSecond: positiveInt(
      env.MESSAGE_RATE_LIMIT,
      DEFAULTS.messageRateLimitPerSecond,
    ),
    maxRoomsTotal: positiveInt(env.MAX_ROOMS_TOTAL, DEFAULTS.maxRoomsTotal),
    maxRoomsPerSession: positiveInt(env.MAX_ROOMS_PER_SESSION, DEFAULTS.maxRoomsPerSession),
    // Behind a reverse proxy every connection arrives from the proxy, so the
    // per-IP cap would apply to the proxy itself and protect nobody. Only
    // trust the forwarded header when the operator says there IS a proxy —
    // otherwise any client could forge its own address.
    trustProxy: String(env.TRUST_PROXY || '').toLowerCase() === 'true',
    motd: readMotd(env),
    bannedIps: readBannedIps(env),
  };
}

/**
 * The client address to rate-limit and ban on.
 * @param {object} req - the upgrade request
 * @param {boolean} trustProxy
 */
export function clientAddress(req, trustProxy) {
  const socketIp = req?.socket?.remoteAddress || 'unknown';
  if (!trustProxy) {
    return socketIp;
  }
  // X-Forwarded-For is "client, proxy1, proxy2" — the FIRST entry is the
  // original client. It is only trustworthy because the operator declared
  // that a proxy sits in front and overwrites it.
  const forwarded = req?.headers?.['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    const first = forwarded.split(',')[0].trim();
    if (first) {
      return first;
    }
  }
  return socketIp;
}

/** Normalize an address for comparison (strips the IPv6-mapped IPv4 prefix). */
export function normalizeIp(ip) {
  return String(ip || '').replace(/^::ffff:/, '');
}
