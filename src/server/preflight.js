import { parseServerConfig } from './config.js';
import { CONNECTION_RATE_PER_MINUTE, MAX_CONNECTIONS_PER_IP } from '../shared/constants.js';

/**
 * What is wrong with this relay's configuration, before it starts serving.
 *
 * The deploy guide already explains every footgun here. That is the problem: a
 * document is read once, by whoever set the machine up, and never again — while
 * the misconfiguration lasts as long as the machine does. The worst of them,
 * `TRUST_PROXY` left off behind a reverse proxy, is invisible from the outside:
 * everything works, the per-IP cap and the banlist simply apply to the proxy
 * and protect nobody. Nothing breaks, so nobody looks.
 *
 * Pure and exported so `--check` and startup share one implementation and
 * cannot disagree about what counts as a problem.
 *
 * @returns {Array<{level: 'error'|'warn', text: string}>}
 */
export function preflight(env = process.env) {
  const config = parseServerConfig(env);
  const findings = [];

  const error = (text) => findings.push({ level: 'error', text });
  const warn = (text) => findings.push({ level: 'warn', text });

  // Behind a proxy, every connection arrives from the proxy. The per-IP limits
  // then bound the proxy's own traffic, which is all of it.
  const behindProxy = Boolean(env.CIPHERMESH_DOMAIN || env.BEHIND_PROXY);
  if (behindProxy && !config.trustProxy) {
    error(
      'TRUST_PROXY is off but this looks like it is behind a reverse proxy. ' +
        'Every connection will appear to come from the proxy, so the per-IP cap, ' +
        'the connection rate limit and the banlist protect nobody.',
    );
  }

  // And the mirror image, which is worse: trusting a header anyone can set.
  if (config.trustProxy && !behindProxy) {
    warn(
      'TRUST_PROXY is on. If this relay is reachable directly, a client can forge ' +
        'X-Forwarded-For and walk straight past the per-IP cap and the banlist.',
    );
  }

  const isPublic = behindProxy || env.PUBLIC_RELAY === 'true';
  if (isPublic) {
    // The defaults are generous because the project started on LANs, where the
    // people connecting are in the same building as the machine.
    if (config.maxConnectionsPerIp >= MAX_CONNECTIONS_PER_IP) {
      warn(
        `MAX_CONNECTIONS_PER_IP is ${config.maxConnectionsPerIp}, the LAN default. ` +
          'On the open internet 3-5 is plenty and costs real users nothing.',
      );
    }
    if (config.connectionRatePerMinute >= CONNECTION_RATE_PER_MINUTE) {
      warn(
        `CONNECTION_RATE_PER_MINUTE is ${config.connectionRatePerMinute}, the LAN default. ` +
          '10-20 still leaves room for a reconnect storm after a restart.',
      );
    }
    if (env.TLS === 'false' && !behindProxy) {
      error('TLS is disabled and nothing appears to be terminating it in front.');
    }
  }

  if (env.LOG_LEVEL?.toLowerCase() === 'debug') {
    warn(
      'LOG_LEVEL is debug. Nothing logs message content at any level — there is a ' +
        'test that proves it — but debug writes more metadata to disk than a ' +
        'running relay needs to.',
    );
  }

  // A banlist file that is not there is almost always a mount that is not
  // there, and it fails open: everyone gets in and nothing says otherwise.
  if (env.BANNED_IPS_FILE && config.bannedIps.size === 0) {
    warn(
      'BANNED_IPS_FILE is set but no addresses were loaded from it. ' +
        'If the file is missing or unreadable the banlist is simply empty.',
    );
  }

  if (env.MOTD_FILE && !config.motd) {
    warn('MOTD_FILE is set but nothing was read from it.');
  }

  return findings;
}

/** Human-readable lines for `--check`. */
export function formatPreflight(findings) {
  if (findings.length === 0) {
    return ['Configuration looks fine.'];
  }
  return findings.map(({ level, text }) => `${level === 'error' ? 'ERROR' : 'warn '}  ${text}`);
}
