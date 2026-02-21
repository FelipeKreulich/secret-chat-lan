/* eslint-disable curly */
// @ts-nocheck
import { existsSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { SERVER_PORT, OFFLINE_QUEUE_MAX_AGE_MS } from '../shared/constants.js';
import { createLogger } from '../shared/logger.js';
import { serverBanner } from '../shared/banner.js';
import { SessionManager } from './SessionManager.js';
import { MessageRouter } from './MessageRouter.js';
import { OfflineQueue } from './OfflineQueue.js';
import { SecureWSServer } from './WebSocketServer.js';
import { loadOrGenerateCerts } from './CertManager.js';

const log = createLogger('server');

// ── Detect LAN IPs ─────────────────────────────────────────────
function getLocalIPs() {
  const ips = [];
  const ifaces = networkInterfaces();
  const inDocker = existsSync('/.dockerenv');

  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        if (inDocker && iface.address.startsWith('172.')) continue;
        ips.push({ name, address: iface.address });
      }
    }
  }
  return { ips, inDocker };
}

// ── Bootstrap ──────────────────────────────────────────────────
const port = parseInt(process.env.PORT, 10) || SERVER_PORT;

const useTls = process.env.TLS !== 'false'; // default: true
const tlsOptions = useTls ? loadOrGenerateCerts() : null;

const sessionManager = new SessionManager();
const offlineQueue = new OfflineQueue();
const messageRouter = new MessageRouter(sessionManager, offlineQueue);
const server = new SecureWSServer(sessionManager, messageRouter, offlineQueue, port, tlsOptions);

// Cleanup offline queue and recently left peers every 5 minutes
setInterval(() => {
  offlineQueue.cleanup();
  sessionManager.cleanupRecentlyLeft(OFFLINE_QUEUE_MAX_AGE_MS);
}, 5 * 60 * 1000);

// ── Startup banner ─────────────────────────────────────────────
serverBanner(port, getLocalIPs(), useTls);

log.info('Servidor iniciado e aguardando conexoes');

// ── Graceful shutdown ──────────────────────────────────────────
async function shutdown(signal) {
  log.info(`${signal} recebido, encerrando...`);
  await server.close();
  log.info('Servidor encerrado');
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
