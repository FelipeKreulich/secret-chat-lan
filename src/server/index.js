import { existsSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { SERVER_PORT } from '../shared/constants.js';
import { createLogger } from '../shared/logger.js';
import { serverBanner } from '../shared/banner.js';
import { SessionManager } from './SessionManager.js';
import { MessageRouter } from './MessageRouter.js';
import { SecureWSServer } from './WebSocketServer.js';

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

const sessionManager = new SessionManager();
const messageRouter = new MessageRouter(sessionManager);
const server = new SecureWSServer(sessionManager, messageRouter, port);

// ── Startup banner ─────────────────────────────────────────────
serverBanner(port, getLocalIPs());

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
