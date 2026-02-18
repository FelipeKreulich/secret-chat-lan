// @ts-nocheck
import { networkInterfaces } from 'node:os';
import { SERVER_PORT } from '../shared/constants.js';
import { createLogger } from '../shared/logger.js';
import { SessionManager } from './SessionManager.js';
import { MessageRouter } from './MessageRouter.js';
import { SecureWSServer } from './WebSocketServer.js';

const log = createLogger('server');

// ── Detect LAN IPs ─────────────────────────────────────────────
function getLocalIPs() {
  const ips = [];
  const ifaces = networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push({ name, address: iface.address });
      }
    }
  }
  return ips;
}

// ── Bootstrap ──────────────────────────────────────────────────
const port = parseInt(process.env.PORT, 10) || SERVER_PORT;

const sessionManager = new SessionManager();
const messageRouter = new MessageRouter(sessionManager);
const server = new SecureWSServer(sessionManager, messageRouter, port);

// ── Startup banner ─────────────────────────────────────────────
console.log();
console.log('  ╔══════════════════════════════════════╗');
console.log('  ║        SecureLAN Chat Server          ║');
console.log('  ║     End-to-End Encrypted Relay        ║');
console.log('  ╚══════════════════════════════════════╝');
console.log();
console.log(`  Porta: ${port}`);
console.log();

const ips = getLocalIPs();
if (ips.length > 0) {
  console.log('  Enderecos LAN disponiveis:');
  for (const { name, address } of ips) {
    console.log(`    ${name}: ws://${address}:${port}`);
  }
} else {
  console.log(`  Local: ws://localhost:${port}`);
}

console.log();
console.log('  O servidor NAO tem acesso ao conteudo das mensagens.');
console.log('  Apenas retransmite payloads criptografados.');
console.log();
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
