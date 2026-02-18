import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import chalk from 'chalk';
import { SERVER_PORT } from '../shared/constants.js';
import { Connection } from './Connection.js';
import { UI } from './UI.js';
import { ChatController } from './ChatController.js';

// ── Banner ──────────────────────────────────────────────────────
console.clear();
console.log();
console.log(chalk.bold.blue('  ╔══════════════════════════════════════╗'));
console.log(chalk.bold.blue('  ║        SecureLAN Chat Client          ║'));
console.log(chalk.bold.blue('  ║     End-to-End Encrypted Chat         ║'));
console.log(chalk.bold.blue('  ╚══════════════════════════════════════╝'));
console.log();

// ── Prompt setup info ───────────────────────────────────────────
const rl = readline.createInterface({ input: stdin, output: stdout });

let nickname = '';
while (!nickname) {
  const raw = await rl.question(chalk.cyan('  Nickname (a-z, 0-9, _, -): '));
  const clean = raw.trim().replace(/[^a-zA-Z0-9_-]/g, '');
  if (clean.length >= 1 && clean.length <= 20) {
    nickname = clean;
  } else {
    console.log(chalk.red('  Nickname invalido. Use 1-20 caracteres alfanumericos.'));
  }
}

const serverInput = await rl.question(
  chalk.cyan(`  Servidor (${chalk.dim(`localhost:${SERVER_PORT}`)}): `),
);
const serverAddr = serverInput.trim() || `localhost:${SERVER_PORT}`;
const wsUrl = serverAddr.startsWith('ws://') ? serverAddr : `ws://${serverAddr}`;

rl.close();

// ── Show fingerprint before entering UI ─────────────────────────
// Create a temporary KeyManager just to show the fingerprint
// The real one will be created inside ChatController
console.log();
console.log(chalk.green('  Conectando a ') + chalk.bold(wsUrl) + chalk.green(' ...'));
console.log();

// ── Initialize ──────────────────────────────────────────────────
const connection = new Connection(wsUrl);
const ui = new UI(nickname);
const controller = new ChatController(nickname, connection, ui);

ui.addInfoMessage(`Seu fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('Use /help para ver comandos disponiveis');

// Start connection
connection.connect();

// ── Graceful shutdown ───────────────────────────────────────────
process.on('SIGINT', () => {
  controller.destroy();
  process.exit(0);
});

process.on('SIGTERM', () => {
  controller.destroy();
  process.exit(0);
});
