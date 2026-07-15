import * as readline from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { readFileSync } from 'node:fs';
import sodium from 'sodium-native';
import boxen from 'boxen';
import {
  clientBanner,
  promptLabel,
  promptDim,
  promptError,
  chalk,
  mint,
} from '../shared/banner.js';
import { KeyManager } from '../crypto/KeyManager.js';
import { StateManager } from '../crypto/StateManager.js';
import { questionHidden } from '../shared/prompt.js';
import { importBackup } from '../crypto/IdentityBackup.js';
import { Discovery } from './Discovery.js';
import { PeerServer } from './PeerServer.js';
import { PeerConnectionManager } from './PeerConnectionManager.js';
import { UI } from '../client/UI.js';
import { P2PChatController } from './P2PChatController.js';
import { PluginManager } from '../shared/PluginManager.js';

// ── Banner ──────────────────────────────────────────────────────
clientBanner();

// ── Prompt setup ────────────────────────────────────────────────
const rl = readline.createInterface({ input: stdin, output: stdout });

let nickname = '';
while (!nickname) {
  const raw = await rl.question(promptLabel(`Nickname ${promptDim('(a-z, 0-9, _, -)')}: `));
  const clean = raw.trim().replace(/[^a-zA-Z0-9_-]/g, '');
  if (clean.length >= 1 && clean.length <= 20) {
    nickname = clean;
  } else {
    console.log(promptError('Nickname invalido. Use 1-20 caracteres alfanumericos.'));
  }
}

// ── State restoration ────────────────────────────────────────────
const stateManager = new StateManager();
let restoredState = null;

if (stateManager.hasState()) {
  const passphrase = await questionHidden(
    rl,
    promptLabel(`Passphrase para restaurar sessao ${promptDim('(Enter para pular)')}: `),
  );
  if (passphrase.trim()) {
    restoredState = stateManager.loadState(passphrase.trim());
    if (restoredState) {
      restoredState.passphrase = passphrase.trim();
      console.log(promptLabel('Sessao anterior restaurada com sucesso!'));
    } else {
      console.log(promptError('Passphrase incorreta ou estado corrompido. Nova sessao.'));
    }
  }
} else {
  const passphrase = await questionHidden(
    rl,
    promptLabel(`Passphrase para proteger sessao ${promptDim('(Enter para pular)')}: `),
  );
  if (passphrase.trim()) {
    const confirm = await questionHidden(rl, promptLabel('Confirme a passphrase: '));
    if (confirm.trim() === passphrase.trim()) {
      restoredState = { passphrase: passphrase.trim() };
    } else {
      console.log(
        promptError('As passphrases nao conferem — sessao nao sera protegida nesta vez.'),
      );
    }
  }
}

// Offer to restore identity + trust from an encrypted backup.
if (!restoredState?.keyManager) {
  const backupPath = await rl.question(
    promptLabel(`Restaurar identidade de um backup? ${promptDim('(caminho ou Enter)')}: `),
  );
  if (backupPath.trim()) {
    try {
      const raw = readFileSync(backupPath.trim(), 'utf-8');
      const pass = await questionHidden(rl, promptLabel('Passphrase do backup: '));
      const data = importBackup(raw, pass.trim());
      if (data?.identity) {
        restoredState = {
          ...(restoredState || {}),
          keyManager: data.identity,
          trust: data.trust,
          passphrase: pass.trim(),
        };
        console.log(promptLabel('Identidade + confianca restauradas do backup!'));
      } else {
        console.log(promptError('Backup invalido ou passphrase incorreta.'));
      }
    } catch (e) {
      console.log(promptError(`Nao foi possivel ler o backup: ${e.message}`));
    }
  }
}

rl.close();

// ── Initialize crypto ──────────────────────────────────────────
const keyManager = restoredState?.keyManager
  ? KeyManager.deserialize(restoredState.keyManager)
  : new KeyManager();

// ── Start P2P server ──────────────────────────────────────────
const peerServer = new PeerServer();
const port = await peerServer.start();

// ── Info box ────────────────────────────────────────────────────
console.log();
const lines = [];
lines.push(chalk.hex('#4cc9f0')('  Modo         ') + chalk.bold.white('P2P (mDNS LAN)'));
lines.push(chalk.hex('#4cc9f0')('  Porta        ') + chalk.bold.white(port));
lines.push(chalk.hex('#4cc9f0')('  Fingerprint  ') + mint(keyManager.fingerprint));
lines.push(chalk.hex('#4cc9f0')('  Crypto       ') + chalk.white('X25519 + XSalsa20-Poly1305'));
lines.push(
  chalk.hex('#4cc9f0')('  Status       ') + chalk.bold.green('● Buscando peers na LAN...'),
);

console.log(
  boxen(lines.join('\n'), {
    padding: { left: 1, right: 1, top: 0, bottom: 0 },
    borderColor: '#7b2dff',
    borderStyle: 'round',
    title: chalk.bold.hex('#00ff9f')(' P2P '),
    titleAlignment: 'center',
  }),
);
console.log();

await new Promise((resolve) => setTimeout(resolve, 1500));

// ── Load plugins ────────────────────────────────────────────────
const pluginManager = new PluginManager();
await pluginManager.loadAll();

// ── Initialize components ──────────────────────────────────────
const connManager = new PeerConnectionManager(nickname, () => keyManager.publicKeyB64);
const discovery = new Discovery();
const ui = new UI(nickname);
const controller = new P2PChatController(
  nickname,
  peerServer,
  connManager,
  discovery,
  ui,
  keyManager,
  restoredState,
  pluginManager,
);

ui.addInfoMessage(`Seu fingerprint: ${controller.fingerprint}`);
ui.addInfoMessage('Modo P2P — peers descobertos automaticamente via mDNS');
ui.addInfoMessage('Use /help para ver comandos disponiveis');

if (restoredState?.handshake) {
  ui.addSystemMessage('Sessao anterior restaurada — ratchets preservados');
}

// Start mDNS discovery
discovery.start(nickname, port, keyManager.publicKeyB64);

// ── Graceful shutdown ───────────────────────────────────────────
function shutdown() {
  const passphrase = controller.passphrase;
  if (passphrase) {
    try {
      const state = controller.serializeState();
      const { kek, salt, opslimit, memlimit } = stateManager.deriveKEK(passphrase);
      stateManager.saveState(state, kek, salt, opslimit, memlimit);
      sodium.sodium_memzero(kek);
    } catch {
      // Best effort — don't block shutdown
    }
  }
  controller.destroy();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
