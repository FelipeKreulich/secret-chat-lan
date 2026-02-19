import figlet from 'figlet';
import gradient from 'gradient-string';
import chalk from 'chalk';
import boxen from 'boxen';

const neon = gradient(['#00ff9f', '#00b8ff', '#7b2dff', '#ff2dff']);
const cyber = gradient(['#f72585', '#7209b7', '#3a0ca3', '#4361ee', '#4cc9f0']);
const mint = gradient(['#00ff9f', '#00b8ff']);

function logo() {
  return neon(figlet.textSync('CipherMesh', { font: 'ANSI Shadow' }));
}

export function serverBanner(port, network) {
  const { ips, inDocker } = network;

  console.clear();
  console.log(logo());
  console.log(cyber('  ░▒▓  End-to-End Encrypted Relay  ▓▒░'));
  console.log();

  const lines = [];
  lines.push(chalk.hex('#4cc9f0')('  Porta    ') + chalk.bold.white(port));

  if (ips.length > 0) {
    for (const { name, address } of ips) {
      lines.push(
        chalk.hex('#4cc9f0')(`  ${name.padEnd(8)} `) +
          chalk.bold.white(`ws://${address}:${port}`),
      );
    }
  } else if (inDocker) {
    lines.push(chalk.hex('#4cc9f0')('  Docker   ') + chalk.bold.yellow('Porta mapeada no host'));
  } else {
    lines.push(chalk.hex('#4cc9f0')('  Local    ') + chalk.bold.white(`ws://localhost:${port}`));
  }

  lines.push(chalk.hex('#4cc9f0')('  Status   ') + chalk.bold.green('● Online'));

  console.log(
    boxen(lines.join('\n'), {
      padding: { left: 1, right: 1, top: 0, bottom: 0 },
      borderColor: '#7b2dff',
      borderStyle: 'round',
      title: chalk.bold.hex('#00ff9f')(' SERVER '),
      titleAlignment: 'center',
    }),
  );

  console.log();
  if (inDocker) {
    console.log(chalk.yellow('  Clientes devem conectar usando o IP da maquina host.'));
    console.log(chalk.dim('  Ex: ws://<IP-DO-HOST>:' + port));
  }
  console.log(chalk.dim('  Zero-knowledge relay — o servidor NAO le as mensagens.'));
  console.log(chalk.dim('  Apenas retransmite payloads cifrados entre os peers.'));
  console.log();
}

export function clientBanner() {
  console.clear();
  console.log(logo());
  console.log(cyber('  ░▒▓  End-to-End Encrypted Chat  ▓▒░'));
  console.log();
}

export function clientConnectingBox(wsUrl, fingerprint) {
  const lines = [];
  lines.push(chalk.hex('#4cc9f0')('  Server       ') + chalk.bold.white(wsUrl));
  lines.push(
    chalk.hex('#4cc9f0')('  Fingerprint  ') + mint(fingerprint),
  );
  lines.push(chalk.hex('#4cc9f0')('  Crypto       ') + chalk.white('X25519 + XSalsa20-Poly1305'));
  lines.push(chalk.hex('#4cc9f0')('  Status       ') + chalk.bold.yellow('● Conectando...'));

  console.log(
    boxen(lines.join('\n'), {
      padding: { left: 1, right: 1, top: 0, bottom: 0 },
      borderColor: '#7b2dff',
      borderStyle: 'round',
      title: chalk.bold.hex('#00ff9f')(' CLIENT '),
      titleAlignment: 'center',
    }),
  );
  console.log();
}

export function promptLabel(text) {
  return chalk.hex('#00ff9f')('  ▸ ') + chalk.bold.white(text);
}

export function promptDim(text) {
  return chalk.dim(text);
}

export function promptError(text) {
  return chalk.red('  ✗ ') + chalk.red(text);
}

export function promptSuccess(text) {
  return chalk.green('  ✓ ') + chalk.green(text);
}

export { chalk, neon, cyber, mint };
