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

export function serverBanner(port, network, tls = false) {
  const { ips, inDocker } = network;
  const proto = tls ? 'wss' : 'ws';

  console.clear();
  console.log(logo());
  console.log(cyber('  ░▒▓  End-to-End Encrypted Relay  ▓▒░'));
  console.log();

  const lines = [];
  lines.push(chalk.hex('#4cc9f0')('  Port     ') + chalk.bold.white(port));

  if (ips.length > 0) {
    for (const { name, address, tailscale } of ips) {
      const label = tailscale ? 'Internet' : name;
      lines.push(
        chalk.hex('#4cc9f0')(`  ${label.padEnd(8)} `) +
          chalk.bold.white(`${proto}://${address}:${port}`),
      );
    }
  } else if (inDocker) {
    lines.push(chalk.hex('#4cc9f0')('  Docker   ') + chalk.bold.yellow('Port mapped on host'));
  } else {
    lines.push(
      chalk.hex('#4cc9f0')('  Local    ') + chalk.bold.white(`${proto}://localhost:${port}`),
    );
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
  if (inDocker && ips.length === 0) {
    console.log(chalk.yellow('  Clients must connect using the host machine IP.'));
    console.log(chalk.dim(`  e.g. ${proto}://<HOST-IP>:${port}`));
    console.log(chalk.dim('  Tip: set ADVERTISE_IP in .env to display the IP here.'));
  }
  if (ips.some((ip) => ip.tailscale)) {
    console.log(
      chalk.dim('  Tailscale IP detected — peers outside the LAN can connect through it.'),
    );
  }
  console.log(chalk.dim('  Zero-knowledge relay — the server does NOT read messages.'));
  console.log(chalk.dim('  It only relays encrypted payloads between peers.'));
  console.log();
}

export function clientBanner() {
  console.clear();
  console.log(logo());
  console.log(cyber('  ░▒▓  End-to-End Encrypted Chat  ▓▒░'));
  console.log();
}

const NEON_STOPS = ['#00ff9f', '#00b8ff', '#7b2dff', '#ff2dff'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Animated splash: the neon gradient "flows" through the ANSI-Shadow logo for
// ~1s, then settles. Runs before the TUI (plain terminal output).
export async function animatedBanner(subtitle = '  ░▒▓  End-to-End Encrypted Chat  ▓▒░') {
  const art = figlet.textSync('CipherMesh', { font: 'ANSI Shadow' }).replace(/\n+$/, '');
  const artLines = art.split('\n');
  const N = artLines.length;

  // Some terminals/CI aren't interactive — just render the static banner.
  if (!process.stdout.isTTY) {
    console.clear();
    console.log(neon(art));
    console.log(cyber(subtitle));
    console.log();
    return;
  }

  console.clear();
  const FRAMES = 22;
  for (let f = 0; f < FRAMES; f++) {
    const shift = f % NEON_STOPS.length;
    const stops = [...NEON_STOPS.slice(shift), ...NEON_STOPS.slice(0, shift)];
    const grad = gradient(stops);
    if (f > 0) {
      process.stdout.write(`\x1b[${N + 1}A`); // back to the top of the art
    }
    process.stdout.write(grad.multiline(art) + '\n');
    process.stdout.write(cyber(subtitle) + '\n');
    await sleep(45);
  }
  // Settle on the canonical neon gradient.
  process.stdout.write(`\x1b[${N + 1}A`);
  process.stdout.write(neon(art) + '\n');
  process.stdout.write(cyber(subtitle) + '\n');
  console.log();
}

export function clientConnectingBox(wsUrl, fingerprint) {
  const lines = [];
  lines.push(chalk.hex('#4cc9f0')('  Server       ') + chalk.bold.white(wsUrl));
  lines.push(chalk.hex('#4cc9f0')('  Fingerprint  ') + mint(fingerprint));
  lines.push(chalk.hex('#4cc9f0')('  Crypto       ') + chalk.white('X25519 + XSalsa20-Poly1305'));
  lines.push(chalk.hex('#4cc9f0')('  Status       ') + chalk.bold.yellow('● Connecting...'));

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
