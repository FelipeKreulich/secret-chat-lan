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

// Linear interpolation between two #rrggbb colors (t in [0,1]).
function mixHex(a, b, t) {
  const pa = [1, 3, 5].map((i) => parseInt(a.slice(i, i + 2), 16));
  const pb = [1, 3, 5].map((i) => parseInt(b.slice(i, i + 2), 16));
  return (
    '#' +
    pa
      .map((v, i) =>
        Math.round(v + (pb[i] - v) * t)
          .toString(16)
          .padStart(2, '0'),
      )
      .join('')
  );
}

// Goodbye animation on /quit: the neon logo fades to black over ~0.8s while a
// farewell line shows, then the process exits. Static fallback on non-TTY.
export async function farewellBanner(message = '  🔒 Session ended — keys wiped from memory') {
  const art = figlet.textSync('CipherMesh', { font: 'ANSI Shadow' }).replace(/\n+$/, '');
  const N = art.split('\n').length;

  if (!process.stdout.isTTY) {
    console.log(neon(art));
    console.log(cyber(message));
    console.log();
    return;
  }

  console.clear();
  const FRAMES = 14;
  for (let f = 0; f < FRAMES; f++) {
    const t = f / (FRAMES - 1); // 0 → 1 (bright → dark)
    const stops = NEON_STOPS.map((c) => mixHex(c, '#0d0d1a', t));
    const grad = gradient(stops);
    if (f > 0) {
      process.stdout.write(`\x1b[${N + 1}A`);
    }
    process.stdout.write(grad.multiline(art) + '\n');
    process.stdout.write(cyber(message) + '\n');
    await sleep(55);
  }
  console.log();
}

const BOOT_STEPS = [
  'Curve25519 key exchange',
  'XSalsa20-Poly1305 cipher',
  'Double Ratchet — forward secrecy',
  'Secure memory (sodium_malloc)',
  'TOFU trust store',
];
const BOOT_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴'];
const BOOT_FRAME_MS = 70; // per spinner frame
const BOOT_SPINS = 1; // minimum full spinner cycles before a step "checks in"
const BOOT_BEAT_MS = 110; // pause after each ✓ so it registers

// Run a step's real work, but stop waiting after `ms` (the underlying promise
// keeps running in the background — e.g. a connection that's still retrying).
// Never rejects: resolves to true on success, false on error/timeout.
function runStep(task, ms) {
  const work = Promise.resolve()
    .then(task)
    .then(
      () => true,
      () => false,
    );
  if (!ms) {
    return work;
  }
  return Promise.race([work, new Promise((resolve) => setTimeout(() => resolve(false), ms))]);
}

// Cyberpunk boot sequence: the crypto stack "checks in" one component at a time
// before the TUI takes over. Each step may carry a real async `task` — the ✓
// then means it genuinely completed; a spinner floor keeps the deliberate pace
// for instant (local) steps, and slow ones (plugins, relay connect) extend it.
// Steps are strings (cosmetic) or { label, task?, timeoutMs? }. Static list on
// non-TTY.
export async function bootSequence(steps = BOOT_STEPS) {
  const norm = steps.map((s) => (typeof s === 'string' ? { label: s } : s));

  if (!process.stdout.isTTY) {
    for (const step of norm) {
      const ok = step.task ? await runStep(step.task, step.timeoutMs) : true;
      console.log((ok ? chalk.green('  ✓ ') : chalk.yellow('  … ')) + chalk.dim(step.label));
    }
    console.log();
    return;
  }

  const minFrames = BOOT_SPINNER.length * BOOT_SPINS;
  for (const step of norm) {
    let settled = !step.task;
    let ok = true;
    const work = step.task
      ? runStep(step.task, step.timeoutMs).then((r) => {
          settled = true;
          ok = r;
        })
      : null;

    // Spin at least `minFrames`, and keep spinning until the real work settles.
    for (let i = 0; i < minFrames || !settled; i++) {
      const glyph = BOOT_SPINNER[i % BOOT_SPINNER.length];
      process.stdout.write(`\r  ${chalk.cyan(glyph)} ${chalk.dim(step.label)}          `);
      await sleep(BOOT_FRAME_MS);
    }
    if (work) {
      await work;
    }

    const mark = ok ? chalk.green('✓') : chalk.yellow('…');
    const label = ok ? chalk.white(step.label) : chalk.dim(step.label);
    process.stdout.write(`\r  ${mark} ${label}          \n`);
    await sleep(BOOT_BEAT_MS);
  }
  console.log(chalk.hex('#00ff9f')('  ▸ Secure session ready') + '\n');
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
