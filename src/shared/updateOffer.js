// The startup half of the version check: ask, install, come back up.
//
// Split from updateCheck.js so that module stays free of prompts and colours
// and can be tested as plain functions. This one owns the conversation.

import { readFileSync } from 'node:fs';
import { promptLabel, promptDim } from './banner.js';
import {
  detectInstall,
  fetchLatest,
  formatNotice,
  isDisabled,
  isNewer,
  readState,
  runUpdate,
  shouldCheck,
  writeState,
} from './updateCheck.js';

function runningVersion(moduleUrl) {
  try {
    const pkg = new URL('../../package.json', moduleUrl);
    return JSON.parse(readFileSync(pkg, 'utf-8')).version;
  } catch {
    return null;
  }
}

/**
 * Offer the update, and if the user takes it, leave on the new version.
 *
 * Called before any prompt, because accepting restarts the process. Returns
 * without a word when the check is off, when there is no terminal, when it ran
 * today already, when the network says nothing, or when the version is current
 * — the quiet paths are the common ones and none of them may cost anything.
 *
 * @param {import('node:readline/promises').Interface} rl
 * @param {string} moduleUrl `import.meta.url` of the entry point
 * @param {string[]} args argv to carry into the restarted process
 * @param {object} config the user's config, for the opt-out
 * @returns {Promise<void>} — or never returns, having replaced the process
 */
export async function offerUpdate(rl, moduleUrl, args = [], config = {}, deps = {}) {
  const {
    now = Date.now(),
    state = readState(),
    fetch = fetchLatest,
    save = writeState,
    run = runUpdate,
    exit = (code) => process.exit(code),
    log = console.log,
    isTty = process.stdin.isTTY,
    // The running version comes off package.json next to the entry point. It is
    // injectable so the tests can exercise the offer itself rather than the
    // file lookup — without this seam a wrong path silently turns every case
    // into the do-nothing one, and the tests pass by not running.
    current = runningVersion(moduleUrl),
  } = deps;

  if (!current) {
    return;
  }
  if (
    !shouldCheck({
      now,
      lastCheckedAt: state.lastCheckedAt,
      disabled: isDisabled(process.env, config),
      isTty,
    })
  ) {
    return;
  }

  const latest = await fetch();
  save({ lastCheckedAt: now, latest });
  if (!latest || !isNewer(latest, current)) {
    return;
  }

  const install = detectInstall(moduleUrl, args);
  log('');
  log(promptLabel(`  ▸ ${formatNotice(current, latest, install)}`));

  if (!install.update) {
    log(promptDim('    Update when you can — this build is behind.'));
    log('');
    return;
  }

  const answer = await rl.question(
    promptLabel(`  ▸ Update now? ${promptDim('(u to update, Enter to skip)')} `),
  );
  if (!/^\s*[uy]/i.test(answer)) {
    return;
  }

  log('');
  const code = run(install);
  if (code === null) {
    log(promptDim('    Update did not complete — starting the version you have.'));
    log('');
    return;
  }
  exit(code);
}
