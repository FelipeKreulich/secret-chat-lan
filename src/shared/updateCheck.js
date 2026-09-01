// "You are running an old CipherMesh" — and the one command that fixes it.
//
// This is the only place the client talks to anything other than the relay, so
// it is deliberately timid: one request a day at most, a short timeout, a
// failure that is indistinguishable from being up to date, and an off switch in
// both the environment and the config file. A LAN chat is routinely run with no
// internet at all, and none of this may ever cost a second of startup.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const REGISTRY_URL = 'https://registry.npmjs.org/ciphermesh/latest';
export const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const CHECK_TIMEOUT_MS = 1500;

/**
 * Compare two `x.y.z` versions. Returns -1, 0 or 1. Anything unparseable sorts
 * as equal, so junk from the registry can never claim an update. Pure.
 */
export function compareVersions(a, b) {
  const parse = (v) => {
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v || '').trim());
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const left = parse(a);
  const right = parse(b);
  if (!left || !right) {
    return 0;
  }
  for (let i = 0; i < 3; i++) {
    if (left[i] !== right[i]) {
      return left[i] < right[i] ? -1 : 1;
    }
  }
  return 0;
}

/** True when `latest` is strictly newer than `current`. Pure. */
export function isNewer(latest, current) {
  return compareVersions(current, latest) < 0;
}

/**
 * Work out how this copy was installed, and therefore how to update it.
 *
 * Getting this wrong is worse than saying nothing: `npm i -g` on a Homebrew
 * install leaves two copies fighting over PATH. The answer comes from where the
 * module actually sits on disk.
 *
 * `relaunch` is null when `update` already starts the new version — which is
 * the case for npx, where `npx ciphermesh@latest` fetches *and* runs. That is
 * also why nothing here ever re-execs `process.argv[1]`: under npx it points at
 * the cache entry that was just replaced, so relaunching it would bring the old
 * version back up and look like the update did nothing.
 *
 * Pure — exported for testing.
 *
 * @param {string} moduleUrl typically `import.meta.url`
 * @param {string[]} [args] the arguments to carry into the new process
 */
export function detectInstall(moduleUrl, args = []) {
  const path = String(moduleUrl || '');

  if (/[/\\]_npx[/\\]/.test(path)) {
    return {
      kind: 'npx',
      label: 'npx',
      update: ['npx', ['--yes', 'ciphermesh@latest', ...args]],
      relaunch: null, // the update command is the new version starting up
    };
  }
  if (/[/\\](Cellar|homebrew|linuxbrew)[/\\]/i.test(path)) {
    return {
      kind: 'homebrew',
      label: 'Homebrew',
      update: ['brew', ['upgrade', 'ciphermesh']],
      relaunch: ['ciphermesh', args],
    };
  }
  if (/[/\\]lib[/\\]node_modules[/\\]ciphermesh[/\\]/.test(path)) {
    return {
      kind: 'global',
      label: 'a global npm install',
      update: ['npm', ['install', '--global', 'ciphermesh@latest']],
      relaunch: ['ciphermesh', args],
    };
  }
  // A checkout. Pulling someone's working tree from under them is not ours to
  // do, so this one only ever gets told what to run.
  return {
    kind: 'source',
    label: 'a source checkout',
    update: null,
    relaunch: null,
    hint: 'git pull && npm install',
  };
}

/**
 * Whether to go to the network at all. Pure — the caller supplies the clock and
 * the last-checked stamp, so the policy is testable without touching a disk.
 */
export function shouldCheck({
  now = Date.now(),
  lastCheckedAt = 0,
  intervalMs = CHECK_INTERVAL_MS,
  disabled = false,
  isTty = true,
} = {}) {
  if (disabled || !isTty) {
    return false;
  }
  return now - Number(lastCheckedAt || 0) >= intervalMs;
}

/** True when the user has switched the check off, by env or by config. Pure. */
export function isDisabled(env = process.env, config = {}) {
  if (env.CIPHERMESH_NO_UPDATE_CHECK === '1' || env.NO_UPDATE_NOTIFIER === '1') {
    return true;
  }
  return config.updateCheck === false;
}

function statePath() {
  return join(homedir(), '.ciphermesh', 'update-check.json');
}

/** Last-check stamp. Never throws — a missing or corrupt file just means "go". */
export function readState(file = statePath()) {
  try {
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    return {
      lastCheckedAt: Number(raw.lastCheckedAt) || 0,
      latest: typeof raw.latest === 'string' ? raw.latest : null,
    };
  } catch {
    return { lastCheckedAt: 0, latest: null };
  }
}

export function writeState(state, file = statePath()) {
  try {
    if (!existsSync(dirname(file))) {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    }
    writeFileSync(file, JSON.stringify(state), { mode: 0o600 });
  } catch {
    /* a cache we cannot write just means we check again tomorrow */
  }
}

/**
 * The published version, or null. Never throws and never waits long: no
 * network, a slow registry, a captive portal and a 500 all look the same from
 * here, and all of them mean "say nothing".
 */
export async function fetchLatest({ url = REGISTRY_URL, timeoutMs = CHECK_TIMEOUT_MS } = {}) {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: abort.signal,
      headers: { accept: 'application/vnd.npm.install-v1+json' },
    });
    if (!res.ok) {
      return null;
    }
    const body = await res.json();
    return typeof body?.version === 'string' ? body.version : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The line shown when an update exists. Pure — exported so the wording is
 * testable and so it can be shown without a network round trip in tests.
 */
export function formatNotice(current, latest, install) {
  const head = `Update available: ${current} → ${latest}`;
  if (install.kind === 'source') {
    return `${head} — you are on ${install.label}, so: ${install.hint}`;
  }
  const [cmd, args] = install.update;
  return `${head} — via ${install.label}: ${cmd} ${args.join(' ')}`;
}

/**
 * Run the update, then bring the new version up.
 *
 * `spawnSync` with inherited stdio on purpose: the installer's own output is
 * what tells the user it is working, and a native rebuild of sodium-native is
 * not fast. Returns the exit code to leave the process with, or null when the
 * caller should simply carry on into the chat.
 */
export function runUpdate(install, { spawn } = {}) {
  const run = spawn || defaultSpawn;
  if (!install.update) {
    return null; // a source checkout only ever gets advice
  }
  const [cmd, args] = install.update;
  const result = run(cmd, args);
  if (result.status !== 0) {
    return null; // it failed; the caller says so and starts the old version
  }
  if (!install.relaunch) {
    return result.status; // the update command *was* the new version
  }
  const [nextCmd, nextArgs] = install.relaunch;
  const relaunched = run(nextCmd, nextArgs);
  return relaunched.status ?? 0;
}

function defaultSpawn(cmd, args) {
  // shell on Windows because npm and npx are .cmd shims there, which
  // CreateProcess cannot execute directly.
  return spawnSync(cmd, args, { stdio: 'inherit', shell: process.platform === 'win32' });
}
