import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const PIN_DIR = '.ciphermesh';
const PIN_FILE = 'pinned-certs.json';

export const PinResult = {
  PINNED: 'pinned', // first time — fingerprint stored (trust on first use)
  MATCH: 'match', // fingerprint matches the pin
  MISMATCH: 'mismatch', // fingerprint changed — possible MITM
};

/**
 * Trust-on-first-use pin store for server TLS certificate fingerprints.
 * Complements the E2EE key TOFU (TrustStore) with transport-layer detection.
 */
export class CertPinStore {
  #path;
  #store; // Map<host, sha256Fingerprint>

  constructor(baseDir = process.cwd()) {
    const dir = join(baseDir, PIN_DIR);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    this.#path = join(dir, PIN_FILE);
    this.#store = new Map();
    this.#load();
  }

  #load() {
    try {
      if (existsSync(this.#path)) {
        const data = JSON.parse(readFileSync(this.#path, 'utf-8'));
        for (const [host, fp] of Object.entries(data)) {
          this.#store.set(host, fp);
        }
      }
    } catch {
      this.#store = new Map();
    }
  }

  #save() {
    writeFileSync(this.#path, JSON.stringify(Object.fromEntries(this.#store), null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
  }

  /**
   * Check a server's cert fingerprint against the pinned one (pinning on first use).
   * @param {string} host - e.g. "100.73.206.23:3600"
   * @param {string|null} fingerprint - SHA-256 fingerprint, or null for non-TLS
   * @returns {string} one of PinResult
   */
  check(host, fingerprint) {
    if (!fingerprint) {
      return PinResult.MATCH; // nothing to pin (plain ws://)
    }
    const pinned = this.#store.get(host);
    if (!pinned) {
      this.#store.set(host, fingerprint);
      this.#save();
      return PinResult.PINNED;
    }
    return pinned === fingerprint ? PinResult.MATCH : PinResult.MISMATCH;
  }

  getPinned(host) {
    return this.#store.get(host) || null;
  }

  /** Explicitly accept a new fingerprint (e.g. after a legitimate cert rotation). */
  repin(host, fingerprint) {
    this.#store.set(host, fingerprint);
    this.#save();
  }
}
