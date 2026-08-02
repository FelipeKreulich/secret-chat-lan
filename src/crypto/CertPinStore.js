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
  #caHosts; // Set<host> — hosts that already presented a CA-valid certificate

  constructor(baseDir = process.cwd()) {
    const dir = join(baseDir, PIN_DIR);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    this.#path = join(dir, PIN_FILE);
    this.#store = new Map();
    this.#caHosts = new Set();
    this.#load();
  }

  #load() {
    try {
      if (existsSync(this.#path)) {
        const data = JSON.parse(readFileSync(this.#path, 'utf-8'));
        for (const [host, entry] of Object.entries(data)) {
          // v1 stored a bare fingerprint string; v2 stores { fp, ca }.
          if (typeof entry === 'string') {
            this.#store.set(host, entry);
          } else if (entry && typeof entry === 'object') {
            if (typeof entry.fp === 'string') {
              this.#store.set(host, entry.fp);
            }
            if (entry.ca) {
              this.#caHosts.add(host);
            }
          }
        }
      }
    } catch {
      this.#store = new Map();
      this.#caHosts = new Set();
    }
  }

  #save() {
    const obj = {};
    // Union of both maps: a host can be CA-validated before (or without) ever
    // having a pinned fingerprint, and that flag must survive a restart.
    for (const host of new Set([...this.#store.keys(), ...this.#caHosts])) {
      obj[host] = { fp: this.#store.get(host) || null, ca: this.#caHosts.has(host) };
    }
    writeFileSync(this.#path, JSON.stringify(obj, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });
  }

  /**
   * Remember that a host served a certificate that chains to a public CA.
   * Subsequent connections to it demand full TLS verification, so a hosted
   * relay can never be silently downgraded to a self-signed (attacker) cert.
   */
  markCAValidated(host) {
    if (!this.#caHosts.has(host)) {
      this.#caHosts.add(host);
      this.#save();
    }
  }

  /** True if this host must be verified strictly (it was CA-valid before). */
  requiresStrictTLS(host) {
    return this.#caHosts.has(host);
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
