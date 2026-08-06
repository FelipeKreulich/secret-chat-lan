import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { existsSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// Resolved lazily so tests (and future flags) can point HOME elsewhere.
export function pluginDir() {
  return join(homedir(), '.ciphermesh', 'plugins');
}

/**
 * Loads plugins, but only the ones the user has said yes to.
 *
 * A plugin is arbitrary JavaScript running inside the chat process, with the
 * same reach as the client itself. That has always been documented, but until
 * now any `.js` file appearing in the directory simply ran — which meant the
 * warning protected nobody who had not already read it, and anything that could
 * write one file to `~/.ciphermesh/plugins` had code execution.
 *
 * Approval is recorded **per file name**, not per plugin name, and that is
 * forced rather than chosen: a plugin's own `name` is inside the module, and
 * reading it means importing the module, and importing it is already running
 * it. The check has to happen on something knowable from the directory listing.
 *
 * This is not a sandbox and is not presented as one. An approved plugin can do
 * everything the client can do. What it buys is that the decision is now made
 * by a person, once, per file — instead of by whatever put the file there.
 */
export class PluginManager {
  #plugins = new Map(); // name -> module
  #commands = new Map(); // '/cmd' -> { handler, pluginName }
  #pending = []; // files found but never approved
  #failed = []; // files approved that would not load

  /**
   * @param {string} dir
   * @param {string[]} allowed file names the user has approved, with or
   *   without the `.js` — `['roll']` and `['roll.js']` both mean the same file.
   */
  async loadAll(dir = pluginDir(), allowed = []) {
    this.#pending = [];
    this.#failed = [];

    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
      return;
    }

    let files;
    try {
      files = await readdir(dir);
    } catch {
      return;
    }

    const approved = new Set(
      (Array.isArray(allowed) ? allowed : [])
        .filter((entry) => typeof entry === 'string')
        .map((entry) => normalizeFileName(entry)),
    );

    for (const file of files.filter((f) => f.endsWith('.js'))) {
      if (!approved.has(normalizeFileName(file))) {
        this.#pending.push(file);
        continue; // NOT imported: importing is running.
      }
      // Sequential on purpose: plugins load once at startup, and a predictable
      // order means a command defined by two of them resolves the same way
      // every run.
      const loaded = await this.#load(dir, file);
      if (!loaded) {
        this.#failed.push(file);
      }
    }
  }

  /** Load one already-approved file. @returns {boolean} */
  async #load(dir, file) {
    try {
      const fileUrl = pathToFileURL(join(dir, file)).href;
      const mod = await import(fileUrl);
      const plugin = mod.default || mod;

      if (!plugin.name || !plugin.commands) {
        return false;
      }

      this.#plugins.set(plugin.name, plugin);

      for (const [cmdName, handler] of Object.entries(plugin.commands)) {
        const normalized = cmdName.startsWith('/')
          ? cmdName.toLowerCase()
          : `/${cmdName.toLowerCase()}`;
        this.#commands.set(normalized, { handler, pluginName: plugin.name });
      }
      return true;
    } catch {
      return false; // a broken plugin must never stop the client starting
    }
  }

  /**
   * Approve and load a file that was sitting in the directory unapproved.
   * The caller persists the name; this only affects the running session.
   */
  async approve(file, dir = pluginDir()) {
    const target = this.#pending.find((f) => normalizeFileName(f) === normalizeFileName(file));
    if (!target) {
      return false;
    }
    const loaded = await this.#load(dir, target);
    this.#pending = this.#pending.filter((f) => f !== target);
    if (!loaded) {
      this.#failed.push(target);
    }
    return loaded;
  }

  getCommandNames() {
    return [...this.#commands.keys()];
  }

  getPluginNames() {
    return [...this.#plugins.keys()];
  }

  /** Files present but never approved, so the client can offer them. */
  getPendingFiles() {
    return [...this.#pending];
  }

  /** Approved files that would not load — otherwise this fails silently. */
  getFailedFiles() {
    return [...this.#failed];
  }

  get pluginCount() {
    return this.#plugins.size;
  }

  handleCommand(cmd, args) {
    const entry = this.#commands.get(cmd.toLowerCase());
    if (!entry) {
      return null;
    }

    try {
      const result = entry.handler(args);
      return result || null;
    } catch {
      return null;
    }
  }
}

function normalizeFileName(name) {
  return name.toLowerCase().replace(/\.js$/, '').trim();
}
