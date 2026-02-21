import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { existsSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const PLUGIN_DIR = join(homedir(), '.ciphermesh', 'plugins');

export class PluginManager {
  #plugins; // Map<name, module>
  #commands; // Map<cmdName, handler>

  constructor() {
    this.#plugins = new Map();
    this.#commands = new Map();
  }

  async loadAll() {
    if (!existsSync(PLUGIN_DIR)) {
      mkdirSync(PLUGIN_DIR, { recursive: true });
      return;
    }

    let files;
    try {
      files = await readdir(PLUGIN_DIR);
    } catch {
      return;
    }

    const jsFiles = files.filter((f) => f.endsWith('.js'));

    for (const file of jsFiles) {
      try {
        const filePath = join(PLUGIN_DIR, file);
        const fileUrl = pathToFileURL(filePath).href;
        const mod = await import(fileUrl);
        const plugin = mod.default || mod;

        if (!plugin.name || !plugin.commands) {
          continue;
        }

        this.#plugins.set(plugin.name, plugin);

        for (const [cmdName, handler] of Object.entries(plugin.commands)) {
          const normalized = cmdName.startsWith('/') ? cmdName.toLowerCase() : `/${cmdName.toLowerCase()}`;
          this.#commands.set(normalized, { handler, pluginName: plugin.name });
        }
      } catch {
        // Skip broken plugins silently
      }
    }
  }

  getCommandNames() {
    return [...this.#commands.keys()];
  }

  getPluginNames() {
    return [...this.#plugins.keys()];
  }

  get pluginCount() {
    return this.#plugins.size;
  }

  handleCommand(cmd, args) {
    const entry = this.#commands.get(cmd.toLowerCase());
    if (!entry) return null;

    try {
      const result = entry.handler(args);
      return result || null;
    } catch {
      return null;
    }
  }
}
