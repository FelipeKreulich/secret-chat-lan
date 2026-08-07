import { loadConfig, saveConfig } from './config.js';

/**
 * `/plugins` for both controllers.
 *
 * Written once and shared because the relay client and the P2P client had
 * separate copies of it, and separate copies of a command drift — one gains a
 * subcommand the other never hears about, and the two `/help` lists stop
 * describing the same program.
 *
 * Returns lines rather than printing, so each controller renders them with its
 * own UI and the logic stays testable without a terminal.
 *
 * @returns {Promise<Array<{kind: 'info'|'error'|'system', text: string}>>}
 */
export async function pluginsCommand(manager, args = []) {
  if (!manager) {
    // Same words as an empty directory. From where the user sits the situation
    // is identical — there is nothing to run — and "not available" would send
    // them looking for a fault that is not theirs.
    return [{ kind: 'info', text: 'No plugins. Put .js files in ~/.ciphermesh/plugins/' }];
  }

  const [sub, target] = args;

  if (sub && sub.toLowerCase() === 'allow') {
    return approve(manager, target);
  }

  if (sub) {
    return [{ kind: 'error', text: 'Usage: /plugins  or  /plugins allow <file>' }];
  }

  return status(manager);
}

function status(manager) {
  const lines = [];
  const loaded = manager.getPluginNames();
  const pending = manager.getPendingFiles();
  const failed = manager.getFailedFiles();

  if (loaded.length > 0) {
    lines.push({ kind: 'info', text: `Plugins loaded (${loaded.length}): ${loaded.join(', ')}` });
    const cmds = manager.getCommandNames();
    if (cmds.length > 0) {
      lines.push({ kind: 'info', text: `Commands: ${cmds.join(', ')}` });
    }
  } else if (pending.length === 0) {
    lines.push({ kind: 'info', text: 'No plugins. Put .js files in ~/.ciphermesh/plugins/' });
  }

  if (pending.length > 0) {
    // Deliberately blunt. A plugin is not an extension in a browser sandbox: it
    // is code in this process, next to the keys, and the person approving it
    // should be told that in the same breath as being told how.
    lines.push({
      kind: 'error',
      text: `Not running (${pending.length}): ${pending.join(', ')}`,
    });
    lines.push({
      kind: 'info',
      text: 'A plugin runs inside this process and can do anything the client can — including reading your keys in memory. Approve one only if you wrote it or read it.',
    });
    lines.push({
      kind: 'info',
      text: `Approve with /plugins allow ${pending[0].replace(/\.js$/, '')}`,
    });
  }

  if (failed.length > 0) {
    lines.push({
      kind: 'error',
      text: `Approved but would not load: ${failed.join(', ')}`,
    });
  }

  return lines;
}

async function approve(manager, file) {
  if (!file) {
    return [{ kind: 'error', text: 'Usage: /plugins allow <file>' }];
  }

  const loaded = await manager.approve(file);
  if (!loaded) {
    return [
      {
        kind: 'error',
        text: `No unapproved plugin called "${file}". Run /plugins to see what is there.`,
      },
    ];
  }

  // Persisted only after it actually loaded, so a broken file does not end up
  // permanently on the approved list.
  const config = loadConfig();
  const allowed = new Set(config.pluginsAllowed || []);
  allowed.add(file.replace(/\.js$/, ''));
  saveConfig({ pluginsAllowed: [...allowed] });

  return [
    { kind: 'system', text: `${file} approved and loaded. It will load on its own from now on.` },
  ];
}
