# CipherMesh Plugin API

CipherMesh loads user plugins at startup from `~/.ciphermesh/plugins/*.js` and
routes unknown slash-commands to them. Plugins work in both relay and P2P mode.

## Quick start

```bash
mkdir -p ~/.ciphermesh/plugins
cp examples/plugins/roll.js examples/plugins/poll.js ~/.ciphermesh/plugins/
```

Restart the client — `/plugins` lists what loaded, and `/roll 2d20+3` /
`/poll Pizza tonight? | yes | obviously` just work.

## Plugin format

A plugin is an ES module whose **default export** is:

```js
export default {
  name: 'roll',                       // required, unique
  description: 'Roll dice',           // optional, shown by /plugins
  commands: {
    // key = command name (with or without the leading slash)
    roll(args) {
      // args: string[] — everything typed after the command, split on spaces
      return { send: '🎲 4' };
    },
  },
};
```

Files that fail to import, or lack `name`/`commands`, are skipped silently.

## Handler return values

| Return | Effect |
|--------|--------|
| `{ send: '<text>' }` | The text is **sent to the current room** as a normal end-to-end-encrypted message (and echoed locally). Markdown and multi-line text work. |
| `{ info: '<text>' }` | Shown **only locally** as an info line. |
| `'<text>'` (plain string) | Same as `{ info }` — the original API, still supported. |
| `null` / `undefined` / throw | Treated as "not handled": the user sees *Unknown command*. |

Handlers are synchronous — return the final value directly.

## Precedence and naming

Built-in commands always win: a plugin command named `/help` or `/join` is
never reached. Plugin commands are only tried when no built-in matches. If two
plugins register the same command, the one loaded last wins (load order is the
directory listing).

## Security model — read this

A plugin is **arbitrary JavaScript running inside your chat process**, with
your privileges and full access to your keys in memory. There is no sandbox.

- Only install plugins you wrote or read line-by-line.
- Treat a plugin file like you treat `curl | sh`.
- Plugins are never synced, auto-updated or downloaded by CipherMesh — the
  only way code gets into `~/.ciphermesh/plugins/` is you putting it there.

## Included examples

- [`examples/plugins/roll.js`](../examples/plugins/roll.js) — dice roller,
  D&D notation (`/roll 2d20+3`), result goes to the room.
- [`examples/plugins/poll.js`](../examples/plugins/poll.js) — quick poll
  (`/poll question | opt A | opt B`), voted with the built-in `/react`.
