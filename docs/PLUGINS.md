# CipherMesh Plugin API

CipherMesh loads user plugins from `~/.ciphermesh/plugins/*.js` and routes
unknown slash-commands to them. Plugins work in both relay and P2P mode.

**Nothing there runs until you say so.** A file in that directory is found, not
loaded. Run `/plugins` to see what is waiting and `/plugins allow <file>` to
approve it — the approval is remembered in `~/.ciphermesh/config.json` under
`pluginsAllowed`, so you are asked once per file.

## Quick start

```bash
mkdir -p ~/.ciphermesh/plugins
cp examples/plugins/roll.js examples/plugins/poll.js ~/.ciphermesh/plugins/
```

Then in the client:

```
/plugins              → shows roll.js and poll.js waiting
/plugins allow roll   → approved, loaded, and remembered
/plugins allow poll
```

Now `/roll 2d20+3` and `/poll Pizza tonight? | yes | obviously` work.

## Plugin format

A plugin is an ES module whose **default export** is:

```js
export default {
  name: 'roll', // required, unique
  description: 'Roll dice', // optional, shown by /plugins
  commands: {
    // key = command name (with or without the leading slash)
    roll(args) {
      // args: string[] — everything typed after the command, split on spaces
      return { send: '🎲 4' };
    },
  },
};
```

A file that fails to import, or lacks `name`/`commands`, is skipped — but if you
approved it, `/plugins` says so. A plugin you asked for and did not get should
not disappear without a word.

## Handler return values

| Return                       | Effect                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `{ send: '<text>' }`         | The text is **sent to the current room** as a normal end-to-end-encrypted message (and echoed locally). Markdown and multi-line text work. |
| `{ info: '<text>' }`         | Shown **only locally** as an info line.                                                                                                    |
| `'<text>'` (plain string)    | Same as `{ info }` — the original API, still supported.                                                                                    |
| `null` / `undefined` / throw | Treated as "not handled": the user sees _Unknown command_.                                                                                 |

Handlers are synchronous — return the final value directly.

## Precedence and naming

Built-in commands always win: a plugin command named `/help` or `/join` is
never reached. Plugin commands are only tried when no built-in matches. If two
plugins register the same command, the one loaded last wins (load order is the
directory listing).

## Security model — read this

A plugin is **arbitrary JavaScript running inside your chat process**, with
your privileges and full access to your keys in memory. There is no sandbox,
and approving one does not create one.

- Only install plugins you wrote or read line-by-line.
- Treat a plugin file like you treat `curl | sh`.
- Plugins are never synced, auto-updated or downloaded by CipherMesh — the
  only way code gets into `~/.ciphermesh/plugins/` is you putting it there.

### What approval actually buys

Before, any `.js` file appearing in that directory ran at the next start. The
warning above protected only the people who had already read it, and anything
able to write one file into a known path had code execution.

Now the file is listed and left alone until you approve it. That is the whole
guarantee, and it is worth being precise about its edges:

- **It is a consent step, not a sandbox.** An approved plugin can do everything
  the client can do. Approve for the same reasons you would run a script.
- **Approval is per _file name_, not per plugin name.** That is forced, not
  chosen: a plugin's own `name` lives inside the module, and reading it means
  importing the module, and importing it is already running it. The check has
  to work from the directory listing alone.
- **Replacing an approved file is not a new decision.** `roll.js` stays
  approved even if its contents change completely. If you did not put the new
  contents there, you have a bigger problem than plugins — but do not read the
  approval as a promise about what the file contains.

There is no capability system, deliberately. Declaring what a plugin may do
without being able to enforce it would make the risk look bounded when it is
not, which is worse than the plain warning above.

## Included examples

- [`examples/plugins/roll.js`](../examples/plugins/roll.js) — dice roller,
  D&D notation (`/roll 2d20+3`), result goes to the room.
- [`examples/plugins/poll.js`](../examples/plugins/poll.js) — quick poll
  (`/poll question | opt A | opt B`), voted with the built-in `/react`.
