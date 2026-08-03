// Makes blessed bundleable, so the TUI client can ship as a binary.
//
// blessed loads its widgets with `require('./widgets/' + file)` — a computed
// specifier, and the one thing in the whole dependency tree that no bundler can
// follow. The result was `Cannot find module './widgets/node'` at runtime and,
// for a long time, "the client cannot be bundled" (issue #328).
//
// The names it loads are a fixed list in blessed's own source and the directory
// has exactly one file per name, so the loop can be replaced with a table of
// static requires that a bundler resolves at build time. Nothing about
// blessed's behaviour changes: the same modules end up on the same properties.
//
// This edits node_modules, which is deliberate — it must not be committed, and
// it runs right before `bun build --compile` in CI, after `npm ci`. Running it
// twice is harmless.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

const WIDGET_JS = 'node_modules/blessed/lib/widget.js';
const WIDGET_DIR = 'node_modules/blessed/lib/widgets';
const MARKER = '_widgets = {';

const source = readFileSync(WIDGET_JS, 'utf-8');

if (source.includes(MARKER)) {
  process.stdout.write('blessed already patched\n');
  process.exit(0);
}

const files = readdirSync(WIDGET_DIR)
  .filter((f) => f.endsWith('.js'))
  .map((f) => f.replace(/\.js$/, ''))
  .sort();

if (files.length === 0) {
  process.stderr.write(`No widgets found in ${WIDGET_DIR}\n`);
  process.exit(1);
}

const table = `var _widgets = {\n${files
  .map((f) => `  '${f}': require('./widgets/${f}')`)
  .join(',\n')}\n};\n`;

const loop = /widget\.classes\.forEach\(function\(name\) \{[\s\S]*?\}\);/;

if (!loop.test(source)) {
  // blessed changed shape. Failing loudly beats producing a binary that dies
  // the first time someone opens a chat window.
  process.stderr.write(`Could not find the widget loader in ${WIDGET_JS}\n`);
  process.exit(1);
}

const patched = source.replace(
  loop,
  `${table}
widget.classes.forEach(function(name) {
  var file = name.toLowerCase();
  widget[name] = widget[file] = _widgets[file];
});`,
);

writeFileSync(WIDGET_JS, patched);
process.stdout.write(`blessed patched: ${files.length} widgets required statically\n`);
