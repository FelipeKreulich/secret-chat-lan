import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

/**
 * docs/ARCHITECTURE.md describes the code, so it can be wrong about it — and
 * silently, because nothing reads it. It had drifted a long way before anyone
 * noticed: the dependency table listed `play-sound`, which is not a dependency
 * at all, and omitted seven of the eleven that are; the directory tree named
 * `.eslintrc.js` and three test files that do not exist, listed 2 of the 27
 * modules under `src/shared/`, and called the project SecureLAN Chat.
 *
 * None of that is catchable by running the code. So the two parts of the
 * document that are pure fact — what the project depends on and what modules it
 * has — are checked against the real thing here, the way commands-json.test.js
 * checks the command list. The prose is still on the author.
 */
const doc = readFileSync(new URL('../docs/ARCHITECTURE.md', import.meta.url), 'utf8');
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

/** The package names listed in one markdown table. */
function tableEntries(heading) {
  const start = doc.indexOf(heading);
  assert.notEqual(start, -1, `${heading} is missing from ARCHITECTURE.md`);
  const body = doc.slice(start, doc.indexOf('###', start + heading.length));
  return [...body.matchAll(/^\|\s*\*\*([^*]+)\*\*\s*\|/gm)].map((m) => m[1].trim());
}

// The fenced block itself, not the whole section: the prose around it names
// this test file, and that is not a claim about the tree.
const treeBlock = (() => {
  const start = doc.indexOf('## 3. Directory Structure');
  assert.notEqual(start, -1, 'the directory structure section is missing');
  const open = doc.indexOf('```', start);
  const close = doc.indexOf('```', open + 3);
  assert.ok(open !== -1 && close !== -1, 'the directory tree is not in a code block');
  return doc.slice(open + 3, close);
})();

function modules(dir) {
  const root = new URL(`../src/${dir}/`, import.meta.url);
  return readdirSync(root).filter((name) => name.endsWith('.js'));
}

const AREAS = ['server', 'client', 'crypto', 'p2p', 'protocol', 'shared'];

describe('ARCHITECTURE.md matches the code', () => {
  // Only the package set, never the versions: those live in package.json, and
  // asserting a copy of them here would put a documentation edit in the way of
  // every Dependabot bump — a chore nobody does is how a guard gets deleted.
  test('the dependency table lists exactly the runtime dependencies', () => {
    const documented = tableEntries('### Production Dependencies');
    assert.deepEqual(
      [...documented].sort(),
      Object.keys(pkg.dependencies).sort(),
      'the table and package.json disagree — this is how play-sound survived in it',
    );
  });

  test('the dev dependency table matches too', () => {
    assert.deepEqual(
      [...tableEntries('### Development Dependencies')].sort(),
      Object.keys(pkg.devDependencies).sort(),
    );
  });

  test('the directory tree names every module under src/', () => {
    for (const area of AREAS) {
      for (const file of modules(area)) {
        assert.ok(
          treeBlock.includes(file),
          `src/${area}/${file} exists but the directory tree does not mention it`,
        );
      }
    }
  });

  test('the directory tree names no file that does not exist', () => {
    const real = new Set(AREAS.flatMap((area) => modules(area)));
    // Every `word.js` inside the tree block, minus the entries that are not
    // modules under src/ (the CLI, the generator script, config files).
    const NOT_MODULES = new Set([
      'ciphermesh.js',
      'generate-commands.mjs',
      'eslint.config.js',
      'package.json',
      'commands.json',
    ]);
    // The lookahead matters: without it `commands.json` yields `commands.js`.
    for (const match of treeBlock.matchAll(/([A-Za-z][\w.-]*\.m?js)(?![\w.-])/g)) {
      const name = match[1];
      if (NOT_MODULES.has(name)) continue;
      assert.ok(real.has(name), `the directory tree names ${name}, which does not exist`);
    }
  });

  test('the document is in English', () => {
    // Everything written into this repository is English (only the READMEs are
    // bilingual). Half of this file was not: the topology diagrams, the whole
    // cryptographic flow, the step-by-step scenario and the boot sequences.
    // The list is short and unambiguous on purpose — words that cannot appear
    // in an English sentence by accident.
    const PORTUGUESE = [
      'mensagem',
      'servidor',
      'usuario',
      'arquivo',
      'chave publica',
      'chave secreta',
      'conexao',
      'seguranca',
      'Cliente A',
      'Decifra',
    ];
    const found = PORTUGUESE.filter((word) => new RegExp(word, 'i').test(doc));
    assert.deepEqual(found, [], `ARCHITECTURE.md has Portuguese in it: ${found.join(', ')}`);
  });

  test('the project is called by its own name', () => {
    // It was still "SecureLAN Chat" three renames later.
    assert.ok(!/securelan/i.test(doc), 'ARCHITECTURE.md still says SecureLAN');
    assert.ok(doc.includes('CipherMesh'), 'ARCHITECTURE.md never names the project');
  });
});
