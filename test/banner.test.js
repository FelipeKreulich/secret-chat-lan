import { test, describe } from 'node:test';
import assert from 'node:assert';
import { LOGO_ART } from '../src/shared/banner.js';

describe('banner art', () => {
  test('matches what figlet produces for ANSI Shadow', async () => {
    // The art is embedded instead of generated because figlet reads its font
    // from disk, which a compiled binary cannot do — it died on
    // `ENOENT: /$bunfs/fonts/ANSI Shadow.flf` before printing anything.
    //
    // figlet stays a devDependency purely so this test can prove the constant
    // is still the real thing. If it ever drifts, this fails and the change has
    // to be a decision rather than an accident.
    const { default: figlet } = await import('figlet');
    const generated = figlet.textSync('CipherMesh', { font: 'ANSI Shadow' });

    assert.equal(LOGO_ART, generated);
  });

  test('keeps the blank seventh line the animations count on', () => {
    // Both animated banners move the cursor back up by the number of lines.
    // Trimming figlet's trailing blank row looks harmless and shifts every
    // redraw by one, which is exactly the kind of thing nobody notices in a
    // diff.
    const lines = LOGO_ART.split('\n');
    assert.equal(lines.length, 7);
    assert.equal(lines[6].trim(), '');
    for (const line of lines) assert.equal(line.length, 78);
  });

  test('carries no characters that break a source string', () => {
    // Embedding art in source is only safe while it stays free of backticks,
    // backslashes and template-literal syntax.
    assert.ok(!/[`\\]/.test(LOGO_ART));
    assert.ok(!LOGO_ART.includes('${'));
  });

  test('does not read anything from disk', async () => {
    // The whole point of #414: importing the banner must not touch the
    // filesystem, or the binary dies on startup again.
    const banner = await import('../src/shared/banner.js');
    assert.equal(typeof banner.LOGO_ART, 'string');
    assert.ok(banner.LOGO_ART.includes('██████╗'));
  });
});
