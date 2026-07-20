import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Jimp } from 'jimp';
import { isImageFile, renderImagePreview } from '../src/client/ImagePreview.js';

describe('ImagePreview', () => {
  let dir;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ciphermesh-preview-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('isImageFile recognizes image extensions', () => {
    assert.equal(isImageFile('/tmp/photo.png'), true);
    assert.equal(isImageFile('/tmp/photo.JPG'), true);
    assert.equal(isImageFile('/tmp/doc.pdf'), false);
    assert.equal(isImageFile('/tmp/script.js'), false);
  });

  test('renders a 4x4 image in 2 rows of half-blocks', async () => {
    const path = join(dir, 'red.png');
    const image = new Jimp({ width: 4, height: 4, color: 0xff0000ff });
    await image.write(path);

    const lines = await renderImagePreview(path);
    assert.equal(lines.length, 2); // 4px tall / 2 per row
    assert.ok(lines[0].includes('▀'));
    assert.ok(lines[0].includes('{#ff0000-fg}'));
    assert.ok(lines[0].includes('{#ff0000-bg}'));
  });

  test('shrinks wide images to the column limit', async () => {
    const path = join(dir, 'wide.png');
    const image = new Jimp({ width: 200, height: 20, color: 0x00ff00ff });
    await image.write(path);

    const lines = await renderImagePreview(path, 40);
    // 200x20 becomes 40x4 (aspect ratio preserved) -> 2 rows
    assert.equal(lines.length, 2);
    const cells = lines[0].match(/▀/g);
    assert.equal(cells.length, 40);
  });

  test('odd height renders the last row with a half block', async () => {
    const path = join(dir, 'odd.png');
    const image = new Jimp({ width: 2, height: 3, color: 0x0000ffff });
    await image.write(path);

    const lines = await renderImagePreview(path);
    assert.equal(lines.length, 2);
    // last row has only the top pixel
    assert.ok(lines[1].includes('▀'));
    assert.ok(!lines[1].includes('-bg}'));
  });

  test('clean failure for a non-image file', async () => {
    await assert.rejects(() => renderImagePreview(join(dir, 'does-not-exist.png')));
  });
});
