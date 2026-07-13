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

  test('isImageFile reconhece extensoes de imagem', () => {
    assert.equal(isImageFile('/tmp/foto.png'), true);
    assert.equal(isImageFile('/tmp/foto.JPG'), true);
    assert.equal(isImageFile('/tmp/doc.pdf'), false);
    assert.equal(isImageFile('/tmp/script.js'), false);
  });

  test('renderiza imagem 4x4 em 2 linhas de half-blocks', async () => {
    const path = join(dir, 'red.png');
    const image = new Jimp({ width: 4, height: 4, color: 0xff0000ff });
    await image.write(path);

    const lines = await renderImagePreview(path);
    assert.equal(lines.length, 2); // 4px de altura / 2 por linha
    assert.ok(lines[0].includes('▀'));
    assert.ok(lines[0].includes('{#ff0000-fg}'));
    assert.ok(lines[0].includes('{#ff0000-bg}'));
  });

  test('reduz imagens largas para o limite de colunas', async () => {
    const path = join(dir, 'wide.png');
    const image = new Jimp({ width: 200, height: 20, color: 0x00ff00ff });
    await image.write(path);

    const lines = await renderImagePreview(path, 40);
    // 200x20 vira 40x4 (proporcao mantida) -> 2 linhas
    assert.equal(lines.length, 2);
    const cells = lines[0].match(/▀/g);
    assert.equal(cells.length, 40);
  });

  test('altura impar rende ultima linha com meio bloco', async () => {
    const path = join(dir, 'odd.png');
    const image = new Jimp({ width: 2, height: 3, color: 0x0000ffff });
    await image.write(path);

    const lines = await renderImagePreview(path);
    assert.equal(lines.length, 2);
    // ultima linha tem so pixel de cima
    assert.ok(lines[1].includes('▀'));
    assert.ok(!lines[1].includes('-bg}'));
  });

  test('falha limpa para arquivo que nao e imagem', async () => {
    await assert.rejects(() => renderImagePreview(join(dir, 'nao-existe.png')));
  });
});
