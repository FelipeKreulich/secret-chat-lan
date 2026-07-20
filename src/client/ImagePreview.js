import { extname } from 'node:path';
import { readFileSync } from 'node:fs';
import { Jimp } from 'jimp';

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.bmp']);
const MAX_PREVIEW_HEIGHT = 96; // pixels (2 per terminal row)
const INLINE_MAX_WIDTH = 1000; // pixels — cap for full-resolution inline render

// Fit the half-block preview to the terminal (leaving room for the border),
// with a sane cap.
function previewWidth() {
  const cols = process.stdout.columns || 80;
  return Math.max(24, Math.min(64, cols - 6));
}

export function isImageFile(filePath) {
  return IMAGE_EXTENSIONS.has(extname(filePath).toLowerCase());
}

/**
 * Load an image as { raw, png } buffers for inline (kitty/iTerm) rendering.
 * Large images are downscaled so the escape stays reasonable.
 * @param {string} filePath
 * @returns {Promise<{ raw: Buffer, png: Buffer }>}
 */
export async function loadImageBuffers(filePath) {
  const raw = readFileSync(filePath);
  const image = await Jimp.read(filePath);
  if (image.width > INLINE_MAX_WIDTH) {
    image.resize({ w: INLINE_MAX_WIDTH });
  }
  const png = await image.getBuffer('image/png');
  return { raw, png };
}

/**
 * Render an image as terminal half-blocks with blessed color tags.
 * Each cell packs two vertical pixels: '▀' with fg = top pixel and
 * bg = bottom pixel. Returns one string per terminal row.
 * @param {string} filePath
 * @param {number} [maxWidth] - max columns
 * @returns {Promise<string[]>}
 */
export async function renderImagePreview(filePath, maxWidth = previewWidth()) {
  const image = await Jimp.read(filePath);

  if (image.width > maxWidth) {
    image.resize({ w: maxWidth });
  }
  if (image.height > MAX_PREVIEW_HEIGHT) {
    image.resize({ h: MAX_PREVIEW_HEIGHT });
  }

  const { width, height } = image;
  const { data } = image.bitmap;

  const px = (x, y) => {
    const i = (y * width + x) * 4;
    if (data[i + 3] < 128) {
      return null; // transparent
    }
    return `#${data[i].toString(16).padStart(2, '0')}${data[i + 1]
      .toString(16)
      .padStart(2, '0')}${data[i + 2].toString(16).padStart(2, '0')}`;
  };

  const lines = [];
  for (let y = 0; y < height; y += 2) {
    let line = '';
    for (let x = 0; x < width; x++) {
      const top = px(x, y);
      const bottom = y + 1 < height ? px(x, y + 1) : null;

      if (!top && !bottom) {
        line += ' ';
      } else if (top && bottom) {
        line += `{${top}-fg}{${bottom}-bg}▀{/${bottom}-bg}{/${top}-fg}`;
      } else if (top) {
        line += `{${top}-fg}▀{/${top}-fg}`;
      } else {
        line += `{${bottom}-fg}▄{/${bottom}-fg}`;
      }
    }
    lines.push(line);
  }

  return lines;
}
