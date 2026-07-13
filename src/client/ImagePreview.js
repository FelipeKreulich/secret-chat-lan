import { extname } from 'node:path';
import { Jimp } from 'jimp';

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.bmp']);
const MAX_PREVIEW_WIDTH = 48; // colunas
const MAX_PREVIEW_HEIGHT = 96; // pixels (2 por linha de terminal)

export function isImageFile(filePath) {
  return IMAGE_EXTENSIONS.has(extname(filePath).toLowerCase());
}

/**
 * Render an image as terminal half-blocks with blessed color tags.
 * Each cell packs two vertical pixels: '▀' with fg = top pixel and
 * bg = bottom pixel. Returns one string per terminal row.
 * @param {string} filePath
 * @param {number} [maxWidth] - max columns
 * @returns {Promise<string[]>}
 */
export async function renderImagePreview(filePath, maxWidth = MAX_PREVIEW_WIDTH) {
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
      return null; // transparente
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
