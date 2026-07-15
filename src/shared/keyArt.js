// Deterministic "randomart" for a key — the OpenSSH "drunken bishop" walk.
// A bishop starts at the center of a 17x9 board and moves diagonally, one step
// per 2-bit pair of the input bytes, incrementing a counter at each cell. The
// resulting density map is drawn with coin characters. Same key → same picture,
// so a changed key produces a visibly different picture (MITM detection aid).

const WIDTH = 17;
const HEIGHT = 9;
const COINS = ' .o+=*BOX@%&#/^'; // index = visit count (clamped)

/**
 * @param {Buffer|Uint8Array} bytes - key material (e.g. the 32-byte public key)
 * @param {string} [title] - short label centered on the top border
 * @returns {string} multi-line box, 11 lines of 19 chars
 */
export function keyArt(bytes, title = '') {
  const field = Array.from({ length: HEIGHT }, () => new Array(WIDTH).fill(0));

  const startX = Math.floor(WIDTH / 2);
  const startY = Math.floor(HEIGHT / 2);
  let x = startX;
  let y = startY;

  for (const byte of bytes) {
    let b = byte;
    for (let i = 0; i < 4; i++) {
      x += b & 0x1 ? 1 : -1; // bit 0 → right / left
      y += b & 0x2 ? 1 : -1; // bit 1 → down / up
      x = Math.max(0, Math.min(WIDTH - 1, x));
      y = Math.max(0, Math.min(HEIGHT - 1, y));
      field[y][x] += 1;
      b >>= 2;
    }
  }

  const lines = [border(title), ...rows(field, startX, startY, x, y), border('')];
  return lines.join('\n');
}

function border(title) {
  if (!title) {
    return `+${'-'.repeat(WIDTH)}+`;
  }
  const label = `[${title.slice(0, WIDTH - 2)}]`;
  const pad = WIDTH - label.length;
  const left = Math.floor(pad / 2);
  return `+${'-'.repeat(left)}${label}${'-'.repeat(pad - left)}+`;
}

function rows(field, startX, startY, endX, endY) {
  const out = [];
  for (let j = 0; j < HEIGHT; j++) {
    let row = '|';
    for (let i = 0; i < WIDTH; i++) {
      if (i === startX && j === startY) {
        row += 'S';
      } else if (i === endX && j === endY) {
        row += 'E';
      } else {
        row += COINS[Math.min(field[j][i], COINS.length - 1)];
      }
    }
    out.push(`${row}|`);
  }
  return out;
}
