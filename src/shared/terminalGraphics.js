// Detect and encode inline-image support for capable terminals (kitty / iTerm2).
// The half-block preview always works; these enable full-resolution rendering
// where the terminal supports a real graphics protocol.

/**
 * @returns {'kitty'|'iterm'|null}
 */
export function detectImageProtocol(env = process.env) {
  if (env.TERM === 'xterm-kitty' || env.KITTY_WINDOW_ID) {
    return 'kitty';
  }
  if (env.TERM_PROGRAM === 'iTerm.app' || env.LC_TERMINAL === 'iTerm2') {
    return 'iterm';
  }
  return null;
}

export function supportsTrueColor(env = process.env) {
  const ct = (env.COLORTERM || '').toLowerCase();
  if (ct === 'truecolor' || ct === '24bit') {
    return true;
  }
  return (env.TERM || '').includes('kitty') || env.TERM_PROGRAM === 'iTerm.app';
}

/**
 * iTerm2 inline image escape. Accepts raw image bytes of any format.
 * @param {Buffer} buffer
 * @param {{ widthCells?: number }} [opts]
 */
export function encodeITermImage(buffer, opts = {}) {
  const args = ['inline=1', `size=${buffer.length}`, 'preserveAspectRatio=1'];
  if (opts.widthCells) {
    args.push(`width=${opts.widthCells}`);
  }
  return `\x1b]1337;File=${args.join(';')}:${buffer.toString('base64')}\x07`;
}

/**
 * kitty graphics protocol escape. Requires a PNG buffer (f=100), chunked so no
 * single escape exceeds the protocol limit.
 * @param {Buffer} pngBuffer
 */
export function encodeKittyImage(pngBuffer) {
  const b64 = pngBuffer.toString('base64');
  const CHUNK = 4096;
  let out = '';
  for (let i = 0; i < b64.length; i += CHUNK) {
    const chunk = b64.slice(i, i + CHUNK);
    const more = i + CHUNK < b64.length ? 1 : 0;
    const control = i === 0 ? `f=100,a=T,m=${more}` : `m=${more}`;
    out += `\x1b_G${control};${chunk}\x1b\\`;
  }
  return out;
}

/**
 * Build the inline-image escape for the detected protocol.
 * @param {'kitty'|'iterm'} protocol
 * @param {{ raw: Buffer, png: Buffer }} images - raw bytes and a PNG re-encoding
 * @param {{ widthCells?: number }} [opts]
 * @returns {string|null}
 */
export function encodeInlineImage(protocol, images, opts = {}) {
  if (protocol === 'iterm') {
    return encodeITermImage(images.raw, opts);
  }
  if (protocol === 'kitty') {
    return encodeKittyImage(images.png);
  }
  return null;
}
