// Selectable colour themes for per-user nick colours. Each palette is a list of
// blessed colour tokens (named colours or #hex). The banner keeps the neon
// brand; themes affect the ongoing message colours, which is what you actually
// look at all session.

export const THEMES = {
  neon: ['cyan', 'green', 'magenta', 'yellow', 'red'],
  matrix: ['green', '#00ff41', '#39ff14', '#7fff00', '#00c853'],
  mono: ['white', '#bbbbbb', '#888888', '#dddddd', '#00b8ff'],
  sunset: ['red', 'yellow', 'magenta', '#ff7b00', '#ff2d95'],
  ocean: ['cyan', 'blue', '#00b8ff', '#4cc9f0', '#7b2dff'],
};

const DEFAULT = 'neon';
let active = DEFAULT;

/** Set the active theme by name; ignores unknown names. Returns the active name. */
export function setTheme(name) {
  if (typeof name === 'string' && Object.prototype.hasOwnProperty.call(THEMES, name)) {
    active = name;
  }
  return active;
}

export function getThemeName() {
  return active;
}

/** The active palette (array of colour tokens). */
export function nickPalette() {
  return THEMES[active];
}

export function themeNames() {
  return Object.keys(THEMES);
}
