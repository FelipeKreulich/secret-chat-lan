import { EMOJI_MAP } from './constants.js';

const SHORTCODE_REGEX = /:([a-z0-9_+-]+):/g;

/**
 * Replace :shortcode: occurrences with their emoji. Unknown codes stay as-is.
 */
export function applyShortcodes(text) {
  return text.replace(SHORTCODE_REGEX, (match) => EMOJI_MAP[match] || match);
}

/**
 * Shortcodes starting with the given prefix (prefix includes the leading ':').
 */
export function shortcodeSuggestions(prefix) {
  return Object.keys(EMOJI_MAP).filter((code) => code.startsWith(prefix));
}
