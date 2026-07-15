/**
 * Ask a question on a readline interface WITHOUT echoing the typed characters
 * (for passphrases). Uses the standard readline `_writeToOutput` override so it
 * composes with an existing readline/promises interface.
 *
 * @param {import('node:readline/promises').Interface} rl
 * @param {string} query - prompt text (shown once)
 * @returns {Promise<string>} the typed answer
 */
export function questionHidden(rl, query) {
  const original = rl._writeToOutput?.bind(rl);
  let promptShown = false;

  rl._writeToOutput = (str) => {
    if (!promptShown) {
      // The first write is the prompt itself — show it, then mask the rest.
      rl.output.write(query);
      promptShown = true;
      return;
    }
    // Preserve line breaks (so the cursor advances on Enter), swallow the
    // character echoes so the passphrase never appears on screen.
    if (str.includes('\n') || str.includes('\r')) {
      rl.output.write('\n');
    }
  };

  return rl.question(query).finally(() => {
    rl._writeToOutput = original;
  });
}
