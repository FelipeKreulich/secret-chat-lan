// CipherMesh example plugin: quick poll voted with reactions.
// Install: cp poll.js ~/.ciphermesh/plugins/
const NUMBERS = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣'];

export default {
  name: 'poll',
  description: 'Create a poll: /poll <question> | <option> | <option> [| …]',
  commands: {
    poll(args) {
      const raw = args.join(' ');
      if (!raw.includes('|')) {
        return { info: 'Usage: /poll <question> | <option> | <option> [| …]' };
      }
      const [question, ...options] = raw
        .split('|')
        .map((s) => s.trim())
        .filter(Boolean);
      if (!question || options.length < 2 || options.length > NUMBERS.length) {
        return { info: `A poll needs a question and 2-${NUMBERS.length} options.` };
      }
      const lines = [`📊 **${question}**`];
      options.forEach((opt, i) => lines.push(`${NUMBERS[i]} ${opt}`));
      lines.push(`Vote by reacting — e.g. /react ${NUMBERS[0]}`);
      // `send` → delivered to the whole room as a normal E2EE message.
      return { send: lines.join('\n') };
    },
  },
};
