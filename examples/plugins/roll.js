// CipherMesh example plugin: dice roller (D&D notation).
// Install: cp roll.js ~/.ciphermesh/plugins/
export default {
  name: 'roll',
  description: 'Roll dice: /roll [NdM+K] — e.g. /roll, /roll d20, /roll 2d20+3',
  commands: {
    roll(args) {
      const spec = (args[0] || 'd6').toLowerCase();
      const m = spec.match(/^(\d{0,2})d(\d{1,4})([+-]\d{1,4})?$/);
      if (!m) {
        return { info: 'Usage: /roll [NdM(+K)] — e.g. /roll 2d20+3' };
      }
      const count = Math.min(parseInt(m[1] || '1', 10) || 1, 20);
      const sides = Math.max(2, parseInt(m[2], 10));
      const modifier = parseInt(m[3] || '0', 10);
      const rolls = Array.from({ length: count }, () => 1 + Math.floor(Math.random() * sides));
      const total = rolls.reduce((a, b) => a + b, 0) + modifier;
      const detail =
        count > 1 || modifier ? ` (${rolls.join(' + ')}${modifier ? ` ${m[3]}` : ''})` : '';
      // `send` → delivered to the whole room as a normal E2EE message.
      return { send: `🎲 rolled ${spec}: **${total}**${detail}` };
    },
  },
};
