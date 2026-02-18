import blessed from 'blessed';
import { writeFileSync, appendFileSync } from 'node:fs';

const LOG = 'key-debug.log';
writeFileSync(LOG, '');

const screen = blessed.screen({ smartCSR: true });

const box = blessed.box({
  parent: screen,
  top: 0,
  left: 0,
  width: '100%',
  height: '100%',
  content: 'Pressione teclas. Resultados vao para key-debug.log\nCtrl+C para sair.',
});

let count = 0;

// Listener 1: program level
screen.program.on('keypress', (ch, key) => {
  count++;
  const line = `[${count}] program.keypress | ch=${JSON.stringify(ch)} name=${key?.name} full=${key?.full} seq=${JSON.stringify(key?.sequence)} time=${performance.now().toFixed(2)}\n`;
  appendFileSync(LOG, line);
  box.setContent(`Eventos: ${count}\nUltimo: ${key?.full || ch}\nVeja key-debug.log`);
  screen.render();
});

// Listener 2: screen level
screen.on('keypress', (ch, key) => {
  count++;
  const line = `[${count}] screen.keypress  | ch=${JSON.stringify(ch)} name=${key?.name} full=${key?.full} seq=${JSON.stringify(key?.sequence)} time=${performance.now().toFixed(2)}\n`;
  appendFileSync(LOG, line);
});

screen.key(['C-c'], () => process.exit(0));
screen.render();
