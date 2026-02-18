const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };

const currentLevel = LEVELS[process.env.LOG_LEVEL?.toLowerCase()] ?? LEVELS.info;

function timestamp() {
  return new Date().toLocaleTimeString('pt-BR', { hour12: false });
}

function format(level, module, message) {
  return `[${timestamp()}] [${level.toUpperCase().padEnd(5)}] [${module}] ${message}`;
}

function createLogger(module) {
  return {
    debug: (msg) => {
      if (currentLevel <= LEVELS.debug) {
        console.log(format('debug', module, msg));
      }
    },
    info: (msg) => {
      if (currentLevel <= LEVELS.info) {
        console.log(format('info', module, msg));
      }
    },
    warn: (msg) => {
      if (currentLevel <= LEVELS.warn) {
        console.warn(format('warn', module, msg));
      }
    },
    error: (msg) => {
      if (currentLevel <= LEVELS.error) {
        console.error(format('error', module, msg));
      }
    },
  };
}

export { createLogger };
