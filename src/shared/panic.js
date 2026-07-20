import { StateManager } from '../crypto/StateManager.js';

// Panic / duress wipe: securely delete every at-rest secret. Best-effort and
// never throws — under duress it must run to completion no matter what.
export function panicWipe({ historyStore, trustStore, auditLog } = {}) {
  const wiped = [];
  try {
    new StateManager().clearState(); // encrypted session state
    wiped.push('session');
  } catch {
    /* best effort */
  }
  try {
    if (historyStore) {
      historyStore.wipe();
      wiped.push('history');
    }
  } catch {
    /* best effort */
  }
  try {
    if (trustStore) {
      trustStore.wipe();
      wiped.push('trust');
    }
  } catch {
    /* best effort */
  }
  try {
    if (auditLog) {
      auditLog.wipe();
      wiped.push('audit');
    }
  } catch {
    /* best effort */
  }
  return wiped;
}
