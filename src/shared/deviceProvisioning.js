// ── Provisioning a second device ────────────────────────────────
//
// Step 5 of multi-device (docs/design/multi-device.md, item 4 of #481).
//
// **The identity secret never moves.** A second device generates its own box
// keypair and receives only the identity's *public* key plus a device list
// signed by it. That costs one thing and buys two: a secondary cannot add or
// revoke devices — only the device holding the identity secret can — and a
// stolen phone is a stolen phone rather than a stolen identity. Today's
// `/backup` does the opposite, copying the whole identity, which is the
// configuration this arc exists to replace.
//
// Because neither side can sign for the other, provisioning is two hops and
// there is no way around that: the new device has to say what its key is before
// the identity can sign for it, and it has to be told what identity it now
// belongs to afterwards.
//
//   B: /device request        → ciphermesh-device://request/…   (~150 bytes)
//   A: /device add <request>  → ciphermesh-device://grant/…     (~740 bytes)
//   B: /device accept <grant>
//
// A byte-mode QR code holds about 2 200 characters, so both fit with room for
// more devices. Neither is secret: a request is a public key, and a grant is a signed statement that
// was going to be broadcast to every peer anyway. Interception achieves
// nothing; substitution is caught, because a grant only applies if it names the
// exact device that asked.

const SCHEME = 'ciphermesh-device://';
const MAX_ENCODED = 8192; // a grant with the maximum eight devices, with room

const DEVICE_ID = /^[0-9a-f]{32}$/;

function encode(kind, body) {
  const json = Buffer.from(JSON.stringify(body), 'utf-8');
  return `${SCHEME}${kind}/${json.toString('base64url')}`;
}

function decode(kind, text) {
  if (typeof text !== 'string') {
    return null;
  }
  const prefix = `${SCHEME}${kind}/`;
  if (!text.startsWith(prefix) || text.length > MAX_ENCODED) {
    return null;
  }
  try {
    const parsed = JSON.parse(
      Buffer.from(text.slice(prefix.length), 'base64url').toString('utf-8'),
    );
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * What a new device says about itself: the two fields the identity has to sign
 * over. Nothing secret, and nothing the peer could not have learned anyway.
 */
export function buildDeviceRequest({ deviceId, boxPk, label = '' }) {
  if (!DEVICE_ID.test(deviceId ?? '') || typeof boxPk !== 'string' || boxPk.length === 0) {
    return null;
  }
  return encode('request', { deviceId, boxPk, label: String(label).slice(0, 32) });
}

/** @returns {{deviceId: string, boxPk: string, label: string}|null} */
export function parseDeviceRequest(text) {
  const body = decode('request', text);
  if (!body || !DEVICE_ID.test(body.deviceId ?? '')) {
    return null;
  }
  if (typeof body.boxPk !== 'string' || body.boxPk.length === 0) {
    return null;
  }
  if (body.label !== undefined && typeof body.label !== 'string') {
    return null;
  }
  return { deviceId: body.deviceId, boxPk: body.boxPk, label: body.label ?? '' };
}

/**
 * What the identity hands back: which identity this device now belongs to, and
 * the signed list saying so.
 *
 * The identity key is in here as well as inside the list because the receiving
 * device has no other way to learn it — and it is checked against the list's
 * own `identityPk` on the way in, so the two cannot disagree.
 */
export function buildDeviceGrant({ identityPk, list }) {
  if (typeof identityPk !== 'string' || !list || typeof list !== 'object') {
    return null;
  }
  return encode('grant', { identityPk, list });
}

/** @returns {{identityPk: string, list: object}|null} */
export function parseDeviceGrant(text) {
  const body = decode('grant', text);
  if (!body || typeof body.identityPk !== 'string') {
    return null;
  }
  if (!body.list || typeof body.list !== 'object' || Array.isArray(body.list)) {
    return null;
  }
  // A grant whose envelope disagrees with the list it carries is malformed, not
  // a decision to make later.
  if (body.list.identityPk !== body.identityPk) {
    return null;
  }
  return { identityPk: body.identityPk, list: body.list };
}
