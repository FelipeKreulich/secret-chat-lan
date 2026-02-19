import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, createSign, createHash } from 'node:crypto';
import { createLogger } from '../shared/logger.js';

const log = createLogger('cert');

const CERT_DIR = join(process.cwd(), 'certs');
const KEY_PATH = join(CERT_DIR, 'server.key');
const CERT_PATH = join(CERT_DIR, 'server.cert');

/**
 * Load or auto-generate self-signed TLS certificates.
 * @returns {{ key: Buffer, cert: Buffer }}
 */
export function loadOrGenerateCerts() {
  if (existsSync(KEY_PATH) && existsSync(CERT_PATH)) {
    log.info('Certificados TLS carregados de certs/');
    return {
      key: readFileSync(KEY_PATH),
      cert: readFileSync(CERT_PATH),
    };
  }

  log.info('Gerando certificado TLS auto-assinado...');

  if (!existsSync(CERT_DIR)) {
    mkdirSync(CERT_DIR, { recursive: true });
  }

  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const cert = createSelfSignedCert(publicKey, privateKey);

  writeFileSync(KEY_PATH, privateKey);
  writeFileSync(CERT_PATH, cert);

  log.info('Certificado TLS auto-assinado gerado em certs/');
  return { key: Buffer.from(privateKey), cert: Buffer.from(cert) };
}

/**
 * Create a minimal self-signed X.509 certificate in PEM format.
 */
function createSelfSignedCert(publicKeyPem, privateKeyPem) {
  // Build a basic X.509 v3 certificate using DER encoding
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  // Extract raw public key bytes from SPKI PEM
  const spkiDer = pemToDer(publicKeyPem);

  // Build TBS (To Be Signed) certificate
  const serialNumber = createHash('sha256')
    .update(Buffer.from(Date.now().toString()))
    .digest()
    .subarray(0, 8);

  const issuer = derSequence([
    derSet([derSequence([
      Buffer.from('550403', 'hex'), // OID: commonName
      derUtf8('CipherMesh'),
    ].map((b, i) => i === 0 ? derOid(b) : b))]),
  ]);

  const validity = derSequence([
    derUtcTime(now),
    derUtcTime(notAfter),
  ]);

  const tbs = derSequence([
    derExplicit(0, derInteger(2)), // version v3
    derInteger(serialNumber),
    derSequence([derOid(Buffer.from('2a864886f70d01010b', 'hex')), derNull()]), // sha256WithRSA
    issuer,
    validity,
    issuer, // subject = issuer (self-signed)
    Buffer.from(spkiDer), // subjectPublicKeyInfo
  ]);

  // Sign the TBS with SHA-256 + RSA
  const signer = createSign('SHA256');
  signer.update(tbs);
  const signature = signer.sign(privateKeyPem);

  // Build the full certificate
  const cert = derSequence([
    tbs,
    derSequence([derOid(Buffer.from('2a864886f70d01010b', 'hex')), derNull()]),
    derBitString(signature),
  ]);

  return derToPem(cert, 'CERTIFICATE');
}

// ── DER encoding helpers ─────────────────────────────────────

function derTag(tag, content) {
  const len = derLength(content.length);
  return Buffer.concat([Buffer.from([tag]), len, content]);
}

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  if (length < 0x100) return Buffer.from([0x81, length]);
  return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
}

function derSequence(items) {
  return derTag(0x30, Buffer.concat(items));
}

function derSet(items) {
  return derTag(0x31, Buffer.concat(items));
}

function derInteger(value) {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from([value]);
  // Prepend 0x00 if high bit is set (positive integer)
  const padded = buf[0] & 0x80 ? Buffer.concat([Buffer.from([0]), buf]) : buf;
  return derTag(0x02, padded);
}

function derOid(buf) {
  return derTag(0x06, buf);
}

function derNull() {
  return Buffer.from([0x05, 0x00]);
}

function derUtf8(str) {
  return derTag(0x0c, Buffer.from(str, 'utf-8'));
}

function derUtcTime(date) {
  const y = String(date.getUTCFullYear()).slice(-2);
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  const h = String(date.getUTCHours()).padStart(2, '0');
  const min = String(date.getUTCMinutes()).padStart(2, '0');
  const s = String(date.getUTCSeconds()).padStart(2, '0');
  return derTag(0x17, Buffer.from(`${y}${m}${d}${h}${min}${s}Z`, 'ascii'));
}

function derBitString(content) {
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), content]));
}

function derExplicit(tag, content) {
  return derTag(0xa0 | tag, content);
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return Buffer.from(b64, 'base64');
}

function derToPem(der, label) {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
