import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, createPrivateKey } from 'node:crypto';
import tls from 'node:tls';
import { loadOrGenerateCerts } from '../src/server/CertManager.js';

describe('CertManager', () => {
  it('produces a self-signed X.509 cert + key that Node can parse and use for TLS', () => {
    const { key, cert } = loadOrGenerateCerts();

    // The hand-rolled DER cert must parse as a real X.509 certificate.
    const x = new X509Certificate(cert);
    assert.match(x.subject, /CipherMesh/);
    assert.equal(x.subject, x.issuer, 'self-signed: subject === issuer');

    // The private key must parse...
    assert.doesNotThrow(() => createPrivateKey(key));

    // ...and both must load into a TLS secure context (what the server does).
    assert.doesNotThrow(() => tls.createSecureContext({ key, cert }));
  });
});
