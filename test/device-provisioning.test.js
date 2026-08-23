/**
 * Provisioning a second device — step 5 of multi-device (item 4 of #481).
 *
 * The property the whole design rests on: **the identity secret never moves.**
 * A second device generates its own box keypair and receives only the
 * identity's public half plus a list signed by it. So a stolen phone is a
 * stolen phone, not a stolen identity, and a secondary cannot add or revoke
 * devices.
 *
 * Neither string here is secret — a request is a public key, a grant is a
 * signed statement that was going to be broadcast to every peer anyway. What
 * matters is that neither can be *substituted*: a grant only applies to the
 * exact device that asked for it, and a list only verifies under the identity
 * it names.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'sodium-native';
import {
  buildDeviceGrant,
  buildDeviceRequest,
  parseDeviceGrant,
  parseDeviceRequest,
} from '../src/shared/deviceProvisioning.js';
import { DeviceIdentity, newDeviceId, signDeviceList } from '../src/crypto/DeviceIdentity.js';

const boxKey = (fill) => Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES, fill).toString('base64');

describe('device request', () => {
  it('round-trips what the identity has to sign over', () => {
    const request = { deviceId: newDeviceId(), boxPk: boxKey(1), label: 'phone' };
    assert.deepEqual(parseDeviceRequest(buildDeviceRequest(request)), request);
  });

  it('is small enough to be a QR code or a typed line', () => {
    const encoded = buildDeviceRequest({ deviceId: newDeviceId(), boxPk: boxKey(1) });
    assert.ok(encoded.length < 200, `${encoded.length} characters`);
  });

  it('refuses to build one without a real device id', () => {
    for (const deviceId of ['', 'nothex', 'AB'.repeat(16), undefined]) {
      assert.equal(buildDeviceRequest({ deviceId, boxPk: boxKey(1) }), null, `${deviceId}`);
    }
  });

  it('refuses to read anything that is not one', () => {
    for (const junk of [
      undefined,
      null,
      42,
      '',
      'ciphermesh://host:3600/general',
      'ciphermesh-device://grant/eyJhIjoxfQ',
      'ciphermesh-device://request/not-base64url!!',
      `ciphermesh-device://request/${Buffer.from('[]').toString('base64url')}`,
      `ciphermesh-device://request/${Buffer.from('{"deviceId":"x"}').toString('base64url')}`,
    ]) {
      assert.equal(parseDeviceRequest(junk), null, `${junk}`);
    }
  });

  it('bounds the label rather than trusting it', () => {
    const request = parseDeviceRequest(
      buildDeviceRequest({ deviceId: newDeviceId(), boxPk: boxKey(1), label: 'x'.repeat(200) }),
    );
    assert.equal(request.label.length, 32);
  });
});

describe('device grant', () => {
  const grantFor = (identity, devices, counter = 2) => {
    const list = signDeviceList(identity, counter, devices);
    return { list, encoded: buildDeviceGrant({ identityPk: list.identityPk, list }) };
  };

  const device = (fill) => ({
    deviceId: newDeviceId(),
    boxPk: boxKey(fill),
    label: '',
    createdAt: 1755000000000,
  });

  it('round-trips the identity and the list that names it', () => {
    const identity = new DeviceIdentity();
    const { list, encoded } = grantFor(identity, [device(1), device(2)]);

    const parsed = parseDeviceGrant(encoded);
    assert.equal(parsed.identityPk, identity.publicKeyB64);
    assert.deepEqual(parsed.list, list);
    identity.destroy();
  });

  it('stays small enough to hand over by hand', () => {
    // A byte-mode QR code holds about 2 200 characters. A two-device grant is
    // roughly 740, so it fits with room for a third and a fourth device — which
    // is the reason there is no ML-KEM key in a descriptor: with one, two
    // devices came to 3.2 KB and nothing would have held it.
    const identity = new DeviceIdentity();
    const { encoded } = grantFor(identity, [device(1), device(2)]);

    assert.ok(encoded.length < 1000, `${encoded.length} characters`);
    identity.destroy();
  });

  it('refuses a grant whose envelope disagrees with its list', () => {
    // The two carry the same claim twice, so they cannot be allowed to differ —
    // a reader that trusted the envelope would adopt an identity the list was
    // never signed by.
    const identity = new DeviceIdentity();
    const other = new DeviceIdentity();
    const { list } = grantFor(identity, [device(1)]);

    const mismatched = buildDeviceGrant({ identityPk: other.publicKeyB64, list });
    assert.equal(parseDeviceGrant(mismatched), null);

    identity.destroy();
    other.destroy();
  });

  it('refuses to read anything that is not one', () => {
    for (const junk of [
      undefined,
      '',
      'ciphermesh-device://request/eyJhIjoxfQ',
      `ciphermesh-device://grant/${Buffer.from('{"identityPk":"a"}').toString('base64url')}`,
      `ciphermesh-device://grant/${Buffer.from('{"identityPk":"a","list":[]}').toString('base64url')}`,
    ]) {
      assert.equal(parseDeviceGrant(junk), null, `${junk}`);
    }
  });

  it('refuses an encoding longer than any real grant', () => {
    const identity = new DeviceIdentity();
    const { list } = grantFor(identity, [device(1)]);
    const padded = buildDeviceGrant({ identityPk: list.identityPk, list }) + 'A'.repeat(9000);

    assert.equal(parseDeviceGrant(padded), null);
    identity.destroy();
  });
});
