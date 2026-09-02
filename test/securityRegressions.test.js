'use strict';

const assert = require('node:assert').strict;
const {
  createPasswordCredential,
  jwtCreateSignedToken,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
} = require('..');
const { serializeIdentity } = require('./keys/keys');

describe('security regressions', function () {
  it('does not trim passwords before hashing or verification', async function () {
    const key = Buffer.alloc(32, 9).toString('base64');
    const keyring = parsePasswordHashKeyring('active', `active:${key}`);
    const credential = await createPasswordCredential(' password phrase ', keyring);

    assert.strictEqual(
      (await verifyPasswordCredential(' password phrase ', credential, keyring)).isValid,
      true,
    );
    assert.strictEqual(
      (await verifyPasswordCredential('password phrase', credential, keyring)).isValid,
      false,
    );
  });

  it('does not accept a caller-selected or changed JWT algorithm', function () {
    const serialized = serializeIdentity();
    const signingJwk = parseJwtSigningJwk(serialized.signingJwk);
    const verificationJwks = parseJwtVerificationJwks(serialized.verificationJwks);
    const token = jwtCreateSignedToken({ sub: 'user' }, signingJwk);
    const [header, payload, signature] = token.split('.');
    const changedHeader = Buffer.from(
      JSON.stringify({ alg: 'sha256', typ: 'JWT', kid: signingJwk.kid }),
    ).toString('base64url');

    assert.strictEqual(
      jwtVerifySignedToken(`${changedHeader}.${payload}.${signature}`, verificationJwks),
      false,
    );
    assert.notStrictEqual(header, changedHeader);
  });

  it('rejects a noncanonical signature encoding', function () {
    const serialized = serializeIdentity();
    const signingJwk = parseJwtSigningJwk(serialized.signingJwk);
    const verificationJwks = parseJwtVerificationJwks(serialized.verificationJwks);
    const token = jwtCreateSignedToken({ sub: 'user' }, signingJwk);

    assert.strictEqual(jwtVerifySignedToken(`${token}=`, verificationJwks), false);
  });
});
