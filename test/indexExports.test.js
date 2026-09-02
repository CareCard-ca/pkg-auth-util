'use strict';

const assert = require('node:assert').strict;
const {
  createPasswordCredential,
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
} = require('..');
const { serializeIdentity } = require('./keys/keys');

function parsedIdentity() {
  const serialized = serializeIdentity();
  return {
    signingJwk: parseJwtSigningJwk(serialized.signingJwk),
    verificationJwks: parseJwtVerificationJwks(serialized.verificationJwks),
  };
}

describe('auth-util public API', function () {
  it('creates, decodes, and verifies an application JWT', function () {
    const { signingJwk, verificationJwks } = parsedIdentity();
    const token = jwtCreateSignedToken({ sub: 'user', roles: ['ad'] }, signingJwk);
    const decoded = jwtGetHeaderPayload(token);

    assert.strictEqual(jwtVerifySignedToken(token, verificationJwks), true);
    assert.strictEqual(decoded.payload.sub, 'user');
    assert.deepStrictEqual(decoded.payload.roles, ['ad']);
  });

  it('creates service tokens and bearer authorization headers', function () {
    const { signingJwk, verificationJwks } = parsedIdentity();
    const options = { issuer: 'ms-auth', audience: 'ms-search', signingJwk };
    const token = jwtCreateServiceToken(options);
    const authorization = jwtCreateServiceAuthorizationHeader(options);

    assert.strictEqual(jwtVerifySignedToken(token, verificationJwks), true);
    assert.match(authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  });

  it('creates and verifies a password credential', async function () {
    const key = Buffer.alloc(32, 3).toString('base64');
    const keyring = parsePasswordHashKeyring('active', `active:${key}`);
    const credential = await createPasswordCredential('password phrase', keyring);

    assert.deepStrictEqual(await verifyPasswordCredential('password phrase', credential, keyring), {
      isValid: true,
      needsRehash: false,
    });
  });
});
