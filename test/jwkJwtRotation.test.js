'use strict';

const assert = require('node:assert').strict;
const {
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
} = require('..');
const { createJwkIdentity } = require('./keys/keys');

describe('JWK JWT rotation', function () {
  it('signs with a deterministic kid and verifies through JWKS', function () {
    const identity = createJwkIdentity();
    const signingJwk = parseJwtSigningJwk(JSON.stringify(identity.signing));
    const verificationJwks = parseJwtVerificationJwks(
      JSON.stringify({ keys: [identity.verification] }),
    );
    const token = jwtCreateSignedToken({ sub: 'user-id' }, signingJwk);
    const decoded = jwtGetHeaderPayload(token);

    assert.deepStrictEqual(decoded.header, {
      alg: 'EdDSA',
      typ: 'JWT',
      kid: identity.verification.kid,
    });
    assert.strictEqual(jwtVerifySignedToken(token, verificationJwks), true);
  });

  it('selects the exact service-token key by kid', function () {
    const active = createJwkIdentity();
    const retiring = createJwkIdentity();
    const signingJwk = parseJwtSigningJwk(JSON.stringify(active.signing));
    const verificationJwks = parseJwtVerificationJwks(
      JSON.stringify({ keys: [retiring.verification, active.verification] }),
    );
    const token = jwtCreateServiceToken({
      issuer: 'ms-auth',
      audience: 'ms-search',
      signingJwk,
    });

    assert.strictEqual(jwtVerifySignedToken(token, verificationJwks), true);
    assert.strictEqual(jwtGetHeaderPayload(token).payload.iss, 'ms-auth');
  });

  it('rejects a token when its kid is no longer present', function () {
    const active = createJwkIdentity();
    const replacement = createJwkIdentity();
    const token = jwtCreateSignedToken(
      { sub: 'user-id' },
      parseJwtSigningJwk(JSON.stringify(active.signing)),
    );
    const replacementJwks = parseJwtVerificationJwks(
      JSON.stringify({ keys: [replacement.verification] }),
    );

    assert.strictEqual(jwtVerifySignedToken(token, replacementJwks), false);
  });

  it('rejects duplicate public kids and private fields in JWKS', function () {
    const identity = createJwkIdentity();
    assert.throws(() =>
      parseJwtVerificationJwks(
        JSON.stringify({ keys: [identity.verification, identity.verification] }),
      ),
    );
    assert.throws(() => parseJwtVerificationJwks(JSON.stringify({ keys: [identity.signing] })));
  });

  it('rejects signing metadata with a non-thumbprint kid', function () {
    const identity = createJwkIdentity();
    assert.throws(() =>
      parseJwtSigningJwk(JSON.stringify({ ...identity.signing, kid: 'not-the-thumbprint' })),
    );
  });

  it('rejects a signing JWK whose public and private key material do not match', function () {
    const privateIdentity = createJwkIdentity();
    const publicIdentity = createJwkIdentity();
    const mismatchedSigningJwk = {
      ...privateIdentity.signing,
      x: publicIdentity.signing.x,
      kid: publicIdentity.signing.kid,
    };

    assert.throws(() => parseJwtSigningJwk(JSON.stringify(mismatchedSigningJwk)));
  });

  it('rejects unexpected private, public, and JWKS members', function () {
    const identity = createJwkIdentity();
    assert.throws(() =>
      parseJwtSigningJwk(JSON.stringify({ ...identity.signing, unexpected: true })),
    );
    assert.throws(() =>
      parseJwtVerificationJwks(
        JSON.stringify({ keys: [{ ...identity.verification, unexpected: true }] }),
      ),
    );
    assert.throws(() =>
      parseJwtVerificationJwks(JSON.stringify({ keys: [identity.verification], unexpected: true })),
    );
  });
});
