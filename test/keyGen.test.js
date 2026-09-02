'use strict';

const assert = require('node:assert').strict;
const { parseJwtSigningJwk, parseJwtVerificationJwks } = require('..');
const { serializeIdentity } = require('./keys/keys');

describe('configured JWT identity', function () {
  it('parses matching private and public Ed25519 configuration', function () {
    const serialized = serializeIdentity();
    const signingJwk = parseJwtSigningJwk(serialized.signingJwk);
    const verificationJwks = parseJwtVerificationJwks(serialized.verificationJwks);

    assert.strictEqual(signingJwk.kid, serialized.identity.signing.kid);
    assert.deepStrictEqual(verificationJwks.kids, [serialized.identity.verification.kid]);
  });
});
