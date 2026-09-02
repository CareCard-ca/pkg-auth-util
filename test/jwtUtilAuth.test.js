'use strict';

const assert = require('node:assert').strict;
const {
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
} = require('..');
const { createJwkIdentity, serializeIdentity } = require('./keys/keys');

function parsedIdentity() {
  const serialized = serializeIdentity();
  return {
    signingJwk: parseJwtSigningJwk(serialized.signingJwk),
    verificationJwks: parseJwtVerificationJwks(serialized.verificationJwks),
  };
}

describe('JWT creation', function () {
  it('supplies default second-based iat and exp claims', function () {
    const { signingJwk } = parsedIdentity();
    const before = Math.floor(Date.now() / 1000);
    const token = jwtCreateSignedToken({ sub: 'user' }, signingJwk);
    const payload = jwtGetHeaderPayload(token).payload;

    assert.ok(payload.iat >= before);
    assert.strictEqual(payload.exp, payload.iat + 3600);
  });

  it('normalizes registered millisecond timestamps to seconds', function () {
    const { signingJwk } = parsedIdentity();
    const token = jwtCreateSignedToken(
      { iat: 1700000000000, exp: 1700000060000, nbf: 1700000001000, auth_time: 1700000002000 },
      signingJwk,
    );

    assert.deepStrictEqual(jwtGetHeaderPayload(token).payload, {
      iat: 1700000000,
      exp: 1700000060,
      nbf: 1700000001,
      auth_time: 1700000002,
    });
  });

  it('creates a service token with array audience and custom claims', function () {
    const { signingJwk } = parsedIdentity();
    const token = jwtCreateServiceToken({
      issuer: 'ms-auth',
      audience: ['ms-search', 'ms-documents'],
      subject: 'service-subject',
      issuedAt: 1700000000000,
      expiresInSeconds: 60,
      claims: { purpose: 'sync' },
      signingJwk,
    });
    const payload = jwtGetHeaderPayload(token).payload;

    assert.deepStrictEqual(payload.aud, ['ms-search', 'ms-documents']);
    assert.strictEqual(payload.sub, 'service-subject');
    assert.strictEqual(payload.iat, 1700000000);
    assert.strictEqual(payload.exp, 1700000060);
    assert.strictEqual(payload.purpose, 'sync');
  });

  for (const options of [
    {},
    { issuer: '', audience: 'ms-search' },
    { issuer: 'ms-auth', audience: '' },
    { issuer: 'ms-auth', audience: [] },
    { issuer: 'ms-auth', audience: [''] },
    { issuer: 'ms-auth', audience: 'ms-search', subject: '' },
    { issuer: 'ms-auth', audience: 'ms-search', expiresInSeconds: 0 },
    { issuer: 'ms-auth', audience: 'ms-search', expiresInSeconds: 1.5 },
    { issuer: 'ms-auth', audience: 'ms-search', issuedAt: Number.NaN },
    { issuer: 'ms-auth', audience: 'ms-search', claims: [] },
  ]) {
    it(`rejects invalid service token options ${JSON.stringify(options)}`, function () {
      const { signingJwk } = parsedIdentity();
      assert.strictEqual(jwtCreateServiceToken({ ...options, signingJwk }), null);
      assert.strictEqual(jwtCreateServiceAuthorizationHeader({ ...options, signingJwk }), null);
    });
  }

  it('rejects an unparsed signing JWK and non-object payload', function () {
    const serialized = serializeIdentity();
    assert.strictEqual(jwtCreateSignedToken({ sub: 'user' }, serialized.identity.signing), null);
    assert.strictEqual(jwtCreateSignedToken([], parseJwtSigningJwk(serialized.signingJwk)), null);
  });

  it('surfaces a circular payload serialization error', function () {
    const { signingJwk } = parsedIdentity();
    const payload = {};
    payload.self = payload;
    assert.throws(() => jwtCreateSignedToken(payload, signingJwk), TypeError);
  });
});

describe('JWT verification and decoding', function () {
  it('rejects malformed, altered, and unconfigured tokens', function () {
    const { signingJwk, verificationJwks } = parsedIdentity();
    const token = jwtCreateSignedToken({ sub: 'user' }, signingJwk);
    const [header, payload, signature] = token.split('.');

    assert.strictEqual(jwtVerifySignedToken('', verificationJwks), false);
    assert.strictEqual(jwtVerifySignedToken('one.two', verificationJwks), false);
    assert.strictEqual(jwtVerifySignedToken('not-json.payload.signature', verificationJwks), false);
    assert.strictEqual(
      jwtVerifySignedToken(`${header}.${payload}.${signature.slice(1)}`, verificationJwks),
      false,
    );
    assert.strictEqual(jwtVerifySignedToken(token, {}), false);
    assert.strictEqual(jwtVerifySignedToken(null, verificationJwks), false);
  });

  it('returns null for malformed decoded JWT parts', function () {
    assert.strictEqual(jwtGetHeaderPayload(null), null);
    assert.strictEqual(jwtGetHeaderPayload('one.two'), null);
    assert.strictEqual(jwtGetHeaderPayload('not-json.payload.signature'), null);
    const arrayPart = Buffer.from('[]').toString('base64url');
    assert.strictEqual(jwtGetHeaderPayload(`${arrayPart}.${arrayPart}.signature`), null);
  });
});

describe('JWT key configuration', function () {
  it('rejects malformed serialized configuration', function () {
    assert.throws(() => parseJwtSigningJwk('not-json'), /signing JWK/);
    assert.throws(() => parseJwtVerificationJwks('[]'), /verification JWKS/);
    assert.throws(() => parseJwtVerificationJwks('{"keys":[]}'), /verification JWKS/);
  });

  for (const change of [
    { kty: 'RSA' },
    { crv: 'X25519' },
    { alg: 'RS256' },
    { use: 'enc' },
    { key_ops: ['verify'] },
    { x: 'invalid' },
    { d: 'invalid' },
  ]) {
    it(`rejects invalid signing metadata ${JSON.stringify(change)}`, function () {
      const identity = createJwkIdentity();
      assert.throws(() => parseJwtSigningJwk(JSON.stringify({ ...identity.signing, ...change })));
    });
  }

  it('rejects invalid public key metadata', function () {
    const identity = createJwkIdentity();
    assert.throws(() =>
      parseJwtVerificationJwks(
        JSON.stringify({ keys: [{ ...identity.verification, key_ops: ['sign'] }] }),
      ),
    );
    assert.throws(() => parseJwtVerificationJwks(JSON.stringify({ keys: [null] })));
  });
});
