'use strict';

const assert = require('assert').strict;
const { describe, it } = require('mocha');

const keys = require('./keys/keys');
const {
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  createPasswordHash,
  verifyPassword,
} = require('../index');

describe('authentication security regressions', function () {
  it('does not accept a credential stored in the removed HMAC format', async function () {
    const legacyHash =
      '$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$';

    assert.strictEqual(
      await verifyPassword(
        'mySecretPassword',
        legacyHash,
        'carecard-test-pepper-is-at-least-32-bytes',
      ),
      false,
    );
  });

  it('preserves leading, trailing, and internal password spaces', async function () {
    const pepper = 'carecard-test-pepper-is-at-least-32-bytes';
    const password = '  spaced password  ';
    const savedHash = await createPasswordHash(password, pepper);

    assert.strictEqual(await verifyPassword(password, savedHash, pepper), true);
    assert.strictEqual(await verifyPassword(password.trim(), savedHash, pepper), false);
  });

  it('preserves explicit zero-valued registered JWT times', function () {
    const token = jwtCreateSignedToken(
      { alg: 'EdDSA' },
      { sub: 'expired-user', iat: 0, exp: 0, nbf: 0 },
      keys.privateKey,
    );
    const { payload } = jwtGetHeaderPayload(token);

    assert.strictEqual(payload.iat, 0);
    assert.strictEqual(payload.exp, 0);
    assert.strictEqual(payload.nbf, 0);
  });

  it('returns false for a signed-token header with an unsupported algorithm', function () {
    const token = jwtCreateSignedToken({ alg: 'EdDSA' }, { sub: 'user' }, keys.privateKey);
    const [, payload, signature] = token.split('.');
    const unsupportedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url',
    );

    assert.strictEqual(
      jwtVerifySignedToken(`${unsupportedHeader}.${payload}.${signature}`, keys.publicKey),
      false,
    );
  });

  it('rejects decoded JWT parts that are not JSON objects', function () {
    const header = Buffer.from(JSON.stringify([])).toString('base64url');
    const payload = Buffer.from(JSON.stringify('not-an-object')).toString('base64url');

    assert.strictEqual(jwtGetHeaderPayload(`${header}.${payload}.signature`), null);
  });
});
