'use strict';

const assert = require('assert').strict;
const { describe, it } = require('mocha');

const keys = require('./keys/keys');
const {
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  passwordCreateHashFromSavedHash,
  passwordCreateHashWithRandomSalt,
} = require('../index');

describe('authentication security regressions', function () {
  it('uses each random password salt in the resulting credential digest', function () {
    const firstHash = passwordCreateHashWithRandomSalt('Password_1', 'pepper', 'sha512');
    const secondHash = passwordCreateHashWithRandomSalt('Password_1', 'pepper', 'sha512');

    assert.notStrictEqual(firstHash.split('$')[3], secondHash.split('$')[3]);
    assert.strictEqual(
      passwordCreateHashFromSavedHash('Password_1', firstHash, 'pepper'),
      firstHash,
    );
    assert.strictEqual(
      passwordCreateHashFromSavedHash('Password_1', secondHash, 'pepper'),
      secondHash,
    );
  });

  it('continues to verify credentials stored before salt affected the digest', function () {
    const legacyHash =
      '$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$';

    assert.strictEqual(
      passwordCreateHashFromSavedHash('mySecretPassword', legacyHash, 'bigSecret'),
      legacyHash,
    );
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
