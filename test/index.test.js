const assert = require('assert').strict;
const { describe, it } = require('mocha');
const {
  generateKeyPair,
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtVerifySignedToken,
  jwtGetHeaderPayload,
  passwordCreateHashWithRandomSalt,
  passwordCreateHashFromSavedHash,
} = require('../index');
const keys = require('./keys/keys');

describe('Index/JwtUtilAuth', function () {
  it('jwtCreateSignedToken returns base64 url safe jwt', function () {
    const header = {
      alg: 'EdDSA',
      typ: 'JWT',
    };
    const payload = {
      sub: '1234567890',
      name: 'John Doe',
      iat: 1516239022,
      cpso: '81883',
      roles: ['ph', 'ea'],
    };
    const createdJwt = jwtCreateSignedToken(header, payload, keys.privateKey);
    const isVerified = jwtVerifySignedToken(createdJwt, keys.publicKey);

    assert.ok(isVerified);
    const { header: decodedHeader, payload: decodedPayload } = jwtGetHeaderPayload(createdJwt);
    assert.deepStrictEqual(decodedHeader, { alg: 'EdDSA', typ: 'JWT' });
    assert.strictEqual(decodedPayload.sub, '1234567890');
  });

  it('jwtVerifySignedToken returns true or false', function () {
    const header = { alg: 'EdDSA', typ: 'JWT' };
    const payload = { sub: '1234567890' };
    const jwt = jwtCreateSignedToken(header, payload, keys.privateKey);

    const isVerified = jwtVerifySignedToken(jwt, keys.publicKey);

    assert.deepStrictEqual(isVerified, true);
  });

  it('jwtCreateServiceToken returns a signed service JWT', function () {
    const createdJwt = jwtCreateServiceToken({
      issuer: 'ms-institutions',
      audience: 'ms-auth',
      privateKey: keys.privateKey,
    });

    const isVerified = jwtVerifySignedToken(createdJwt, keys.publicKey);
    const { payload } = jwtGetHeaderPayload(createdJwt);

    assert.strictEqual(isVerified, true);
    assert.strictEqual(payload.iss, 'ms-institutions');
    assert.strictEqual(payload.sub, 'ms-institutions');
    assert.strictEqual(payload.aud, 'ms-auth');
  });

  it('jwtCreateServiceAuthorizationHeader returns a bearer service JWT header', function () {
    const authorizationHeader = jwtCreateServiceAuthorizationHeader({
      issuer: 'ms-institutions',
      audience: 'ms-auth',
      privateKey: keys.privateKey,
    });

    assert.match(authorizationHeader, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  });

  it('jwtGetHeaderPayload returns header, payload object', function () {
    const headerObj = { alg: 'EdDSA', typ: 'JWT' };
    const payloadObj = { sub: '1234567890' };
    const jwt = jwtCreateSignedToken(headerObj, payloadObj, keys.privateKey);

    const expectedHeader = {
      alg: 'EdDSA',
      typ: 'JWT',
    };
    const expectedPayload = {
      sub: '1234567890',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const { header, payload } = jwtGetHeaderPayload(jwt);

    assert.deepStrictEqual(header, expectedHeader);
    assert.strictEqual(payload.sub, expectedPayload.sub);
    assert.ok(Math.abs(payload.iat - expectedPayload.iat) < 2);
  });

  it('generateKeyPair returns a KeyPair', function () {
    const keys = generateKeyPair('ed25519');
    assert.ok(keys.publicKey);
    assert.ok(keys.privateKey);
    assert.ok(keys.publicKey.includes('BEGIN PUBLIC KEY'));
    assert.ok(keys.privateKey.includes('BEGIN PRIVATE KEY'));
  });
});

describe('Index/PwdUtilAuth', function () {
  it('passwordCreateHashWithRandomSalt called with save hash', function () {
    const password = 'mySecretPassword';
    const secret = 'bigSecret';
    const algorithm = 'sha512';

    const hash = passwordCreateHashWithRandomSalt(password, secret, algorithm);

    assert.deepStrictEqual(hash.length > 40, true);
  });

  it('passwordCreateHashFromSavedHash called with saved hash', function () {
    const savedHash =
      '$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$';
    const password = 'mySecretPassword';
    const secret = 'bigSecret';

    const hash = passwordCreateHashFromSavedHash(password, savedHash, secret);

    assert.deepStrictEqual(hash, savedHash);
  });
});
