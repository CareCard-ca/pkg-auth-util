const assert = require('assert').strict;
const { describe, it } = require('mocha');
const keys = require('./keys/keys');
const {
  generateKeyPair,
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
} = require('../index');

describe('JwtUtilAuth test', function () {
  describe('createSignedJwtFromObject', function () {
    it('should return a valid signed JWT with exp and correct iat', function () {
      const header = { alg: 'EdDSA' };
      const payload = {
        sub: '1234567890',
        name: 'John Doe',
        iat: 1516239022000, // ms
        exp: 1516242622000, // ms
        nbf: 1516239022000, // ms
        auth_time: 1516239022000, // ms
      };
      const privateKey = keys.privateKey;

      const jwt = jwtCreateSignedToken(header, payload, privateKey);
      assert.ok(jwt);

      const { header: decodedHeader, payload: decodedPayload } = jwtGetHeaderPayload(jwt);
      assert.strictEqual(decodedHeader.alg, 'EdDSA');
      assert.strictEqual(decodedPayload.sub, '1234567890');
      assert.strictEqual(decodedPayload.iat, 1516239022); // converted to seconds
      assert.strictEqual(decodedPayload.exp, 1516242622); // converted to seconds
      assert.strictEqual(decodedPayload.nbf, 1516239022); // converted to seconds
      assert.strictEqual(decodedPayload.auth_time, 1516239022); // converted to seconds
      assert.ok(decodedPayload.exp > decodedPayload.iat);
    });

    it('should propagate unexpected payload serialization errors', function () {
      const circular = {};
      circular.self = circular;
      assert.throws(() => jwtCreateSignedToken({}, circular, keys.privateKey), TypeError);
    });

    it('should return null when privateKey is missing', function () {
      const result = jwtCreateSignedToken({}, {}, null);
      assert.strictEqual(result, null);
    });

    it('should return a valid signed JWT with RSA algorithm', function () {
      const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateKeyPair('rsa');
      const header = { alg: 'sha256' };
      const payload = { sub: '123' };
      const jwt = jwtCreateSignedToken(header, payload, rsaPrivateKey);
      assert.ok(jwt);
      assert.ok(jwtVerifySignedToken(jwt, rsaPublicKey));
    });
  });

  describe('createServiceJwt', function () {
    it('should return a signed service JWT with standard service identity claims', function () {
      const jwt = jwtCreateServiceToken({
        issuer: 'ms-institutions',
        audience: 'ms-auth',
        privateKey: keys.privateKey,
        expiresInSeconds: 120,
      });

      assert.ok(jwt);
      assert.strictEqual(jwtVerifySignedToken(jwt, keys.publicKey), true);

      const { header, payload } = jwtGetHeaderPayload(jwt);
      assert.strictEqual(header.alg, 'EdDSA');
      assert.strictEqual(payload.iss, 'ms-institutions');
      assert.strictEqual(payload.aud, 'ms-auth');
      assert.strictEqual(payload.sub, 'ms-institutions');
      assert.strictEqual(payload.exp - payload.iat, 120);
    });

    it('should allow array audiences and additional claims without overriding registered service claims', function () {
      const jwt = jwtCreateServiceToken({
        issuer: 'ms-institutions',
        audience: ['ms-auth', 'ms-user-profiles'],
        privateKey: keys.privateKey,
        claims: {
          aud: 'unexpected-audience',
          route: '/api/v1/ms-auth/users/by-ids',
        },
      });

      const { payload } = jwtGetHeaderPayload(jwt);
      assert.deepStrictEqual(payload.aud, ['ms-auth', 'ms-user-profiles']);
      assert.strictEqual(payload.route, '/api/v1/ms-auth/users/by-ids');
    });

    it('should normalize millisecond issued-at values', function () {
      const jwt = jwtCreateServiceToken({
        issuer: 'ms-institutions',
        audience: 'ms-auth',
        privateKey: keys.privateKey,
        issuedAt: 1516239022000,
        expiresInSeconds: 60,
      });

      const { payload } = jwtGetHeaderPayload(jwt);
      assert.strictEqual(payload.iat, 1516239022);
      assert.strictEqual(payload.exp, 1516239082);
    });

    it('should return null when service JWT inputs are incomplete', function () {
      assert.strictEqual(
        jwtCreateServiceToken({
          issuer: 'ms-institutions',
          audience: 'ms-auth',
          privateKey: '',
        }),
        null,
      );
      assert.strictEqual(
        jwtCreateServiceToken({
          issuer: '',
          audience: 'ms-auth',
          privateKey: keys.privateKey,
        }),
        null,
      );
      assert.strictEqual(
        jwtCreateServiceToken({
          issuer: 'ms-institutions',
          audience: [],
          privateKey: keys.privateKey,
        }),
        null,
      );
      assert.strictEqual(
        jwtCreateServiceToken({
          issuer: 'ms-institutions',
          audience: 'ms-auth',
          privateKey: keys.privateKey,
          subject: '',
        }),
        null,
      );
      assert.strictEqual(
        jwtCreateServiceToken({
          issuer: 'ms-institutions',
          audience: 'ms-auth',
          privateKey: keys.privateKey,
          expiresInSeconds: 0,
        }),
        null,
      );
    });
  });

  describe('createServiceAuthorizationHeader', function () {
    it('should return a bearer Authorization header for service requests', function () {
      const authorizationHeader = jwtCreateServiceAuthorizationHeader({
        issuer: 'ms-institutions',
        audience: 'ms-auth',
        privateKey: keys.privateKey,
      });

      assert.match(authorizationHeader, /^Bearer [^.]+\.[^.]+\.[^.]+$/);
    });

    it('should return null when a service JWT cannot be created', function () {
      const authorizationHeader = jwtCreateServiceAuthorizationHeader({
        issuer: 'ms-institutions',
        audience: 'ms-auth',
        privateKey: '',
      });

      assert.strictEqual(authorizationHeader, null);
    });
  });

  describe('verifyJwtSignature', function () {
    it('should return true for valid signature', function () {
      const header = { alg: 'EdDSA' };
      const payload = { sub: '1234567890' };
      const jwt = jwtCreateSignedToken(header, payload, keys.privateKey);

      const isValid = jwtVerifySignedToken(jwt, keys.publicKey);
      assert.strictEqual(isValid, true);
    });

    it('should return false when error occurs (invalid header format)', function () {
      const result = jwtVerifySignedToken('not-base64.payload.sig', keys.publicKey);
      assert.strictEqual(result, false);
    });

    it('should return false if jwt has invalid number of parts', function () {
      const result = jwtVerifySignedToken('one.two', keys.publicKey);
      assert.strictEqual(result, false);
    });

    it('should propagate unexpected public-key configuration errors', function () {
      const jwt = jwtCreateSignedToken({ alg: 'EdDSA' }, { sub: '1234567890' }, keys.privateKey);

      assert.throws(() => jwtVerifySignedToken(jwt, 'not-a-public-key'));
    });
  });

  describe('getHeaderPayloadFromJwt', function () {
    it('should return header and payload for valid JWT', function () {
      const header = { alg: 'EdDSA' };
      const payload = { sub: '1234567890' };
      const jwt = jwtCreateSignedToken(header, payload, keys.privateKey);

      const result = jwtGetHeaderPayload(jwt);
      assert.strictEqual(result.header.alg, 'EdDSA');
      assert.strictEqual(result.payload.sub, '1234567890');
    });

    it('should return null when error occurs (invalid JSON in header)', function () {
      const result = jwtGetHeaderPayload('bm90LWpzb24.payload.sig'); // 'bm90LWpzb24' is 'not-json'
      assert.strictEqual(result, null);
    });

    it('should return null when input is not a string', function () {
      const result = jwtGetHeaderPayload(null);
      assert.strictEqual(result, null);
    });
  });

  describe('public signing behavior', function () {
    it('normalizes millisecond timestamps in signed payloads', function () {
      const payload = {
        iat: 1516239022000,
        exp: 1516242622000,
        nbf: 1516239022000,
        auth_time: 1516239022000,
      };
      const jwt = jwtCreateSignedToken({ alg: 'EdDSA' }, payload, keys.privateKey);
      const { payload: normalized } = jwtGetHeaderPayload(jwt);
      assert.strictEqual(normalized.iat, 1516239022);
      assert.strictEqual(normalized.exp, 1516242622);
      assert.strictEqual(normalized.nbf, 1516239022);
      assert.strictEqual(normalized.auth_time, 1516239022);
    });

    it('adds default issue and expiry timestamps when they are omitted', function () {
      const jwt = jwtCreateSignedToken({ alg: 'EdDSA' }, {}, keys.privateKey);
      const { payload: normalized } = jwtGetHeaderPayload(jwt);
      assert.ok(normalized.iat);
      assert.strictEqual(normalized.exp, normalized.iat + 3600);
    });

    it('preserves custom payload values through token creation and decoding', function () {
      const payload = { foo: 'bar' };
      const jwt = jwtCreateSignedToken({ alg: 'EdDSA' }, payload, keys.privateKey);
      const { payload: decodedPayload } = jwtGetHeaderPayload(jwt);
      assert.strictEqual(decodedPayload.foo, payload.foo);
    });

    it('creates EdDSA tokens accepted by public signature verification', function () {
      const jwt = jwtCreateSignedToken({ alg: 'EdDSA' }, { sub: 'ed25519-user' }, keys.privateKey);
      const isValid = jwtVerifySignedToken(jwt, keys.publicKey);
      assert.strictEqual(isValid, true);
    });

    it('creates RSA tokens accepted by public signature verification', function () {
      const { privateKey: rsaPrivateKey, publicKey: rsaPublicKey } = generateKeyPair('rsa');
      const jwt = jwtCreateSignedToken({ alg: 'sha256' }, { sub: 'rsa-user' }, rsaPrivateKey);
      const isValid = jwtVerifySignedToken(jwt, rsaPublicKey);
      assert.strictEqual(isValid, true);
    });
  });
});
