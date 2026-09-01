import assert from 'assert';
import { describe, it } from 'mocha';
import {
  createPasswordHash,
  generateKeyPair,
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  JwtHeader,
  JwtParts,
  JwtPayload,
  jwtUtilAuth,
  jwtVerifySignedToken,
  KeyPair,
  ServiceJwtOptions,
  stringUtilAuth,
  verifyPassword,
} from '../index';

describe('TypeScript Type Definitions', () => {
  it('should verify jwtUtilAuth types and interfaces', () => {
    const header: JwtHeader = { alg: 'EdDSA', typ: 'JWT', custom: 'value' };
    const payload: JwtPayload = {
      sub: '123',
      iat: 1234567890,
      exp: 1234571490,
      nbf: 1234567890,
      auth_time: 1234567890,
      custom_claim: 'foo',
    };
    const { privateKey, publicKey }: KeyPair = generateKeyPair('ed25519');

    const jwt: string | null = jwtUtilAuth.createSignedJwtFromObject(header, payload, privateKey);
    const serviceJwtOptions: ServiceJwtOptions = {
      issuer: 'ms-institutions',
      audience: 'ms-auth',
      privateKey,
      claims: {
        route: '/api/v1/ms-auth/users/by-ids',
      },
    };
    const isValid: boolean = jwtUtilAuth.verifyJwtSignature(jwt || '', publicKey);
    const parts: JwtParts | null = jwtUtilAuth.getHeaderPayloadFromJwt(jwt || '');

    assert.strictEqual(typeof isValid, 'boolean');
    if (parts) {
      assert.ok(parts.header);
      assert.ok(parts.payload);
      assert.strictEqual(parts.header.alg, header.alg);
      assert.strictEqual(parts.payload.sub, payload.sub);
    }

    // Test top-level functions directly
    const jwtDirect: string | null = jwtCreateSignedToken(header, payload, privateKey);
    const serviceJwtDirect: string | null = jwtCreateServiceToken(serviceJwtOptions);
    const serviceAuthorizationHeaderDirect: string | null =
      jwtCreateServiceAuthorizationHeader(serviceJwtOptions);
    const isValidDirect: boolean = jwtVerifySignedToken(jwtDirect || '', publicKey);
    const partsDirect: JwtParts | null = jwtGetHeaderPayload(jwtDirect || '');
    assert.strictEqual(typeof isValidDirect, 'boolean');
    assert.ok(!partsDirect || partsDirect.header);
    assert.ok(serviceJwtDirect === null || typeof serviceJwtDirect === 'string');
    assert.ok(
      serviceAuthorizationHeaderDirect === null ||
        serviceAuthorizationHeaderDirect.startsWith('Bearer '),
    );
  });

  it('should verify password hash types', async () => {
    const secret = 'carecard-test-pepper-is-at-least-32-bytes';
    const password = 'my-password';
    const savedHash: string = await createPasswordHash(password, secret);
    const matches: boolean = await verifyPassword(password, savedHash, secret);

    assert.strictEqual(typeof savedHash, 'string');
    assert.strictEqual(typeof matches, 'boolean');
  });

  it('should verify generateKeyPair types and KeyPair interface', () => {
    const keys: KeyPair = generateKeyPair('ed25519');
    const rsaKeys: KeyPair = generateKeyPair('rsa');
    const defaultKeys: KeyPair = generateKeyPair();

    assert.ok(keys.publicKey);
    assert.ok(keys.privateKey);
    assert.ok(rsaKeys.publicKey);
    assert.ok(rsaKeys.privateKey);
    assert.ok(defaultKeys.publicKey);
    assert.ok(defaultKeys.privateKey);
  });

  it('should verify stringUtilAuth types', () => {
    const safeStr: string = stringUtilAuth.makeStringUrlSafe('a+b/c=');
    const unsafeStr: string = stringUtilAuth.reverseStringUrlSafe(safeStr);
    const b64: string = stringUtilAuth.asciiToBase64('hello');
    const ascii: string = stringUtilAuth.base64ToAscii(b64);
    const objB64: string = stringUtilAuth.objectToBase64UrlSafeString({ a: 1 });
    const backToObj: unknown = stringUtilAuth.urlSafeBase64ToObject(objB64);

    assert.strictEqual(typeof safeStr, 'string');
    assert.strictEqual(typeof unsafeStr, 'string');
    assert.strictEqual(typeof b64, 'string');
    assert.strictEqual(typeof ascii, 'string');
    assert.strictEqual(typeof objB64, 'string');
    assert.ok(backToObj);

    // Verify dotConnectedStringToHeaderPayloadSignature
    const mockJwt = 'header.payload.signature';
    const jwtDots = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(mockJwt);
    if (jwtDots) {
      assert.strictEqual(typeof jwtDots.header, 'string');
      assert.strictEqual(typeof jwtDots.payload, 'string');
      assert.strictEqual(typeof jwtDots.signature, 'string');
    }
  });
});
