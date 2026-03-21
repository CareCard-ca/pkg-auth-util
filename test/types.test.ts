import assert from 'assert';
import { jwtUtilAuth, pwdUtilAuth, createKeys, stringUtilAuth, JwtHeader, JwtPayload, KeyPair, JwtParts } from '../index';

describe('TypeScript Type Definitions', () => {
  it('should verify jwtUtilAuth types', () => {
    const header: JwtHeader = { alg: 'EdDSA', typ: 'JWT', custom: 'value' };
    const payload: JwtPayload = { sub: '123', iat: 1234567890, exp: 1234571490 };
    const privateKey = 'some-private-key';
    const publicKey = 'some-public-key';

    const jwt: string | null = jwtUtilAuth.createSignedJwtFromObject(header, payload, privateKey);
    const isValid: boolean = jwtUtilAuth.verifyJwtSignature(jwt || '', publicKey);
    const parts: JwtParts | null = jwtUtilAuth.getHeaderPayloadFromJwt(jwt || '');

    assert.strictEqual(typeof isValid, 'boolean');
    if (parts) {
      assert.ok(parts.header);
      assert.ok(parts.payload);
    }
  });

  it('should verify pwdUtilAuth types', () => {
    const secret = 'my-secret';
    const password = 'my-password';
    const algorithm = 'sha256';
    const hashWithSalt: string = pwdUtilAuth.createPasswordHashWithRandomSalt(password, secret, algorithm);
    const hashBasedOnSaved: string = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt(password, hashWithSalt, secret);
    
    assert.strictEqual(typeof hashWithSalt, 'string');
    assert.strictEqual(typeof hashBasedOnSaved, 'string');
  });

  it('should verify createKeys types', () => {
    const keys: KeyPair = createKeys('ed25519');
    const rsaKeys: KeyPair = createKeys('rsa');
    
    assert.ok(keys.publicKey);
    assert.ok(keys.privateKey);
    assert.ok(rsaKeys.publicKey);
    assert.ok(rsaKeys.privateKey);
  });

  it('should verify stringUtilAuth types', () => {
    const safeStr: string = stringUtilAuth.makeStringUrlSafe('a+b/c=');
    const unsafeStr: string = stringUtilAuth.reverseStringUrlSafe(safeStr);
    const b64: string = stringUtilAuth.asciiToBase64('hello');
    const ascii: string = stringUtilAuth.base64ToAscii(b64);
    const objB64: string = stringUtilAuth.objectToBase64UrlSafeString({ a: 1 });
    const backToObj: any = stringUtilAuth.urlSafeBase64ToObject(objB64);

    assert.strictEqual(typeof safeStr, 'string');
    assert.strictEqual(typeof unsafeStr, 'string');
    assert.strictEqual(typeof b64, 'string');
    assert.strictEqual(typeof ascii, 'string');
    assert.strictEqual(typeof objB64, 'string');
    assert.ok(backToObj);
  });
});
