import assert from 'assert';
import {describe, it} from 'mocha';
import {jwtUtilAuth, pwdUtilAuth, createKeys, stringUtilAuth, JwtHeader, JwtPayload, KeyPair, JwtParts, PasswordParts} from '../index';

describe('TypeScript Type Definitions', () => {
    it('should verify jwtUtilAuth types and interfaces', () => {
        const header: JwtHeader = {alg: 'EdDSA', typ: 'JWT', custom: 'value'};
        const payload: JwtPayload = {
            sub: '123',
            iat: 1234567890,
            exp: 1234571490,
            nbf: 1234567890,
            auth_time: 1234567890,
            custom_claim: 'foo'
        };
        const privateKey = 'some-private-key';
        const publicKey = 'some-public-key';

        const jwt: string | null = jwtUtilAuth.createSignedJwtFromObject(header, payload, privateKey);
        const isValid: boolean = jwtUtilAuth.verifyJwtSignature(jwt || '', publicKey);
        const parts: JwtParts | null = jwtUtilAuth.getHeaderPayloadFromJwt(jwt || '');

        assert.strictEqual(typeof isValid, 'boolean');
        if (parts) {
            assert.ok(parts.header);
            assert.ok(parts.payload);
            assert.strictEqual(parts.header.alg, header.alg);
            assert.strictEqual(parts.payload.sub, payload.sub);
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

    it('should verify createKeys types and KeyPair interface', () => {
        const keys: KeyPair = createKeys('ed25519');
        const rsaKeys: KeyPair = createKeys('rsa');
        const defaultKeys: KeyPair = createKeys();

        assert.ok(keys.publicKey);
        assert.ok(keys.privateKey);
        assert.ok(rsaKeys.publicKey);
        assert.ok(rsaKeys.privateKey);
        assert.ok(defaultKeys.publicKey);
        assert.ok(defaultKeys.privateKey);
    });

    it('should verify stringUtilAuth types and PasswordParts interface', () => {
        const safeStr: string = stringUtilAuth.makeStringUrlSafe('a+b/c=');
        const unsafeStr: string = stringUtilAuth.reverseStringUrlSafe(safeStr);
        const b64: string = stringUtilAuth.asciiToBase64('hello');
        const ascii: string = stringUtilAuth.base64ToAscii(b64);
        const objB64: string = stringUtilAuth.objectToBase64UrlSafeString({a: 1});
        const backToObj: any = stringUtilAuth.urlSafeBase64ToObject(objB64);

        assert.strictEqual(typeof safeStr, 'string');
        assert.strictEqual(typeof unsafeStr, 'string');
        assert.strictEqual(typeof b64, 'string');
        assert.strictEqual(typeof ascii, 'string');
        assert.strictEqual(typeof objB64, 'string');
        assert.ok(backToObj);

        // Verify dollarSignConnectedStringToAlgorithmHashSalt and PasswordParts
        const mockHash = '$1$sha256$hashvalue$saltvalue';
        const pwdParts: PasswordParts | null = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt(mockHash);
        if (pwdParts) {
            assert.strictEqual(typeof pwdParts.version, 'string');
            assert.strictEqual(typeof pwdParts.alg, 'string');
            assert.strictEqual(typeof pwdParts.hash, 'string');
            assert.strictEqual(typeof pwdParts.salt, 'string');
        }

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
