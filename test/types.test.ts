import assert from 'node:assert';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, it } from 'mocha';
import {
  createPasswordCredential,
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
  parsePasswordHashKeyring,
  stringUtilAuth,
  verifyPasswordCredential,
  type JwtParts,
  type JwtPayload,
  type JwtSigningJwk,
  type JwtVerificationJwks,
  type PasswordCredential,
  type PasswordCredentialVerification,
  type PasswordHashKeyring,
  type ServiceJwtOptions,
} from '../index';

function createParsedIdentity(): {
  signingJwk: JwtSigningJwk;
  verificationJwks: JwtVerificationJwks;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicJwk.x });
  const kid = createHash('sha256').update(canonical).digest('base64url');
  const signingJwk = parseJwtSigningJwk(
    JSON.stringify({ ...privateJwk, alg: 'EdDSA', use: 'sig', key_ops: ['sign'], kid }),
  );
  const verificationJwks = parseJwtVerificationJwks(
    JSON.stringify({
      keys: [{ ...publicJwk, alg: 'EdDSA', use: 'sig', key_ops: ['verify'], kid }],
    }),
  );
  return { signingJwk, verificationJwks };
}

describe('TypeScript type definitions', () => {
  it('supports the JWK JWT public contract', () => {
    const { signingJwk, verificationJwks } = createParsedIdentity();
    const payload: JwtPayload = { sub: '123', roles: ['ad'], custom_claim: 'value' };
    const options: ServiceJwtOptions = {
      issuer: 'ms-institutions',
      audience: 'ms-auth',
      signingJwk,
      claims: { route: '/api/v1/ms-auth/users/by-ids' },
    };
    const jwt: string | null = jwtCreateSignedToken(payload, signingJwk);
    const serviceJwt: string | null = jwtCreateServiceToken(options);
    const authorization: string | null = jwtCreateServiceAuthorizationHeader(options);
    const isValid: boolean = jwtVerifySignedToken(jwt || '', verificationJwks);
    const parts: JwtParts | null = jwtGetHeaderPayload(jwt || '');

    assert.strictEqual(isValid, true);
    assert.strictEqual(parts?.payload.sub, '123');
    assert.ok(serviceJwt);
    assert.ok(authorization?.startsWith('Bearer '));
  });

  it('supports the password keyring public contract', async () => {
    const keyring: PasswordHashKeyring = parsePasswordHashKeyring(
      'active',
      `active:${Buffer.alloc(32, 5).toString('base64')}`,
    );
    const credential: PasswordCredential = await createPasswordCredential('my-password', keyring);
    const result: PasswordCredentialVerification = await verifyPasswordCredential(
      'my-password',
      credential,
      keyring,
    );

    assert.strictEqual(result.isValid, true);
  });

  it('supports retained string utility types', () => {
    const safe: string = stringUtilAuth.makeStringUrlSafe('a+b/c=');
    const unsafe: string = stringUtilAuth.reverseStringUrlSafe(safe);
    const base64: string = stringUtilAuth.asciiToBase64('hello');
    const plain: string = stringUtilAuth.base64ToAscii(base64);
    const encoded: string = stringUtilAuth.objectToBase64UrlSafeString({ a: 1 });
    const decoded: unknown = stringUtilAuth.urlSafeBase64ToObject(encoded);
    const parts = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature(
      'header.payload.signature',
    );

    assert.strictEqual(typeof unsafe, 'string');
    assert.strictEqual(plain, 'hello');
    assert.ok(decoded);
    assert.strictEqual(parts?.payload, 'payload');
  });
});
