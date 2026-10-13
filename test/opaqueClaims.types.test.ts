import { jwtCreateSignedToken, type JwtPayload, type JwtSigningJwk } from '../index';

const opaquePayload: JwtPayload = {
  sub: 'subject',
  roles: { arbitrary: true },
  emailVerified: 'opaque value',
};

export function signOpaqueClaims(signingJwk: JwtSigningJwk): string | null {
  return jwtCreateSignedToken(opaquePayload, signingJwk);
}
