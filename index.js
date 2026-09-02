const pwdUtilAuth = require('./lib/pwdUtilAuth');
const jwtUtilAuth = require('./lib/jwtUtilAuth');
const jwkUtilAuth = require('./lib/jwkUtilAuth');

module.exports = {
  jwtCreateSignedToken: jwtUtilAuth.createSignedJwtFromObject,
  jwtCreateServiceToken: jwtUtilAuth.createServiceJwt,
  jwtCreateServiceAuthorizationHeader: jwtUtilAuth.createServiceAuthorizationHeader,
  jwtVerifySignedToken: jwtUtilAuth.verifyJwtSignature,
  jwtGetHeaderPayload: jwtUtilAuth.getHeaderPayloadFromJwt,
  parseJwtSigningJwk: jwkUtilAuth.parseJwtSigningJwk,
  parseJwtVerificationJwks: jwkUtilAuth.parseJwtVerificationJwks,
  createPasswordCredential: pwdUtilAuth.createPasswordCredential,
  parsePasswordHashKeyring: pwdUtilAuth.parsePasswordHashKeyring,
  verifyPasswordCredential: pwdUtilAuth.verifyPasswordCredential,
  /**
   * @deprecated Use native Buffer methods or other modern alternatives.
   */
  stringUtilAuth: require('./lib/stringUtilAuth'),
};
