const pwdUtilAuth = require('./lib/pwdUtilAuth');
const jwtUtilAuth = require('./lib/jwtUtilAuth');
const keyGen = require('./lib/keyGen');

module.exports = {
  // New
  generateKeyPair: keyGen.generateKeyPair,
  jwtCreateSignedToken: jwtUtilAuth.createSignedJwtFromObject,
  jwtCreateServiceToken: jwtUtilAuth.createServiceJwt,
  jwtCreateServiceAuthorizationHeader: jwtUtilAuth.createServiceAuthorizationHeader,
  jwtVerifySignedToken: jwtUtilAuth.verifyJwtSignature,
  jwtGetHeaderPayload: jwtUtilAuth.getHeaderPayloadFromJwt,
  createPasswordHash: pwdUtilAuth.createPasswordHash,
  verifyPassword: pwdUtilAuth.verifyPassword,

  // Deprecated
  /**
   * @deprecated use direct import of the new functions.
   */
  jwtUtilAuth: {
    createSignedJwtFromObject: jwtUtilAuth.createSignedJwtFromObject,
    verifyJwtSignature: jwtUtilAuth.verifyJwtSignature,
    getHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt,
  },
  /**
   * @deprecated Use native Buffer methods or other modern alternatives.
   */
  stringUtilAuth: require('./lib/stringUtilAuth'),
};
