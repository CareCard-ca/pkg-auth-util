const pwdUtilAuth = require('./lib/pwdUtilAuth');
const jwtUtilAuth = require('./lib/jwtUtilAuth');
const keyGen = require('./lib/keyGen');

module.exports = {
  // New
  generateKeyPair: keyGen.generateKeyPair,
  jwtCreateSignedToken: jwtUtilAuth.createSignedJwtFromObject,
  jwtVerifySignedToken: jwtUtilAuth.verifyJwtSignature,
  jwtGetHeaderPayload: jwtUtilAuth.getHeaderPayloadFromJwt,
  passwordCreateHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
  passwordCreateHashFromSavedHash: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt,

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
   * @deprecated use direct import of the new functions.
   */
  pwdUtilAuth: {
    createPasswordHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
    createPasswordHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt,
  },
  /**
   * @deprecated Use native Buffer methods or other modern alternatives.
   */
  stringUtilAuth: require('./lib/stringUtilAuth'),
};
