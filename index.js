const pwdUtilAuth = require('./lib/pwdUtilAuth');
const jwtUtilAuth = require('./lib/jwtUtilAuth');
const keyGen = require('./lib/keyGen');

module.exports = {
    // New
    generateKeyPair: keyGen.generateKeyPair,
    jwtCreateSignedFromObject: jwtUtilAuth.createSignedJwtFromObject,
    jwtVerifySignature: jwtUtilAuth.verifyJwtSignature,
    jwtGetHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt,
    passwordCreateHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
    passwordCreateHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt,

    // Deprecated
    /**
     * @deprecated use direct import of the new functions.
     */
    jwtUtilAuth: {
        createSignedJwtFromObject: jwtUtilAuth.createSignedJwtFromObject,
        verifyJwtSignature: jwtUtilAuth.verifyJwtSignature,
        getHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt
    },
    /**
     * @deprecated use direct import of the new functions.
     */
    pwdUtilAuth: {
        createPasswordHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
        createPasswordHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt
    },
    /**
     * @deprecated Use native Buffer methods or other modern alternatives.
     */
    stringUtilAuth: require('./lib/stringUtilAuth'),
};

