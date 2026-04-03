const pwdUtilAuth = require('./lib/pwdUtilAuth');
const jwtUtilAuth = require('./lib/jwtUtilAuth');
const keyGen = require('./lib/keyGen');

module.exports = {
    // New
    createKeys: keyGen.generateKeyPair,
    jwtCreateSignedFromObject: jwtUtilAuth.createSignedJwtFromObject,
    jwtVerifySignature: jwtUtilAuth.verifyJwtSignature,
    jwtGetHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt,
    passwordCreateHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
    passwordCreateHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt,

    // Deprecated
    jwtUtilAuth: {
        createSignedJwtFromObject: jwtUtilAuth.createSignedJwtFromObject,
        verifyJwtSignature: jwtUtilAuth.verifyJwtSignature,
        getHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt
    },
    pwdUtilAuth: {
        createPasswordHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
        createPasswordHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt
    },
    stringUtilAuth: require('./lib/stringUtilAuth'),
};

