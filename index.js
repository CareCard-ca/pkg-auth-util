const pwdUtilAuth = require( './lib/pwdUtilAuth' );
const jwtUtilAuth = require( './lib/jwtUtilAuth' );
const strEncryptUtil = require( './lib/strEncryptUtil' );
const keyGen = require( './lib/keyGen' );

module.exports = {
    jwtUtilAuth: {
        createSignedJwtFromObject: jwtUtilAuth.createSignedJwtFromObject,
        verifyJwtSignature: jwtUtilAuth.verifyJwtSignature,
        getHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt
    },

    pwdUtilAuth: {
        createPasswordHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
        createPasswordHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt
    },

    strEncryptUtil: {
        encryptByPrivateKey: strEncryptUtil.encryptByPrivateKey,
        decryptByPublicKey: strEncryptUtil.decryptByPublicKey,
        encryptByKey: strEncryptUtil.encryptByKey,
        decryptByKey: strEncryptUtil.decryptByKey
    },

    createRsaKeys: keyGen.generateKeyPair,

    stringUtilAuth: require( './lib/stringUtilAuth' ),
};

