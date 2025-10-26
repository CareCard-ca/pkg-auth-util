const crypto = require( "crypto" );


/**
 * Signs a token returns signature string
 * @param token
 * @param privateKey
 * @param signingAlgorithm
 * @returns {string}
 */
const createBase64SignatureOfToken = function ( token = '', privateKey, signingAlgorithm ) {

    const sign = crypto.createSign( signingAlgorithm );
    sign.write( token );
    sign.end();
    return sign.sign( privateKey, 'base64' );
};

/**
 * Verifies the signature returns true or false
 * @param token
 * @param signature
 * @param publicKey
 * @param signingAlgorithm
 * @returns {boolean}
 */
const verifyBase64SignatureOfToken = function ( token = '', signature, publicKey, signingAlgorithm ) {
    const verify = crypto.createVerify( signingAlgorithm );
    verify.update( token );
    verify.end();
    return verify.verify( publicKey, signature, 'base64' );
};

/**
 * Creates the hash of given string
 * @param string
 * @param secret
 * @param algorithm
 * @returns {string}
 */
const createHmacBase64 = function ( string = '', secret, algorithm ) {
    const hmac = crypto.createHmac( algorithm, secret );
    hmac.update( string );
    return hmac.digest( 'base64' );
};

/**
 * Create random salt
 * @returns {string}
 */
const createSaltBase64 = () => {
    const date = new Date().valueOf();
    const hmac = crypto.createHmac( 'SHA256', date.toString() );
    hmac.update( date.toString() );
    return hmac.digest( 'base64' );
};

/**
 * Encrypt given string
 * @param string
 * @param salt
 * @param secret
 * @param algorithm
 * @returns {string}
 */
const encryptStringAsciiToBase64 = ( string, salt, secret, algorithm ) => {

    const key = crypto.scryptSync( secret, salt, 24 );
    const iv = Buffer.alloc( 16, 0 );
    const cipher = crypto.createCipheriv( algorithm, key, iv );
    let encrypted = cipher.update( string, 'ascii', 'base64' );
    encrypted += cipher.final( 'base64' );
    return encrypted;
};

/**
 * Decrypts given string
 * @param encryptedString
 * @param salt
 * @param secret
 * @param algorithm
 * @returns {string}
 */
const decryptStringBase64ToAscii = ( encryptedString, salt, secret, algorithm ) => {
    const key = crypto.scryptSync( secret, salt, 24 );
    const iv = Buffer.alloc( 16, 0 );
    const decipher = crypto.createDecipheriv( algorithm, key, iv );
    let decrypted = decipher.update( encryptedString, 'base64', 'ascii' );
    decrypted += decipher.final( 'ascii' );
    return decrypted;
};

module.exports = {
    createBase64SignatureOfToken,
    verifyBase64SignatureOfToken,
    createHmacBase64,
    createSaltBase64,
    encryptStringAsciiToBase64,
    decryptStringBase64ToAscii
};
