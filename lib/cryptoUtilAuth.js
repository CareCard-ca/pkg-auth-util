const crypto = require( "crypto" );


/**
 * Signs a token returns signature string
 * @param token
 * @param privateKey
 * @param signingAlgorithm
 * @returns {string}
 */
const createBase64SignatureOfToken = function ( token = '', privateKey, signingAlgorithm = 'EdDSA' ) {
    if ( signingAlgorithm === 'EdDSA' || signingAlgorithm === 'Ed25519' ) {
        return crypto.sign( null, Buffer.from( token ), privateKey ).toString( 'base64' );
    }

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
const verifyBase64SignatureOfToken = function ( token = '', signature, publicKey, signingAlgorithm = 'EdDSA' ) {
    try {
        if ( signingAlgorithm === 'EdDSA' || signingAlgorithm === 'Ed25519' ) {
            return crypto.verify( null, Buffer.from( token ), publicKey, Buffer.from( signature, 'base64' ) );
        }

        const verify = crypto.createVerify( signingAlgorithm );
        verify.update( token );
        verify.end();
        return verify.verify( publicKey, signature, 'base64' );
    } catch ( e ) {
        return false;
    }
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
const createSaltBase64 = ( size = 32 ) => {
    return crypto.randomBytes( size ).toString( 'base64' );
};

module.exports = {
    createBase64SignatureOfToken,
    verifyBase64SignatureOfToken,
    createHmacBase64,
    createSaltBase64
};
