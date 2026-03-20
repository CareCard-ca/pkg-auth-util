const stringUtilAuth = require( './stringUtilAuth' );
const cryptoUtilAuth = require( './cryptoUtilAuth' );

/**
 * User supplied header, payload and signature create jwt.
 * @returns {string|null}
 * @param headerBase64
 * @param payloadBase64
 * @param signatureBase64
 */
const _assembleJwt = ( headerBase64, payloadBase64, signatureBase64 ) => {
    return headerBase64 + "." + payloadBase64 + "." + signatureBase64;
};

/**
 * Normalizes jwt header
 * @param headerObject
 * @returns {{alg: string, typ: string}}
 */
const normalizeHeader = ( headerObject ) => {
    const header = { ...headerObject };
    header.alg = header.alg || 'EdDSA';
    header.typ = 'JWT';
    return header;
};

/**
 * Normalizes jwt payload time-related fields
 * @param payloadObject
 * @returns {*}
 */
const normalizePayload = ( payloadObject ) => {
    const payload = { ...payloadObject };
    const now = Math.floor( Date.now() / 1000 );
    const fieldsToNormalize = [ 'iat', 'exp', 'nbf', 'auth_time' ];
    const msThreshold = 1000000000000;

    if ( !payload.iat ) {
        payload.iat = now;
    }

    fieldsToNormalize.forEach( field => {
        if ( payload[ field ] && payload[ field ] > msThreshold ) {
            payload[ field ] = Math.floor( payload[ field ] / 1000 );
        }
    } );

    if ( !payload.exp ) {
        // Default 1 hour expiration if not provided
        payload.exp = payload.iat + 3600;
    } else if ( payload.exp > msThreshold ) {
        payload.exp = Math.floor( payload.exp / 1000 );
    }

    return payload;
};

/**
 * User supplied header, payload and signature create jwt.
 * @returns {{payload: *, signature: *, header: *}}
 * @param jwt
 */
const _splitJwtInToHeaderPayloadSignature = ( jwt ) => {
    return stringUtilAuth.dotConnectedStringToHeaderPayloadSignature( jwt );
};

/**
 * Creates Url safe jwt
 * @param headerObject
 * @param payloadObject
 * @param privateKey
 * @return {string|null}
 */
const createSignedJwtFromObject = ( headerObject, payloadObject, privateKey ) => {
    try {
        if ( !privateKey ) return null;

        const header = normalizeHeader( headerObject );
        const payload = normalizePayload( payloadObject );

        const headerBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString( header );
        const payloadBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString( payload );
        const token = headerBase64UrlSafe + "." + payloadBase64UrlSafe;

        const signature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, header.alg );
        const urlSafeSignature = stringUtilAuth.makeStringUrlSafe( signature );

        return _assembleJwt( headerBase64UrlSafe, payloadBase64UrlSafe, urlSafeSignature );
    } catch ( error ) {
        return null;
    }
};

/**
 * Verify signature of jwt
 * @param jwt
 * @param publicKey
 * @return {boolean}
 */
const verifyJwtSignature = ( jwt, publicKey ) => {
    try {
        if ( !jwt || !publicKey ) return false;
        const parts = _splitJwtInToHeaderPayloadSignature( jwt );
        if ( !parts ) return false;
        const { header, signature } = parts;
        const token = header + "." + parts.payload;
        const headerObject = stringUtilAuth.urlSafeBase64ToObject( header );
        const signatureBase64 = stringUtilAuth.reverseStringUrlSafe( signature );
        return cryptoUtilAuth.verifyBase64SignatureOfToken( token, signatureBase64, publicKey, headerObject.alg )
    } catch ( error ) {
        return false;
    }
};

/**
 * Returns header and payload object for jwt.
 * @param jwt
 * @return {{payload: any, header: any}}
 */
const getHeaderPayloadFromJwt = jwt => {
    try {
        const parts = _splitJwtInToHeaderPayloadSignature( jwt );
        if ( !parts ) return null;
        const { header, payload } = parts;
        let headerObject = stringUtilAuth.urlSafeBase64ToObject( header );
        let payloadObject = stringUtilAuth.urlSafeBase64ToObject( payload );
        return { header: headerObject, payload: payloadObject }
    } catch ( e ) {
        return null;
    }
};


module.exports = {
    _assembleJwt,
    _splitJwtInToHeaderPayloadSignature,
    normalizeHeader,
    normalizePayload,
    createSignedJwtFromObject,
    verifyJwtSignature,
    getHeaderPayloadFromJwt
};
