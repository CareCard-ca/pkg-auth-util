'use strict';
/**
 * For incoming jwt token validation, splitting and parsing.
 * For outgoing jwt token assembling to jwt, make it url safe.
 */

/**
 * Adjusts padding of base64String
 * @param base64String
 * @return {*}
 */
const adjustBase64Padding = base64String => {
    while ( base64String.length % 4 ) base64String += '=';
    return base64String;
}

/**
 * Removes /, + and = from the string
 * @returns {string}
 */
const makeStringUrlSafe = ( urlUnsafeString = '' ) => {
    return urlUnsafeString
        .replaceAll( '+', '-' )
        .replaceAll( '/', '_' )
        .replaceAll( '=', '' );
};

/**
 * Put back /, + and = into the string
 * @returns {string}
 */
const reverseStringUrlSafe = ( urlSafeString = '' ) => {
    let myString = urlSafeString
        .replaceAll( '-', '+' )
        .replaceAll( '_', '/' );
    return adjustBase64Padding( myString );
};

/**
 * Encode string to base64 string
 * @param unCodedString
 * @returns {string}
 */
const asciiToBase64 = ( unCodedString ) => {
    return Buffer.from( unCodedString ).toString( 'base64' );
}

/** Decode string from base64
 * @param codedString
 * @returns {string}
 */
const base64ToAscii = ( codedString ) => {
    return Buffer.from( codedString, 'base64' ).toString( 'ascii' );
}

/**
 * Decompose $ connected string and return an object
 * return null if error
 * @param passwordHash
 */
const dollarSignConnectedStringToAlgorithmHashSalt = ( passwordHash ) => {
    const splitStringArray = passwordHash.split( '$' );
    if ( splitStringArray.length !== 6 ) return null;
    return {
        version: splitStringArray[ 1 ],
        alg: splitStringArray[ 2 ],
        hash: splitStringArray[ 3 ],
        salt: splitStringArray[ 4 ]
    };
}

/**
 * Decompose . connected string and return an object with
 * {header: 'string', payload: 'string', signature: 'string'}
 * return null if error
 */
const dotConnectedStringToHeaderPayloadSignature = ( jwt ) => {
    const splitJWT = jwt.split( '.' );
    if ( splitJWT.length !== 3 ) return null;
    return {
        header: splitJWT[ 0 ],
        payload: splitJWT[ 1 ],
        signature: splitJWT[ 2 ]
    };
}


/**
 * Turns object into url safe string
 * @param object
 * @return {string}
 */
const objectToBase64UrlSafeString = object => {
    let stringAscii = JSON.stringify( object );
    let base64String = asciiToBase64( stringAscii );
    return makeStringUrlSafe( base64String );
};

/**
 * Turns base64 into object
 * @param urlSafeBase64String
 * @return {any}
 */
const urlSafeBase64ToObject = urlSafeBase64String => {
    let base64String = reverseStringUrlSafe( urlSafeBase64String );
    let stringAscii = base64ToAscii( base64String );
    return JSON.parse( stringAscii );
};

module.exports = {
    makeStringUrlSafe,
    reverseStringUrlSafe,
    asciiToBase64,
    base64ToAscii,
    dollarSignConnectedStringToAlgorithmHashSalt,
    dotConnectedStringToHeaderPayloadSignature,
    objectToBase64UrlSafeString,
    urlSafeBase64ToObject
};
