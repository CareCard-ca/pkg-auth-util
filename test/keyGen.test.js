const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const cryptoUtilAuth = require( "../lib/cryptoUtilAuth" );
const { createRsaKeys } = require( "../index" );

describe( 'Create key to use with jwt', function () {
    it( 'tests if keys created work', function () {

        const {
            publicKey,
            privateKey,
        } = createRsaKeys()

        const algorithm = 'SHA256';
        const token = "Hi I am token";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, algorithm );
        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, returnedSignature, publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, true );
    } );
} );