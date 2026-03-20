const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const cryptoUtilAuth = require( "../lib/cryptoUtilAuth" );
const { createKeys } = require( "../index" );

describe( 'Create key to use with jwt', function () {
    it( 'tests if keys created work with default (ed25519)', function () {

        const {
            publicKey,
            privateKey,
        } = createKeys()

        const algorithm = 'EdDSA';
        const token = "Hi I am token";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, algorithm );
        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, returnedSignature, publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, true );
    } );

    it( 'tests if keys created work with explicitly passed ed25519', function () {

        const {
            publicKey,
            privateKey,
        } = createKeys( 'ed25519' )

        const algorithm = 'EdDSA';
        const token = "Hi I am token";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, algorithm );
        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, returnedSignature, publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, true );
    } );

    it( 'tests if keys created work with explicitly passed rsa', function () {

        const {
            publicKey,
            privateKey,
        } = createKeys( 'rsa' )

        const algorithm = 'sha256';
        const token = "Hi I am token";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, algorithm );
        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, returnedSignature, publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, true );
    } );
} );