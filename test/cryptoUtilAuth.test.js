const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const cryptoUtilAuth = require( '../lib/cryptoUtilAuth' );
const keys = require( './keys/keys' );


describe( 'CryptoUtilAuth test', function () {
    it( 'createBase64SignatureOfToken returns base64 signature of token', function () {
        const algorithm = 'EdDSA';
        const token = "Hi I am token";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, keys.privateKey, algorithm );

        assert.ok( returnedSignature );
        assert.ok( cryptoUtilAuth.verifyBase64SignatureOfToken( token, returnedSignature, keys.publicKey, algorithm ) );
    } );

    it( 'verifyBase64SignatureOfToken returns true or false', function () {
        const algorithm = 'EdDSA';
        const token = "Hi I am token";
        const signature = cryptoUtilAuth.createBase64SignatureOfToken( token, keys.privateKey, algorithm );
        const temperedSignature = "temper" + signature;
        const expectedValueTrue = true;
        const expectedValueFalse = false;

        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, signature, keys.publicKey, algorithm );
        const returnedValueFalse = cryptoUtilAuth.verifyBase64SignatureOfToken( token, temperedSignature, keys.publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, expectedValueTrue );
        assert.deepStrictEqual( returnedValueFalse, expectedValueFalse );
    } );

    it( 'createHmacBase64 returns base 64 hmac', function () {
        const algorithm = 'SHA256';
        const token = "Hi I am token";
        const secret = "My secret";
        const expectedHmacBase64 = "IpOkaPa1YPTXQYPr6adIGk3ACgeqWyV+nvB4+7Ox4Dg=";

        const returnedHmacBase64 = cryptoUtilAuth.createHmacBase64( token, secret, algorithm );

        assert.deepStrictEqual( returnedHmacBase64, expectedHmacBase64 );
    } );

    it( 'createSaltBase64 returns random base 64 string', function () {
        const randomSalt = cryptoUtilAuth.createSaltBase64();

        assert.deepStrictEqual( randomSalt.length, 44 );
    } );
} );
