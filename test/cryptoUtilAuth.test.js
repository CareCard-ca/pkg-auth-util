const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const cryptoUtilAuth = require( '../lib/cryptoUtilAuth' );
const keys = require( './keys/keys' );


describe( 'CryptoUtilAuth test', function () {
    it( 'createBase64SignatureOfToken returns base64 signature of token', function () {
        const algorithm = 'SHA256';
        const token = "Hi I am token";
        const signature = "G3uHnG5DIoi3YWaj+umNmCtzAfBMmxAGfkWxlXP9qTfEr48qJjIVIdD5ic5T9YSDMt+6+XsembuL2NP6h4xoe+qE/wRjNKXCF6Hg/VvBciOdZyUqX8TaiAbGsh6J2d42rjX1vchrqfrBgCW5kiyeZcTic8LQeNdL/2gO+F9bW8A=";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, keys.privateKey, algorithm );

        assert.deepStrictEqual( returnedSignature, signature );
    } );

    it( 'verifyBase64SignatureOfToken returns true or false', function () {
        const algorithm = 'SHA256';
        const token = "Hi I am token";
        const signature = "G3uHnG5DIoi3YWaj+umNmCtzAfBMmxAGfkWxlXP9qTfEr48qJjIVIdD5ic5T9YSDMt+6+XsembuL2NP6h4xoe+qE/wRjNKXCF6Hg/VvBciOdZyUqX8TaiAbGsh6J2d42rjX1vchrqfrBgCW5kiyeZcTic8LQeNdL/2gO+F9bW8A=";
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

    it( 'encryptStringAsciiToBase64 returns  base 64 and encrypted string', function () {
        const plainTextString = 'This is some text for encryption';
        const encryptedString = "juggjf+C81QzXvqa8qE1GHTbrMQydtoFszKw2kFjGDduCpXwS01cVnYyYl9an7l7";
        const salt = 'my salt';
        const secret = 'top secret';
        const algorithm = 'aes-192-cbc';

        const encryptedText = cryptoUtilAuth.encryptStringAsciiToBase64( plainTextString, salt, secret, algorithm );

        assert.deepStrictEqual( encryptedText, encryptedString );
    } );

    it( 'decryptStringBase64ToAscii returns ascii string', function () {
        const encryptedString = "juggjf+C81QzXvqa8qE1GHTbrMQydtoFszKw2kFjGDduCpXwS01cVnYyYl9an7l7";
        const plainTextString = 'This is some text for encryption';
        const salt = 'my salt';
        const secret = 'top secret';
        const algorithm = 'aes-192-cbc';

        const encryptedText = cryptoUtilAuth.decryptStringBase64ToAscii( encryptedString, salt, secret, algorithm );

        assert.deepStrictEqual( encryptedText, plainTextString );
    } );
} );
