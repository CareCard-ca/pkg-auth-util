const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const stringUtilAuth = require( '../lib/stringUtilAuth' );

describe( 'StringUtilAuth test', function () {
    it( 'makeStringUrlSafe and reverseStringUrlSafe should be inverses (excluding padding)', function () {
        const original = 'a+b/c=';
        const urlSafe = stringUtilAuth.makeStringUrlSafe( original );
        assert.strictEqual( urlSafe, 'a-b_c' );
        
        const reversed = stringUtilAuth.reverseStringUrlSafe( urlSafe );
        // reverseStringUrlSafe adds padding, so 'a-b_c' (length 5) -> 'a+b/c' (length 5) -> pad to 8: 'a+b/c==='
        // Wait, 'a-b_c' length is 5. 5 % 4 = 1. (4 - 1) % 4 = 3. So 3 '=' added.
        assert.strictEqual( reversed, 'a+b/c===' );
    } );

    it( 'asciiToBase64 and base64ToAscii should handle UTF-8 characters', function () {
        const original = 'Hello World! ©®™';
        const base64 = stringUtilAuth.asciiToBase64( original );
        const reversed = stringUtilAuth.base64ToAscii( base64 );
        assert.strictEqual( reversed, original );
    } );

    it( 'dollarSignConnectedStringToAlgorithmHashSalt should parse password hash', function () {
        const validHash = '$1$someAlg$someHash$someSalt$someExtra'; // length 6
        const result = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt( validHash );
        assert.ok( result );
        assert.strictEqual( result.version, '1' );
        assert.strictEqual( result.alg, 'someAlg' );
        assert.strictEqual( result.hash, 'someHash' );
        assert.strictEqual( result.salt, 'someSalt' );

        const invalidHash = '$1$too$few$parts';
        const resultNull = stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt( invalidHash );
        assert.strictEqual( resultNull, null );
    } );

    it( 'dotConnectedStringToHeaderPayloadSignature should parse JWT', function () {
        const jwt = 'header.payload.signature';
        const result = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature( jwt );
        assert.strictEqual( result.header, 'header' );
        assert.strictEqual( result.payload, 'payload' );
        assert.strictEqual( result.signature, 'signature' );
    } );

    it( 'objectToBase64UrlSafeString and urlSafeBase64ToObject should be inverses', function () {
        const obj = { foo: 'bar', baz: 123, utf8: '©' };
        const base64Url = stringUtilAuth.objectToBase64UrlSafeString( obj );
        const reversed = stringUtilAuth.urlSafeBase64ToObject( base64Url );
        assert.deepStrictEqual( reversed, obj );
    } );
} );
