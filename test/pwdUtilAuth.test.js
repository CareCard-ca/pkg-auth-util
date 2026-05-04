const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const pwdUtilAuth = require( '../lib/pwdUtilAuth' );

describe( 'PwdUtilAuth test', function () {

    describe( 'createPasswordHashWithRandomSalt & createPasswordHashBasedOnSavedAlgorithmSalt', function () {
        it( 'should create and verify hash correctly', function () {
            const password = 'myPassword';
            const secret = 'appSecret';
            const algorithm = 'sha512';
            
            const hash = pwdUtilAuth.createPasswordHashWithRandomSalt( password, secret, algorithm );
            assert.ok( hash );
            
            const isMatch = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( password, hash, secret );
            assert.strictEqual( isMatch, hash );
            
            const noMatch = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( 'wrongPassword', hash, secret );
            assert.notStrictEqual( noMatch, hash );
        } );

        it( 'should return null on error (invalid algorithm)', function () {
            const result = pwdUtilAuth.createPasswordHashWithRandomSalt( 'pw', 'sec', 'invalid-alg' );
            assert.strictEqual( result, null );
        } );

        it( 'should return null on error (invalid hash format)', function () {
            const result = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( 'pw', null, 'sec' );
            assert.strictEqual( result, null );
        } );

        it( 'should return null on invalid saved hash structure', function () {
            const result = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( 'pw', 'not$enough$parts', 'sec' );
            assert.strictEqual( result, null );
        } );
    } );
} );
