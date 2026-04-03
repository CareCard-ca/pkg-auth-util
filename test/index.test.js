const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { 
    jwtUtilAuth, 
    pwdUtilAuth,
    jwtCreateSignedFromObject,
    jwtVerifySignature,
    jwtGetHeaderPayloadFromJwt,
    generateKeyPair,
    passwordCreateHashWithRandomSalt,
    passwordCreateHashBasedOnSavedAlgorithmSalt
} = require( '../index' );
const keys = require( './keys/keys' );


describe( 'Index/JwtUtilAuth', function () {

    it( 'jwtCreateSignedFromObject returns base64 url safe jwt', function () {
        const header = {
            alg: "EdDSA",
            typ: "JWT"
        }
        const payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "cpso": "81883",
            "roles": ["ph", "ea"]
        }
        const createdJwt = jwtCreateSignedFromObject( header, payload, keys.privateKey );
        const isVerified = jwtVerifySignature( createdJwt, keys.publicKey );

        assert.ok( isVerified );
        const { header: decodedHeader, payload: decodedPayload } = jwtGetHeaderPayloadFromJwt( createdJwt );
        assert.deepStrictEqual( decodedHeader, { alg: 'EdDSA', typ: 'JWT' } );
        assert.strictEqual( decodedPayload.sub, '1234567890' );
    } );

    it( 'jwtVerifySignature returns true or false', function () {
        const header = { alg: "EdDSA", typ: "JWT" };
        const payload = { sub: "1234567890" };
        const jwt = jwtCreateSignedFromObject( header, payload, keys.privateKey );

        const isVerified = jwtVerifySignature( jwt, keys.publicKey );

        assert.deepStrictEqual( isVerified, true );
    } );

    it( 'jwtGetHeaderPayloadFromJwt returns header, payload object', function () {
        const headerObj = { alg: "EdDSA", typ: "JWT" };
        const payloadObj = { sub: "1234567890" };
        const jwt = jwtCreateSignedFromObject( headerObj, payloadObj, keys.privateKey );

        const expectedHeader = {
            alg: "EdDSA",
            typ: "JWT"
        }
        const expectedPayload = {
            sub: '1234567890',
            iat: Math.floor( Date.now() / 1000 ),
            exp: Math.floor( Date.now() / 1000 ) + 3600
        }

        const { header, payload } = jwtGetHeaderPayloadFromJwt( jwt );

        assert.deepStrictEqual( header, expectedHeader );
        assert.strictEqual( payload.sub, expectedPayload.sub );
        assert.ok( Math.abs( payload.iat - expectedPayload.iat ) < 2 );
    } );

    it( 'generateKeyPair returns a KeyPair', function () {
        const keys = generateKeyPair( 'ed25519' );
        assert.ok( keys.publicKey );
        assert.ok( keys.privateKey );
        assert.ok( keys.publicKey.includes( 'BEGIN PUBLIC KEY' ) );
        assert.ok( keys.privateKey.includes( 'BEGIN PRIVATE KEY' ) );
    } );
} );

describe( 'Index/PwdUtilAuth', function () {

    it( 'passwordCreateHashWithRandomSalt called with save hash', function () {
        const password = "mySecretPassword";
        const secret = 'bigSecret';
        const algorithm = 'sha512';

        const hash = passwordCreateHashWithRandomSalt( password, secret, algorithm );

        assert.deepStrictEqual( hash.length > 40, true );
    } );

    it( 'passwordCreateHashBasedOnSavedAlgorithmSalt called with saved hash', function () {
        const savedHash = "$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$";
        const password = "mySecretPassword";
        const secret = 'bigSecret';

        const hash = passwordCreateHashBasedOnSavedAlgorithmSalt( password, savedHash, secret );

        assert.deepStrictEqual( hash, savedHash );
    } );
} );
