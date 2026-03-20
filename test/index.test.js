const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { jwtUtilAuth, pwdUtilAuth } = require( '../index' );
const keys = require( './keys/keys' );


describe( 'Index/JwtUtilAuth', function () {

    it( 'createSignedJwtFromObject returns base64 url safe jwt', function () {
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
        const expectedJwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl0sImV4cCI6MTUxNjI0MjYyMn0.WK53I6NgU03eXKM3e9MTgKmC8lQb-jWg3-mJQp8z0Y-HsS0n33UIPCtOIx4KLJB0gpxH-GTkxMs2QRzCQ1uXCA";

        const createdJwt = jwtUtilAuth.createSignedJwtFromObject( header, payload, keys.privateKey );

        assert.deepStrictEqual( createdJwt, expectedJwt );
    } );

    it( 'verifyJwtSignature returns true or false', function () {
        const jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl0sImV4cCI6MTUxNjI0MjYyMn0.WK53I6NgU03eXKM3e9MTgKmC8lQb-jWg3-mJQp8z0Y-HsS0n33UIPCtOIx4KLJB0gpxH-GTkxMs2QRzCQ1uXCA";

        const isVerified = jwtUtilAuth.verifyJwtSignature( jwt, keys.publicKey );

        assert.deepStrictEqual( isVerified, true );
    } );

    it( 'getHeaderPayloadFromJwt returns header, payload object', function () {
        const jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl0sImV4cCI6MTUxNjI0MjYyMn0.WK53I6NgU03eXKM3e9MTgKmC8lQb-jWg3-mJQp8z0Y-HsS0n33UIPCtOIx4KLJB0gpxH-GTkxMs2QRzCQ1uXCA"

        const expectedHeader = {
            alg: "EdDSA",
            typ: "JWT"
        }
        const expectedPayload = {
            sub: '1234567890',
            name: 'John Doe',
            iat: 1516239022,
            cpso: "81883",
            roles: [ "ph", "ea" ],
            exp: 1516242622
        }

        const { header, payload } = jwtUtilAuth.getHeaderPayloadFromJwt( jwt );

        assert.deepStrictEqual( header, expectedHeader );
        assert.deepStrictEqual( payload, expectedPayload );
    } );
} );

describe( 'Index/PwdUtilAuth', function () {

    it( 'createPasswordHashWithRandomSalt called with save hash', function () {
        const password = "mySecretPassword";
        const secret = 'bigSecret';
        const algorithm = 'sha512';

        const hash = pwdUtilAuth.createPasswordHashWithRandomSalt( password, secret, algorithm );

        assert.deepStrictEqual( hash.length > 40, true );
    } );

    it( 'createPasswordHashBasedOnSavedAlgorithmSalt called with saved hash', function () {
        const savedHash = "$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$";
        const password = "mySecretPassword";
        const secret = 'bigSecret';

        const hash = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( password, savedHash, secret );

        assert.deepStrictEqual( hash, savedHash );
    } );
} );
