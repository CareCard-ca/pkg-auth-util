const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const jwtUtilAuthFromFile = require( '../lib/jwtUtilAuth' )


const keys = require( './keys/keys' );

describe( 'JwtUtilAuth test', function () {
    it( 'createSignedJwtFromObject returns a valid signed JWT with exp and correct iat', function () {
        const header = { alg: 'EdDSA' };
        const payload = {
            sub: '1234567890',
            name: 'John Doe',
            iat: 1516239022000, // ms
            exp: 1516242622000, // ms
            nbf: 1516239022000, // ms
            auth_time: 1516239022000 // ms
        };
        const privateKey = keys.privateKey;

        const jwt = jwtUtilAuthFromFile.createSignedJwtFromObject( header, payload, privateKey );
        assert.ok( jwt );

        const { header: decodedHeader, payload: decodedPayload } = jwtUtilAuthFromFile.getHeaderPayloadFromJwt( jwt );
        assert.strictEqual( decodedHeader.alg, 'EdDSA' );
        assert.strictEqual( decodedPayload.sub, '1234567890' );
        assert.strictEqual( decodedPayload.iat, 1516239022 ); // converted to seconds
        assert.strictEqual( decodedPayload.exp, 1516242622 ); // converted to seconds
        assert.strictEqual( decodedPayload.nbf, 1516239022 ); // converted to seconds
        assert.strictEqual( decodedPayload.auth_time, 1516239022 ); // converted to seconds
        assert.ok( decodedPayload.exp > decodedPayload.iat );
    } );

    it( 'verifyJwtSignature returns true for valid signature', function () {
        const header = { alg: 'EdDSA' };
        const payload = { sub: '1234567890' };
        const jwt = jwtUtilAuthFromFile.createSignedJwtFromObject( header, payload, keys.privateKey );

        const isValid = jwtUtilAuthFromFile.verifyJwtSignature( jwt, keys.publicKey );
        assert.strictEqual( isValid, true );
    } );

    it( 'assembleJwt called with header, payload and signature returns jwt', function () {
        const header = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        const signature = "-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";
        const expectedJwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";

        const returnedJwt = jwtUtilAuthFromFile._assembleJwt( header, payload, signature );
        assert.deepStrictEqual( returnedJwt, expectedJwt );
    } );

    it( 'splitJwtInToHeaderPayloadSignature splits jwt into its parts', function () {
        const jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";
        const headerExpected = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        const payloadExpected = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        const signatureExpected = "-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";

        const { header, payload, signature } = jwtUtilAuthFromFile._splitJwtInToHeaderPayloadSignature( jwt );
        assert.deepStrictEqual( header, headerExpected );
        assert.deepStrictEqual( payload, payloadExpected );
        assert.deepStrictEqual( signature, signatureExpected );
    } );

    it( 'normalizeHeader adds default algorithm and typ', function () {
        const header = {};
        const normalized = jwtUtilAuthFromFile.normalizeHeader( header );
        assert.strictEqual( normalized.alg, 'EdDSA' );
        assert.strictEqual( normalized.typ, 'JWT' );
    } );

    it( 'normalizePayload normalizes iat, exp, nbf, auth_time from ms to s', function () {
        const payload = {
            iat: 1516239022000,
            exp: 1516242622000,
            nbf: 1516239022000,
            auth_time: 1516239022000
        };
        const normalized = jwtUtilAuthFromFile.normalizePayload( payload );
        assert.strictEqual( normalized.iat, 1516239022 );
        assert.strictEqual( normalized.exp, 1516242622 );
        assert.strictEqual( normalized.nbf, 1516239022 );
        assert.strictEqual( normalized.auth_time, 1516239022 );
    } );

    it( 'normalizePayload adds default iat and exp', function () {
        const payload = {};
        const normalized = jwtUtilAuthFromFile.normalizePayload( payload );
        assert.ok( normalized.iat );
        assert.strictEqual( normalized.exp, normalized.iat + 3600 );
    } );
} );
