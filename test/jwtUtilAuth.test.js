const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const jwtUtilAuthFromFile = require( '../lib/jwtUtilAuth' )


describe( 'JwtUtilAuth test', function () {
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
} );
