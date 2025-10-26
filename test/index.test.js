const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { jwtUtilAuth, pwdUtilAuth, strEncryptUtil } = require( '../index' );
const keys = require( './keys/keys' );


describe( 'Index/JwtUtilAuth', function () {

    it( 'createSignedJwtFromObject returns base64 url safe jwt', function () {
        const header = {
            alg: "SHA512",
            typ: "JWT"
        }
        const payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "cpso": "81883",
            "roles": ["ph", "ea"]
        }
        const expectedJwt = "eyJhbGciOiJTSEE1MTIiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl19.PWff8BvKP79ukuZrGEhyIw4HN86m99l4VZo9xL_Ul5EHQFC1RsEvxUig4z2sUZqAvQLcQjEhNR7hf0KkB7YeJTWZF4QLRX6GwC5SvE2kryrYSlZvop2SCbYdty38gzDw3xTdDzcJo0awE45Sk_ZlRnjgcDD-wXAW3i7ToXRcPxM";

        const createdJwt = jwtUtilAuth.createSignedJwtFromObject( header, payload, keys.privateKey );

        assert.deepStrictEqual( createdJwt, expectedJwt );
    } );

    it( 'verifyJwtSignature returns true or false', function () {
        const jwt = "eyJhbGciOiJTSEE1MTIiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl19.PWff8BvKP79ukuZrGEhyIw4HN86m99l4VZo9xL_Ul5EHQFC1RsEvxUig4z2sUZqAvQLcQjEhNR7hf0KkB7YeJTWZF4QLRX6GwC5SvE2kryrYSlZvop2SCbYdty38gzDw3xTdDzcJo0awE45Sk_ZlRnjgcDD-wXAW3i7ToXRcPxM";

        const isVerified = jwtUtilAuth.verifyJwtSignature( jwt, keys.publicKey );

        assert.deepStrictEqual( isVerified, true );
    } );

    it( 'getHeaderPayloadFromJwt returns header, payload object', function () {
        const jwt = "eyJhbGciOiJTSEE1MTIiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJjcHNvIjoiODE4ODMiLCJyb2xlcyI6WyJwaCIsImVhIl19.PWff8BvKP79ukuZrGEhyIw4HN86m99l4VZo9xL_Ul5EHQFC1RsEvxUig4z2sUZqAvQLcQjEhNR7hf0KkB7YeJTWZF4QLRX6GwC5SvE2kryrYSlZvop2SCbYdty38gzDw3xTdDzcJo0awE45Sk_ZlRnjgcDD-wXAW3i7ToXRcPxM"

        const expectedHeader = {
            alg: "SHA512",
            typ: "JWT"
        }
        const expectedPayload = {
            sub: '1234567890',
            name: 'John Doe',
            iat: 1516239022,
            cpso: "81883",
            roles: [ "ph", "ea" ]
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

describe( 'Index/strEncryptUtil', function () {

    it( 'encryptByPrivateKey', function () {
        const textToEncrypt = 'Asymmetric encryption';
        const expectedEncryptedString = "VtwwLocyYdCreTBRifUmFuLRQ3Lrmw0RxDEN9zQh9lTJ2+6K/iLj7F5TDqm10hIKtfeajacs5HgEPGLb4whSpy7ggMtCNZQoujJNElNq2d7TScquYWi34cGlURzNTIUqC66afYYF2djq1QNVkWMzrnLMztrHem09+VlmA+eGLdc=";
        const encryptionConfigObj = {
            cipherAlgorithm: "aes-256-cbc",
            keyLength: 32,
            privateKey: keys.privateKey,
            plainTextEncoding: "utf8",
            encryptedTextEncoding: "base64"
        }

        const encryptedString = strEncryptUtil.encryptByPrivateKey( encryptionConfigObj, textToEncrypt );

        assert.deepStrictEqual( encryptedString, expectedEncryptedString );
    } );

    it( 'decryptByPublicKey', function () {
        const inputEncryptedString = "VtwwLocyYdCreTBRifUmFuLRQ3Lrmw0RxDEN9zQh9lTJ2+6K/iLj7F5TDqm10hIKtfeajacs5HgEPGLb4whSpy7ggMtCNZQoujJNElNq2d7TScquYWi34cGlURzNTIUqC66afYYF2djq1QNVkWMzrnLMztrHem09+VlmA+eGLdc=";
        const expectedText = 'Asymmetric encryption';
        const decryptionConfigObj = {
            cipherAlgorithm: "aes-256-cbc",
            keyLength: 32,
            publicKey: keys.publicKey,
            plainTextEncoding: "utf8",
            encryptedTextEncoding: "base64"
        }

        const decryptedString = strEncryptUtil.decryptByPublicKey( decryptionConfigObj, inputEncryptedString );

        assert.deepStrictEqual( decryptedString, expectedText );
    } );


    it( 'encryptByKey', function () {
        const textToEncrypt = 'This is some text for encryption';
        const expectedEncryptedString = "/RMgsfS/ANEngXOwjFDYqxutOLnaY7XxDiJK403KZTcp8D76qPzwUYcYAF+lle4I";
        const encryptConfigObj = {
            cipherAlgorithm: "aes-256-cbc",
            keyLength: 32,
            encryptionKey: keys.privateKey,
            plainTextEncoding: "utf8",
            encryptedTextEncoding: "base64"
        }

        const encryptedString = strEncryptUtil.encryptByKey( encryptConfigObj, textToEncrypt );

        assert.deepStrictEqual( encryptedString, expectedEncryptedString );
    } );

    it( 'decryptByKey', function () {
        const encryptedString = "/RMgsfS/ANEngXOwjFDYqxutOLnaY7XxDiJK403KZTcp8D76qPzwUYcYAF+lle4I";
        const expectedText = 'This is some text for encryption';
        const encryptConfigObj = {
            cipherAlgorithm: "aes-256-cbc",
            keyLength: 32,
            encryptionKey: keys.privateKey,
            plainTextEncoding: "utf8",
            encryptedTextEncoding: "base64"
        }

        const decryptedString = strEncryptUtil.decryptByKey( encryptConfigObj, encryptedString );

        assert.deepStrictEqual( decryptedString, expectedText );
    } );
} );
