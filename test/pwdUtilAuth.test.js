const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const pwdUtilAuth = require( '../lib/pwdUtilAuth' );

describe( 'PwdUtilAuth test', function () {
    it( 'assemblePasswordHash called with algorithmBase64, hashBase64, saltBase64 returns password hash', function () {
        const algorithmBase64 = 'c2hhMjU2';
        const hashBase64 = 'c2hhMjU2';
        const saltBase64 = 'c2hhMjU2';
        const expectedHash = "$1$c2hhMjU2$c2hhMjU2$c2hhMjU2$";

        const returnedHash = pwdUtilAuth._assemblePasswordHash( algorithmBase64, hashBase64, saltBase64 );

        assert.deepStrictEqual( returnedHash, expectedHash );
    } );

    it( 'disassemblePasswordHash called with save hash', function () {
        const savedHash = "$1$c2hhMjU2$c2hhMjU$c2hhMjU2$";
        const hashBase64 = 'c2hhMjU';
        const saltBase64 = 'c2hhMjU2';

        const { version, alg, hash, salt } = pwdUtilAuth._disassemblePasswordHash( savedHash );

        assert.deepStrictEqual( salt, saltBase64 );
        assert.deepStrictEqual( hash, hashBase64 );
    } );

    it( 'createPasswordHash called with save hash', function () {
        const password = "bigSecret*2";
        const secret = '240gTxVT2KnXOP4W6OdFkSEsdDWLqhLO2OP68o';
        const algorithm = 'sha512';
        const salt = "6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=";
        const expectedHash = "$1$c2hhNTEy$rNPXY0aVOYsdenIAWdfxDL6d6247s+ScI9kcDvEBkipNo7S9QDy6utTqTcQLY3+tufc0f7AvmdocotW7bDIyYA==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$";
        const hash = pwdUtilAuth._createPasswordHash( password, secret, salt, algorithm );

        assert.deepStrictEqual( hash, expectedHash );
    } );
} );
