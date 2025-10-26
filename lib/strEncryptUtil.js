const crypto = require( "crypto" );


function createKey( key, keyLength = 32 ) {
    return crypto.scryptSync( key, key, keyLength );
}

const encryptByPrivateKey = ( encryptionConfigObj, textToEncrypt ) => {
    try {

        const encrypted = crypto.privateEncrypt(
            encryptionConfigObj.privateKey,
            Buffer.from( textToEncrypt )
        );

        return encrypted.toString( encryptionConfigObj.encryptedTextEncoding );

    } catch ( error ) {

        return error.code;

    }
};

const decryptByPublicKey = ( decryptionConfigObj, textToDecrypt ) => {
    try {

        const decrypted = crypto.publicDecrypt(
            decryptionConfigObj.publicKey,
            Buffer.from(
                textToDecrypt,
                decryptionConfigObj.encryptedTextEncoding
            )
        );

        return decrypted.toString( decryptionConfigObj.plainTextEncoding );

    } catch ( error ) {

        return error.code;

    }
};

const encryptByKey = ( encryptConfigObj = {}, textToEncrypt ) => {
    try {

        const iv = Buffer.alloc( 16, 0 );

        const cipher = crypto.createCipheriv(
            encryptConfigObj.cipherAlgorithm,
            createKey(
                encryptConfigObj.encryptionKey,
                encryptConfigObj.keyLength
            ),
            iv
        );

        let encrypted = cipher.update(
            textToEncrypt,
            encryptConfigObj.plainTextEncoding,
            encryptConfigObj.encryptedTextEncoding
        );

        encrypted += cipher.final( encryptConfigObj.encryptedTextEncoding );

        return encrypted;

    } catch ( error ) {

        return error.code;

    }
};

const decryptByKey = ( encryptConfigObj, textToDecrypt ) => {
    try {

        const iv = Buffer.alloc( 16, 0 );

        const decipher = crypto.createDecipheriv(
            encryptConfigObj.cipherAlgorithm,
            createKey(
                encryptConfigObj.encryptionKey,
                encryptConfigObj.keyLength
            ),
            iv
        );

        let decrypted = decipher.update(
            textToDecrypt,
            encryptConfigObj.encryptedTextEncoding,
            encryptConfigObj.plainTextEncoding
        );

        decrypted += decipher.final( encryptConfigObj.plainTextEncoding );

        return decrypted;

    } catch ( error ) {

        return error.code;

    }
};


module.exports = {
    encryptByPrivateKey,
    decryptByPublicKey,
    encryptByKey,
    decryptByKey
}
