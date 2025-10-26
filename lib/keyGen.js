const {
    generateKeyPairSync,
} = require( 'node:crypto' );


const generateKeyPair = ( modulusLength = 4096 ) => ( generateKeyPairSync( 'rsa', {
    modulusLength: modulusLength,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    },
} ) );


module.exports = {
    generateKeyPair
};