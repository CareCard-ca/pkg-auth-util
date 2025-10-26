# Auth utilities class

## Main Functionality

This is a collection of utility functions for use in authentication

### Main functions

```js
const { jwtUtilAuth, pwdUtilAuth } = require( '@chatpta/auth-util' );
```

Create jwt

```js
const headerObject = {
    alg: "SHA256", // Mendatory acceptable algorithm
    ...
};

const payloadObject = {
    ...
};

const jwt = jwtUtilAuth.createSignedJwtFromObject( headerObject, payloadObject, privateKey );
```

Verify jwt signature returns ```true``` or ```false```

```js
const isVerified = jwtUtilAuth.verifyJwtSignature( jwt, publicKey );
```

Get header and payload object from jwt.

```js
const { header, payload } = jwtUtilAuth.getHeaderPayloadFromJwt( jwt );
```

Create password hash to save in database

```js
const hash = pwdUtilAuth.createPasswordHashWithRandomSalt( password, secret, algorithm );
```

Create another password hash based on saved hash to compare.

```js
const hashForLogin = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( passwordForLogin, savedPasswordHash, secret );
```

