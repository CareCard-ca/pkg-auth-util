# @carecard/auth-util

![Tests Passing](https://github.com/CareCard-ca/pkg-auth-util/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-97%25-green)

Utility package for authentication and authorization in the CareCard ecosystem.

## Features

- **JWT Utilities**: Create, verify, and parse JSON Web Tokens with support for EdDSA (Ed25519) and RSA.
- **Password Utilities**: Secure password hashing using HMAC with random salt and a custom string format for easy storage.
- **Key Generation**: Generate Ed25519 and RSA key pairs for JWT signing.
- **Crypto Utilities**: Low-level cryptographic primitives for signing, verification, and hashing.
- **String Utilities**: Base64 and Base64UrlSafe encoding/decoding, and custom string parsing.

## Installation

```bash
npm install @carecard/auth-util
```

## Usage

### JWT Utilities (`jwtUtilAuth`)

```javascript
const { jwtCreateSignedToken, jwtGetHeaderPayload, jwtVerifySignedToken } = require('@carecard/auth-util');

const header = { alg: 'EdDSA', typ: 'JWT' };
const payload = { sub: '1234567890', name: 'John Doe' };
const privateKey = '...'; // Your private PEM key

// Create a signed JWT
const token = jwtCreateSignedToken(header, payload, privateKey);

// Verify a JWT signature
const publicKey = '...'; // Your public PEM key
const isValid = jwtVerifySignedToken(token, publicKey);

// Get header and payload from a JWT
const { header: decodedHeader, payload: decodedPayload } = jwtGetHeaderPayload(token);
```

### Service-To-Service JWT Creation

```javascript
const { jwtCreateServiceAuthorizationHeader, jwtCreateServiceToken } = require('@carecard/auth-util');

const token = jwtCreateServiceToken({
  issuer: 'ms-institutions',
  audience: 'ms-auth',
  privateKey: institutionsPrivateKey,
});

const authorization = jwtCreateServiceAuthorizationHeader({
  issuer: 'ms-institutions',
  audience: 'ms-auth',
  privateKey: institutionsPrivateKey,
});
```

### Password Utilities (`pwdUtilAuth`)

```javascript
const { pwdUtilAuth } = require('@carecard/auth-util');

const password = 'mySecretPassword';
const secret = 'application-wide-secret';
const algorithm = 'sha512';

// Create a new password hash with a random salt
const hash = pwdUtilAuth.createPasswordHashWithRandomSalt(password, secret, algorithm);
// Resulting format: $1$base64(algorithm)$base64(hash)$base64(salt)$

// Verify a password against a saved hash
const isCorrect = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt(password, hash, secret) === hash;
```

### Key Generation

```javascript
const { generateKeyPair } = require('@carecard/auth-util');

// Generate Ed25519 keys (default)
const { publicKey, privateKey } = generateKeyPair();

// Generate RSA keys
const rsaKeys = generateKeyPair('rsa');
```

### String Utilities (`stringUtilAuth`)

```javascript
const { stringUtilAuth } = require('@carecard/auth-util');

const base64 = stringUtilAuth.asciiToBase64('Hello World');
const original = stringUtilAuth.base64ToAscii(base64);

const urlSafe = stringUtilAuth.makeStringUrlSafe('a+b/c==');
// Result: a-b_c
```

## CareCard Auth Contract

`ms-auth` issues CareCard user JWTs and now enforces its own auth tables with
forced PostgreSQL RLS. This package should preserve JWT claim values exactly
when creating or verifying tokens; a payload containing `roles: ["ad"]` is the
auth-service super-admin signal. Do not add helpers that hide, rename, or drop
the `roles` array, and do not add database bypass behavior to this package.

## Testing

Run tests using:

```bash
npm test
```

To run type tests:

```bash
npm run test:types
```

## Architecture

The package is organized into several modules:

- `jwtUtilAuth`: Manages the JWT lifecycle.
- `pwdUtilAuth`: Handles password hashing and verification.
- `keyGen`: Utility for generating cryptographic keys.
- `cryptoUtilAuth`: Core cryptographic operations using Node.js `crypto` module.
- `stringUtilAuth`: String manipulation and format conversions.

All modules are exported through the main `index.js`.
