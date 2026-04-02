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
const { jwtUtilAuth } = require('@carecard/auth-util');

const header = { alg: 'EdDSA', typ: 'JWT' };
const payload = { sub: '1234567890', name: 'John Doe' };
const privateKey = '...'; // Your private PEM key

// Create a signed JWT
const token = jwtUtilAuth.createSignedJwtFromObject(header, payload, privateKey);

// Verify a JWT signature
const publicKey = '...'; // Your public PEM key
const isValid = jwtUtilAuth.verifyJwtSignature(token, publicKey);

// Get header and payload from a JWT
const { header: decodedHeader, payload: decodedPayload } = jwtUtilAuth.getHeaderPayloadFromJwt(token);
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
const isCorrect = (pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt(password, hash, secret) === hash);
```

### Key Generation

```javascript
const { createKeys } = require('@carecard/auth-util');

// Generate Ed25519 keys (default)
const { publicKey, privateKey } = createKeys();

// Generate RSA keys
const rsaKeys = createKeys('rsa');
```

### String Utilities (`stringUtilAuth`)

```javascript
const { stringUtilAuth } = require('@carecard/auth-util');

const base64 = stringUtilAuth.asciiToBase64('Hello World');
const original = stringUtilAuth.base64ToAscii(base64);

const urlSafe = stringUtilAuth.makeStringUrlSafe('a+b/c==');
// Result: a-b_c
```

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
