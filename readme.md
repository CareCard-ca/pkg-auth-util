# @carecard/auth-util

Non-negotiable root-cause solution rule: Always identify and solve the verified root cause, use the stronger solution, and deliver a correct, durable, production-quality result. Never treat a temporary workaround, resource increase, retry, suppression, bypass, or symptom-only patch as completion. Validate the root-cause fix against the real failing workflow and prove the end state.

![Tests Passing](https://github.com/CareCard-ca/pkg-auth-util/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-97%25-green)

Utility package for authentication and authorization in the CareCard ecosystem.

## Development Rule

Non-negotiable TDD rule: Always write the failing test first, run it to confirm it fails for the intended reason, then implement the code and rerun the test until it passes. Test Driven Development is required for all coding work and must not be skipped. For documentation- or skill-only edits, add or update the relevant validation check before changing the prose.

Non-negotiable repository isolation rule: Every repository must run its Husky hooks and tests using only files, code, fixtures, dependencies, and services contained within that repository. Tests and Husky scripts must not import, require, read, execute, or otherwise depend on sibling repositories or paths outside the repository root. app-e2e-tests is the only exception because cross-repository end-to-end testing is its explicit responsibility.

Non-negotiable error and warning rule: Never suppress, silence, hide, downgrade, filter, ignore, skip, or bypass errors or warnings from code, tests, tools, compilers, linters, or validation. Fix the root cause, then rerun the affected check and require a clean result. Expected error-path tests may assert errors, but must not conceal unexpected failures.

Non-negotiable TypeScript type rule: Never use the TypeScript type `any`; always use specific domain types, generics, existing project types, or `unknown` with explicit narrowing in all TypeScript-family files (`.ts`, `.tsx`, `.mts`, `.cts`, and `.d.ts`).

Non-negotiable code organization rule: Functions with the same or equivalent behavior must use the same or clearly corresponding descriptive names across CareCard repositories, and equivalent functionality must live in files with the same names within each repository's established architecture. No backward compatibility names, aliases, or duplicate locations are allowed.

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

Docs that mention `ms-auth` controller internals should use concise action
names such as `loginUser`, `registerUser`, `getUserDetail`, and `renewJwt`.
Access level is conveyed by route middleware and endpoint placement, not by
`public`/`protected`/`admin`/`Handler` suffixes.

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

## Fail-Closed Test Lifecycle Audit

The current package tests own no HTTP listener, database pool, Kafka client,
background timer, or child process after completion. Mocha's test timeout fails
a stalled async test, the suites run without bail or forced exit, and npm
preserves each command's nonzero status. Keep natural process exit as the open
handle regression check; validation must not hide failures with retries, forced
success, skipped tests, or output suppression.

Do not add unpublished executable validation code to a `pkg-*` repository. If a
future test owns a long-lived resource or demonstrates a post-suite hang, add a
contract-tested process watchdog through the coordinated package version,
publish, and consumer propagation workflow. That watchdog must return
immediately when no helper remains, allow only a bounded 250 ms settlement
window for already-stopping helpers, fail persistent descendants, preserve
failures and output, use exit code `124` only for a real outer deadline, and
remain a final guard rather than a substitute for explicit cleanup.
