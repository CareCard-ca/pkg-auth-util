# Coding Guidelines for @carecard/auth-util

This package provides core authentication and authorization utilities for the CareCard ecosystem.

## Architecture and Design

The package follows a simple functional utility pattern, organized into modular libraries:

- **Entry Point**: `index.js` - Centralized export of all utility functions.
- **JWT Layer (`lib/jwtUtilAuth.js`)**:
  - Handles creation, verification, and decomposition of JWTs.
  - Uses `EdDSA` (Ed25519) as the default algorithm.
  - Standardizes headers and payloads (e.g., auto-filling `iat` and `exp`).
- **Password Layer (`lib/pwdUtilAuth.js`)**:
  - Implements password hashing using HMAC.
  - Utilizes a custom string format for hashed passwords: `$1$base64(algorithm)$base64(hash)$base64(salt)$`.
  - Always handles salt automatically when creating new hashes.
- **Core Crypto Layer (`lib/cryptoUtilAuth.js`)**:
  - Wraps Node.js `crypto` module.
  - Provides primitives for signing, verifying, and generating HMACs and salts.
- **String Utility Layer (`lib/stringUtilAuth.js`)**:
  - Manages Base64 and Base64UrlSafe conversions.
  - Handles parsing of custom formatted strings (JWT, Password hashes).
- **Key Generation (`lib/keyGen.js`)**:
  - Generates cryptographic key pairs (Ed25519, RSA).

## Coding Patterns

- **Asynchronous vs Synchronous**: Currently, most operations are synchronous. When adding new utilities, maintain consistency with the existing style.
- **Error Handling**: Use `try-catch` blocks within utility functions to ensure they fail gracefully (returning `null` or `false` where appropriate) rather than throwing uncaught exceptions.
- **Naming Conventions**:
  - Public functions: `camelCase` (e.g., `createSignedJwtFromObject`).
  - Internal/Helper functions: Prepend with an underscore (e.g., `_assembleJwt`).
- **Consistency**: Always use the provided `stringUtilAuth` for any Base64 or URL-safe string transformations to ensure consistency across the package.

## Testing

- **Framework**: Mocha.
- **Directory**: `test/`.
- **Test Structure**: Every module in `lib/` must have a corresponding test file in `test/` (e.g., `lib/jwtUtilAuth.js` -> `test/jwtUtilAuth.test.js`).
- **E2E/Integration**: `test/index.test.js` should cover scenarios using the main exports from `index.js`.
- **Type Definitions**: Maintain `index.d.ts` and verify with `test/types.test.ts` (using `tsc`).

## Future Development

- Ensure all new features are covered by tests.
- When adding a new algorithm, update `cryptoUtilAuth` and ensure it's integrated correctly into `jwtUtilAuth` or `pwdUtilAuth`.
- Keep the `index.d.ts` up to date with any changes to the exported API.
