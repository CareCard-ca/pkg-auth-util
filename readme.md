# @carecard/auth-util

Non-negotiable test order invariance rule: Every test must pass independently of which tests run before or after it, and the suite must pass in every execution order. Each test must establish the state it needs, isolate mutable state, and clean up state it owns; it must never rely on another test's setup, mutations, or cleanup. Default test, CI, and Husky commands must use the test framework's ordinary ordering and must not force randomized ordering. Random-order execution is an explicit diagnostic only, and every failure it exposes must be fixed at the root cause.

Non-negotiable root-cause solution rule: Always identify and solve the verified root cause, use the stronger solution, and deliver a correct, durable, production-quality result. Never treat a temporary workaround, resource increase, retry, suppression, bypass, or symptom-only patch as completion. Validate the root-cause fix against the real failing workflow and prove the end state.

![Tests Passing](https://github.com/CareCard-ca/pkg-auth-util/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/Coverage-97%25-green)

Utility package for authentication and authorization in the CareCard ecosystem.

## Development Rule

Non-negotiable TDD rule: Always write the failing test first, run it to confirm it fails for the intended reason, then implement the code and rerun the test until it passes. Test Driven Development is required for all coding work and must not be skipped. For documentation- or skill-only edits, run the relevant focused non-test
validation before changing the prose; do not add automated tests that inspect
prose, files, or repository structure.

Non-negotiable repository isolation rule: Every repository must run its Husky hooks and tests using only files, code, fixtures, dependencies, and services contained within that repository. Tests and Husky scripts must not import, require, read, execute, or otherwise depend on sibling repositories or paths outside the repository root. app-e2e-tests is the only exception because cross-repository end-to-end testing is its explicit responsibility.

Non-negotiable error and warning rule: Never suppress, silence, hide, downgrade, filter, ignore, skip, or bypass errors or warnings from code, tests, tools, compilers, linters, or validation. Fix the root cause, then rerun the affected check and require a clean result. Expected error-path tests may assert errors, but must not conceal unexpected failures.

Non-negotiable TypeScript type rule: Never use the TypeScript type `any`; always use specific domain types, generics, existing project types, or `unknown` with explicit narrowing in all TypeScript-family files (`.ts`, `.tsx`, `.mts`, `.cts`, and `.d.ts`).

Non-negotiable code organization rule: Functions with the same or equivalent behavior must use the same or clearly corresponding descriptive names across CareCard repositories, and equivalent functionality must live in files with the same names within each repository's established architecture. No backward compatibility names, aliases, or duplicate locations are allowed.

## Features

- **JWT Utilities**: Create and verify EdDSA JWTs through strict Ed25519 JWK and JWKS configuration.
- **Password Utilities**: Rotate versioned Argon2id password peppers while preserving a strict saved-credential format.
- **Crypto Utilities**: Low-level cryptographic primitives for signing, verification, and hashing.
- **String Utilities**: Base64 and Base64UrlSafe encoding/decoding, and custom string parsing.

## Installation

```bash
npm install @carecard/auth-util
```

## Usage

### JWT Utilities (`jwtUtilAuth`)

```javascript
const {
  jwtCreateSignedToken,
  jwtGetHeaderPayload,
  jwtVerifySignedToken,
  parseJwtSigningJwk,
  parseJwtVerificationJwks,
} = require('@carecard/auth-util');

const payload = { sub: '1234567890', name: 'John Doe' };
const signingJwk = parseJwtSigningJwk(process.env.JWT_SIGNING_JWK);
const verificationJwks = parseJwtVerificationJwks(process.env.JWT_VERIFICATION_JWKS);

const token = jwtCreateSignedToken(payload, signingJwk);

const isValid = jwtVerifySignedToken(token, verificationJwks);

// Get header and payload from a JWT
const { header: decodedHeader, payload: decodedPayload } = jwtGetHeaderPayload(token);
```

### Service-To-Service JWT Creation

```javascript
const {
  jwtCreateServiceAuthorizationHeader,
  jwtCreateServiceToken,
} = require('@carecard/auth-util');

const token = jwtCreateServiceToken({
  issuer: 'ms-institutions',
  audience: 'ms-auth',
  signingJwk: institutionsSigningJwk,
});

const authorization = jwtCreateServiceAuthorizationHeader({
  issuer: 'ms-institutions',
  audience: 'ms-auth',
  signingJwk: institutionsSigningJwk,
});
```

### Password Utilities

```javascript
const {
  createPasswordCredential,
  parsePasswordHashKeyring,
  verifyPasswordCredential,
} = require('@carecard/auth-util');

const password = 'correct horse battery staple';
const keyring = parsePasswordHashKeyring(
  process.env.MS_AUTH_PASSWORD_HASH_ACTIVE_KEY_ID,
  process.env.MS_AUTH_PASSWORD_HASH_KEYRING,
);

const credential = await createPasswordCredential(password, keyring);

const result = await verifyPasswordCredential(password, credential, keyring);
if (result.isValid && result.needsRehash) {
  const replacement = await createPasswordCredential(password, keyring);
  // Persist replacement.hash and replacement.hashKeyId atomically.
}
```

Keyring entries use `key-id:canonical-base64-32-byte-key`, separated by commas.
Credential rows persist both the PHC hash and its `hashKeyId`; pepper keys stay
outside persisted credentials and logs. Passwords retain spaces and normalize
well-formed Unicode to NFC. `@carecard/validate` owns password policy.

JWT signing configuration is one strict private Ed25519 JWK. Verification
configuration is an RFC 7517 JWKS containing one or more public Ed25519 JWKs.
Every key uses `alg: "EdDSA"`, `use: "sig"`, one exact `key_ops` operation, and
an RFC 7638 SHA-256 thumbprint `kid`. Add replacement public keys before
switching signers, and retain retiring public keys for the maximum token
lifetime plus clock skew.

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

- `jwkUtilAuth`: Strictly parses private signing JWKs and public verification JWKS values.
- `jwtUtilAuth`: Creates fixed-header Ed25519 JWTs and verifies signatures by `kid`.
- `pwdUtilAuth`: Creates and verifies versioned Argon2id password credentials.
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

## TDD And Validation

Test Driven Development is a non-negotiable requirement.

The sole purpose of automated tests is to verify observable functionality and externally visible behavior.
Tests must validate what the system does through its public interfaces and expected outcomes.

Tests must not assert, inspect, or depend on implementation details, including but not limited to:

- The existence of specific lines of code, statements, functions, classes, files, or modules.
- Specific algorithms, control flow, variable names, method calls, code snippets, or internal implementation choices.
- Any internal structure that can change without changing externally observable behavior.

A correct implementation may be completely rewritten or refactored without requiring changes to functional tests, provided its externally observable behavior remains unchanged.

Any test that fails solely because the implementation changed while the externally observable behavior remained correct is incorrectly designed and must be rewritten or removed.

This requirement is mandatory for all new tests and must be applied whenever existing tests are modified.
